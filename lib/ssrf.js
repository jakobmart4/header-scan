// SSRF-safe URL parsing, DNS validation and fetching. See SPEC.md 2.3.
// Design: resolve DNS ourselves, reject if ANY answer is non-public, then connect to a PINNED address
// (the request's `lookup` returns only that IP), so DNS rebinding between check and connect is impossible.
import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';
import { isIP } from 'node:net';

export class SsrfError extends Error {
  constructor(code, message) { super(message || code); this.name = 'SsrfError'; this.code = code; }
}
export class FetchError extends Error {
  constructor(code, message) { super(message || code); this.name = 'FetchError'; this.code = code; }
}

const UA = 'header-scan/1.0 (+security scanner)';
const ALLOWED_PORTS = new Set(['', '80', '443']);
const LOCAL_SUFFIXES = ['localhost', 'local', 'internal', 'localdomain', 'home.arpa'];

// ---- IP classification (numeric, never string-regex on ranges) ----

const V4_BLOCKED = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4], // 240/4 incl. 255.255.255.255
];

function v4ToInt(s) {
  const p = s.split('.').map(Number);
  return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
}
function blockedV4(n) {
  return V4_BLOCKED.some(([base, bits]) => {
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return ((n & mask) >>> 0) === ((v4ToInt(base) & mask) >>> 0);
  });
}

// Parse an already isIP()-validated IPv6 string into a BigInt; null if malformed.
function v6ToBig(ip) {
  if (ip.includes('%')) return null; // zone ids
  let s = ip;
  const m = s.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/); // embedded dotted v4 tail
  if (m) {
    const p = m[2].split('.').map(Number);
    if (p.some((x) => x > 255)) return null;
    s = m[1] + ((p[0] << 8) | p[1]).toString(16) + ':' + ((p[2] << 8) | p[3]).toString(16);
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = 8 - head.length - tail.length;
  if (halves.length === 2 ? fill < 1 : fill !== 0) return null;
  const groups = [...head, ...(halves.length === 2 ? Array(fill).fill('0') : []), ...tail];
  let n = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
    n = (n << 16n) | BigInt('0x' + g);
  }
  return n;
}

function blockedV6(n) {
  const low32 = Number(n & 0xffffffffn);
  const hi96 = n >> 32n;
  if (hi96 === 0n) return true;                         // ::/96 (::, ::1, IPv4-compatible)
  if (hi96 === 0xffffn) return blockedV4(low32);        // ::ffff:a.b.c.d (IPv4-mapped)
  if (hi96 === 0x0064ff9b0000000000000000n) return blockedV4(low32); // 64:ff9b::/96 (NAT64)
  if (n >> 125n !== 1n) return true;                    // only 2000::/3 (global unicast) can be public
  const top16 = n >> 112n;
  if (top16 === 0x2001n) {
    if (((n >> 96n) & 0xffffn) < 0x200n) return true;   // 2001::/23 (Teredo, benchmarking, ORCHID, ...)
    if (n >> 96n === 0x20010db8n) return true;          // 2001:db8::/32 documentation
  }
  if (top16 === 0x2002n) return blockedV4(Number((n >> 80n) & 0xffffffffn)); // 6to4 embedded v4
  if (n >> 108n === 0x3fff0n) return true;              // 3fff::/20 documentation
  return false;
}

export function isBlockedIp(ip) {
  if (typeof ip !== 'string') return true;
  const s = ip.startsWith('[') && ip.endsWith(']') ? ip.slice(1, -1) : ip;
  const fam = isIP(s);
  if (fam === 4) return blockedV4(v4ToInt(s));
  if (fam === 6) { const n = v6ToBig(s); return n === null ? true : blockedV6(n); }
  return true; // not an IP at all -> blocked
}

// ---- target parsing ----

export function parseTarget(input, opts = {}) {
  const allowPrivate = !!opts.allowPrivate;
  if (typeof input !== 'string' || input.length === 0 || input.length > 2048) throw new SsrfError('BAD_URL', 'invalid URL');
  let u;
  try { u = new URL(input.trim()); } catch { throw new SsrfError('BAD_URL', 'invalid URL'); }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new SsrfError('BAD_URL', 'only http and https are allowed');
  if (u.username || u.password) throw new SsrfError('BAD_URL', 'credentials in URL are not allowed');
  let host = u.hostname.toLowerCase();
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  host = host.replace(/\.+$/, '');
  if (!host) throw new SsrfError('BAD_URL', 'invalid host');
  const isLiteral = isIP(host) !== 0; // WHATWG parsing already normalized decimal/hex/octal forms to dotted quads
  if (!allowPrivate) {
    if (LOCAL_SUFFIXES.some((s) => host === s || host.endsWith('.' + s))) throw new SsrfError('BLOCKED_TARGET', 'target is not a public host');
    if (isLiteral && isBlockedIp(host)) throw new SsrfError('BLOCKED_TARGET', 'target is not a public host');
    if (!ALLOWED_PORTS.has(u.port)) throw new SsrfError('BAD_URL', 'only ports 80 and 443 are allowed');
  }
  if (!isLiteral && !host.includes('.') && !allowPrivate) throw new SsrfError('BAD_URL', 'host must be a fully qualified domain name');
  u.hash = '';
  u.hostname = isIP(host) === 6 ? `[${host}]` : host;
  const shown = isIP(host) === 6 ? `[${host}]` : host;
  return { url: u.href, host, origin: `${u.protocol}//${shown}${u.port ? ':' + u.port : ''}` };
}

// ---- DNS validation ----

function runLookup(lookup, host) {
  return new Promise((resolve, reject) => {
    const cb = (err, addrs) => (err ? reject(err) : resolve(addrs));
    try {
      const r = lookup(host, { all: true, verbatim: true }, cb);
      if (r && typeof r.then === 'function') r.then(resolve, reject);
    } catch (e) { reject(e); }
  });
}

export async function assertPublicHost(host, opts = {}) {
  const { allowPrivate = false, lookup = dns.lookup } = opts;
  const bare = typeof host === 'string' && host.startsWith('[') ? host.slice(1, -1) : host;
  if (typeof bare !== 'string' || !bare) throw new SsrfError('BAD_URL', 'invalid host');
  const lit = isIP(bare);
  let list;
  if (lit) {
    list = [{ address: bare, family: lit }];
  } else {
    try { list = await runLookup(lookup, bare); } catch { throw new SsrfError('DNS_FAILED', 'DNS lookup failed'); }
    if (!Array.isArray(list)) list = list ? [list] : [];
    list = list.map((a) => (typeof a === 'string' ? { address: a, family: isIP(a) } : { address: a.address, family: isIP(a.address) }));
  }
  if (list.length === 0) throw new SsrfError('DNS_FAILED', 'DNS lookup returned no addresses');
  if (!allowPrivate && list.some((a) => isBlockedIp(a.address))) throw new SsrfError('BLOCKED_TARGET', 'target resolves to a non-public address'); // mixed answers rejected
  return list;
}

// ---- fetching ----

function within(ms, promise) {
  if (ms <= 0) return Promise.reject(new FetchError('TIMEOUT', 'timeout'));
  let t;
  const timer = new Promise((_, rej) => { t = setTimeout(() => rej(new FetchError('TIMEOUT', 'timeout')), ms); });
  return Promise.race([promise, timer]).finally(() => clearTimeout(t));
}

function toFetchError(e) {
  if (e instanceof FetchError) return e;
  if (e instanceof SsrfError) return new FetchError(e.code === 'DNS_FAILED' ? 'NETWORK' : e.code, e.message);
  return new FetchError('NETWORK', `network error: ${e && e.code ? e.code : 'failed'}`);
}

// One request to one pinned address. Resolves with the raw response (body read up to maxBytes).
function once(t, address, family, { method, headers, maxBytes, encoding, deadline, readBody }) {
  return new Promise((resolve, reject) => {
    const u = new URL(t.url);
    const isHttps = u.protocol === 'https:';
    let done = false, connectTimer, totalTimer, req;
    const finish = (fn, v) => {
      if (done) return;
      done = true; clearTimeout(connectTimer); clearTimeout(totalTimer);
      fn(v);
    };
    const pinned = (_h, o, cb) => (o && o.all ? cb(null, [{ address, family }]) : cb(null, address, family));
    try {
      req = (isHttps ? https : http).request({
        host: t.host, port: u.port || (isHttps ? 443 : 80), path: u.pathname + u.search, method, headers,
        agent: false, lookup: pinned, servername: isIP(t.host) ? undefined : t.host,
      }, (res) => {
        const hdrs = { ...res.headers, 'set-cookie': res.headers['set-cookie'] || [] };
        const base = { status: res.statusCode, headers: hdrs };
        if (!readBody(res.statusCode, hdrs) || method === 'HEAD') {
          res.destroy();
          return finish(resolve, { ...base, body: '', truncated: false });
        }
        const chunks = [];
        let size = 0, truncated = false;
        const end = () => finish(resolve, { ...base, body: Buffer.concat(chunks).toString(encoding), truncated });
        res.on('data', (c) => {
          if (done) return;
          size += c.length;
          if (size > maxBytes) {
            chunks.push(c.subarray(0, c.length - (size - maxBytes)));
            truncated = true;
            res.destroy(); // stop reading and drop the socket
            end();
          } else chunks.push(c);
        });
        res.on('end', end);
        res.on('error', (e) => finish(reject, toFetchError(e)));
        res.on('close', () => finish(reject, new FetchError('NETWORK', 'network error: connection closed')));
      });
    } catch (e) { return reject(toFetchError(e)); } // e.g. invalid header characters
    const fail = (e) => { finish(reject, e); req.destroy(); };
    req.on('error', (e) => finish(reject, toFetchError(e)));
    totalTimer = setTimeout(() => fail(new FetchError('TIMEOUT', 'timeout')), Math.max(1, deadline - Date.now()));
    req.on('socket', (s) => {
      if (!s.connecting) return;
      connectTimer = setTimeout(() => fail(new FetchError('TIMEOUT', 'connect timeout')), 5000);
      s.once('connect', () => clearTimeout(connectTimer));
    });
    req.end();
  });
}

export async function safeFetch(url, opts = {}) {
  const {
    method = 'GET', headers = {}, maxBytes = 1048576, timeoutMs = 10000, maxRedirects = 5,
    followRedirects = true, allowPrivate = false, encoding = 'utf8', lookup,
  } = opts;
  if (method !== 'GET' && method !== 'HEAD') throw new FetchError('BAD_URL', 'method not allowed');
  const enc = encoding === 'latin1' ? 'latin1' : 'utf8';
  const started = Date.now();
  const deadline = started + timeoutMs;
  const base = { 'user-agent': UA, accept: '*/*', 'accept-encoding': 'identity' };
  for (const [k, v] of Object.entries(headers)) if (k.toLowerCase() !== 'host') base[k.toLowerCase()] = v;

  const redirects = [];
  const seen = new Set();
  let cur = url, firstOrigin = null;
  for (;;) {
    let t;
    try { t = parseTarget(cur, { allowPrivate }); } catch (e) { throw toFetchError(e); }
    seen.add(t.url);
    firstOrigin ??= t.origin;
    const hdrs = { ...base };
    if (t.origin !== firstOrigin) { delete hdrs.authorization; delete hdrs.cookie; }
    let addrs;
    try { addrs = await within(deadline - Date.now(), assertPublicHost(t.host, { allowPrivate, lookup })); } catch (e) { throw toFetchError(e); }
    addrs.sort((a, b) => a.family - b.family); // prefer IPv4 (many hosts lack IPv6 routes); the chosen IP is pinned
    const r = await once(t, addrs[0].address, addrs[0].family, {
      method, headers: hdrs, maxBytes, encoding: enc, deadline,
      readBody: (status, h) => !(followRedirects && status >= 300 && status < 400 && h.location),
    });
    if (followRedirects && r.status >= 300 && r.status < 400 && r.headers.location) {
      if (redirects.length >= maxRedirects) throw new FetchError('TOO_MANY_REDIRECTS', 'too many redirects');
      let next;
      try { next = new URL(r.headers.location, t.url); } catch { throw new FetchError('BAD_URL', 'invalid redirect target'); }
      next.hash = '';
      if (seen.has(next.href)) throw new FetchError('REDIRECT_LOOP', 'redirect loop');
      redirects.push({ status: r.status, from: t.url, to: next.href });
      cur = next.href; // validated (scheme, host, port, DNS) at the top of the next iteration
      continue;
    }
    return { status: r.status, headers: r.headers, body: r.body, finalUrl: t.url, timingMs: Date.now() - started, redirects, truncated: r.truncated };
  }
}
