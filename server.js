// HTTP server: static index.html + JSON API. See SPEC.md 4 and 5. node:http only, no framework.
import http from 'node:http';
import crypto from 'node:crypto';
import net from 'node:net';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { scan as realScan, resolveTxt as realResolveTxt } from './lib/scan.js';
import { parseTarget, SsrfError, FetchError } from './lib/ssrf.js';
import { makeToken, isVerified, isSharedHost, txtNameFor } from './lib/verify.js';

const MAX_BODY = 4096;
const MAX_ACTIVE = 4;
const MAX_PER_IP = 2; // concurrent scans per client: one slow-target client must not hold every slot
const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1']);

class ApiError extends Error {
  constructor(status, code, message, headers = {}) { super(message); this.status = status; this.code = code; this.headers = headers; }
}

// Limiter key: IPv6 clients share their /64 (one subscriber routinely owns a whole /64, so rotating addresses must not buy fresh quota).
export function limiterKey(ip) {
  ip = String(ip).replace(/%.*$/, '');
  if (!net.isIPv6(ip)) return ip;
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (mapped) return mapped[1];
  const [head, tail = ''] = ip.split('::');
  const h = head ? head.split(':') : [], t = tail ? tail.split(':') : [];
  const groups = ip.includes('::') ? [...h, ...Array(Math.max(0, 8 - h.length - t.length)).fill('0'), ...t] : h;
  return groups.slice(0, 4).map((g) => g.replace(/^0+(?=.)/, '').toLowerCase()).join(':') + '::/64';
}

function version() {
  try { return JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')).version; } catch { return 'unknown'; }
}

// Inline <style>/<script> are allowed only by SHA-256 hash, computed once at startup.
function loadIndex() {
  let html;
  try { html = readFileSync(new URL('./public/index.html', import.meta.url), 'utf8'); } catch { return null; }
  const hash = (s) => `'sha256-${crypto.createHash('sha256').update(s, 'utf8').digest('base64')}'`;
  const style = [...html.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/gi)].map((m) => hash(m[1]));
  const script = [...html.matchAll(/<script(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)<\/script>/gi)].map((m) => hash(m[1]));
  const csp = `default-src 'none'; script-src ${script.join(' ') || "'none'"}; style-src ${style.join(' ') || "'none'"}; ` +
    "connect-src 'self'; img-src data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";
  return { body: Buffer.from(html, 'utf8'), csp };
}

function mapError(e) {
  if (e instanceof ApiError) return e;
  if (e instanceof SsrfError) {
    return e.code === 'DNS_FAILED' ? new ApiError(502, 'SCAN_FAILED', 'target could not be resolved') : new ApiError(400, e.code, e.message);
  }
  if (e instanceof FetchError) {
    if (e.code === 'TIMEOUT') return new ApiError(504, 'TIMEOUT', 'scan timed out');
    if (e.code === 'BLOCKED_TARGET' || e.code === 'BAD_URL') return new ApiError(400, e.code, e.message);
    return new ApiError(502, 'SCAN_FAILED', 'target unreachable');
  }
  console.error('internal error:', e && e.message);
  return new ApiError(500, 'INTERNAL', 'internal error');
}

// deps (all optional, for tests): scan, resolveTxt, secret, host
export function createServer(deps = {}) {
  const scan = deps.scan || realScan;
  const resolveTxt = deps.resolveTxt || realResolveTxt;
  const bindHost = deps.host || process.env.HOST || '127.0.0.1';
  const trustProxy = process.env.HEADERSCAN_TRUST_PROXY === '1';
  // Behind the Cloudflare Pages proxy: /api/* (except health) needs the shared key; the real client IP arrives in x-headerscan-client.
  const proxyKey = process.env.HEADERSCAN_PROXY_KEY || '';
  const sha = (v) => crypto.createHash('sha256').update(String(v)).digest();
  const proxied = (req) => crypto.timingSafeEqual(sha(req.headers['x-headerscan-key'] || ''), sha(proxyKey));
  const index = loadIndex();
  const ver = version();
  let active = 0;
  const activeBy = new Map(); // limiter key -> running scans

  // ponytail: in-memory, resets on restart; per-process only, put a real limiter in front for multi-instance.
  const hits = new Map();
  const prune = setInterval(() => {
    const now = Date.now();
    for (const [k, arr] of hits) { const keep = arr.filter((t) => now - t < 60000); if (keep.length) hits.set(k, keep); else hits.delete(k); }
  }, 60000);
  prune.unref();

  function clientIp(req) {
    if (proxyKey && proxied(req)) {
      const c = String(req.headers['x-headerscan-client'] || '').trim();
      if (c) return c;
    }
    if (trustProxy) {
      const xff = String(req.headers['x-forwarded-for'] || '').split(',').pop().trim(); // rightmost = added by our proxy
      if (xff) return xff;
    }
    return req.socket.remoteAddress || 'unknown';
  }

  function limit(ip, rules) { // rules: [[bucket, perMinute], ...]; records only if every rule passes
    const now = Date.now();
    let wait = 0;
    const keys = rules.map(([b, max]) => {
      const k = `${b}|${ip}`;
      if (!hits.has(k) && hits.size > 50000) wait = 60; // bound memory under many-IP floods
      const arr = (hits.get(k) || []).filter((t) => now - t < 60000);
      if (arr.length >= max) wait = Math.max(wait, Math.ceil((arr[0] + 60000 - now) / 1000));
      return [k, arr];
    });
    if (wait > 0) throw new ApiError(429, 'RATE_LIMITED', 'too many requests, slow down', { 'Retry-After': String(wait) });
    for (const [k, arr] of keys) { arr.push(now); hits.set(k, arr); }
  }

  function readJson(req) {
    return new Promise((resolve, reject) => {
      if (!/^application\/json\b/i.test(req.headers['content-type'] || '')) return reject(new ApiError(400, 'BAD_REQUEST', 'Content-Type must be application/json'));
      if (Number(req.headers['content-length']) > MAX_BODY) return reject(new ApiError(413, 'TOO_LARGE', 'request body too large'));
      const chunks = [];
      let size = 0, over = false;
      req.on('data', (c) => { size += c.length; if (size > MAX_BODY) over = true; else chunks.push(c); });
      req.on('error', () => reject(new ApiError(400, 'BAD_REQUEST', 'bad request')));
      req.on('end', () => {
        if (over) return reject(new ApiError(413, 'TOO_LARGE', 'request body too large'));
        try {
          const j = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (!j || typeof j !== 'object' || Array.isArray(j)) throw new Error('not an object');
          resolve(j);
        } catch { reject(new ApiError(400, 'BAD_REQUEST', 'body must be a JSON object')); }
      });
    });
  }

  const normalizeUrl = (u) => {
    if (typeof u !== 'string' || !u.trim()) throw new ApiError(400, 'BAD_REQUEST', 'missing url');
    u = u.trim();
    return /^[a-z][a-z0-9+.-]*:\/\//i.test(u) ? u : 'https://' + u;
  };

  // Called before limit() too, so a rejection for capacity does not use up the client's per-minute quota.
  function admit(ip) {
    if (active >= MAX_ACTIVE) throw new ApiError(503, 'BUSY', 'server busy, try again shortly', { 'Retry-After': '10' });
    if ((activeBy.get(ip) || 0) >= MAX_PER_IP) throw new ApiError(429, 'RATE_LIMITED', 'too many scans running from your address, wait for one to finish', { 'Retry-After': '10' });
  }

  async function runScan(ip, url, deep, verified) {
    admit(ip);
    active++; activeBy.set(ip, (activeBy.get(ip) || 0) + 1);
    try { return await scan({ url, deep, verified }); } finally {
      active--;
      const n = activeBy.get(ip) - 1;
      if (n > 0) activeBy.set(ip, n); else activeBy.delete(ip);
    }
  }

  // Validate a host for verification: hostname only, public, not a shared platform domain or IP.
  function verifyHost(input) {
    if (typeof input !== 'string' || !input.trim()) throw new ApiError(400, 'BAD_REQUEST', 'missing host');
    const raw = input.trim();
    const host = parseTarget(raw.includes('://') ? raw : 'https://' + raw, { allowPrivate: process.env.HEADERSCAN_ALLOW_PRIVATE === '1' }).host;
    if (isSharedHost(host)) throw new ApiError(400, 'BAD_REQUEST', 'verification is not available for shared-platform domains or IP addresses');
    return host;
  }

  async function route(req, res, u) {
    const p = u.pathname;
    const ip = limiterKey(clientIp(req));
    if (proxyKey && p.startsWith('/api/') && p !== '/api/health' && !proxied(req)) throw new ApiError(403, 'FORBIDDEN', 'use the public site');
    if (p === '/' || p === '/index.html') {
      if (req.method !== 'GET' && req.method !== 'HEAD') throw new ApiError(405, 'METHOD_NOT_ALLOWED', 'method not allowed', { Allow: 'GET, HEAD' });
      // behind the proxy the UI lives on the Worker only: the backend is not a second public entry point
      if (!index || (proxyKey && !proxied(req))) throw new ApiError(404, 'NOT_FOUND', 'not found');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': index.csp, 'Cache-Control': 'no-store' });
      return res.end(index.body);
    }
    if (p === '/api/health') {
      if (req.method !== 'GET') throw new ApiError(405, 'METHOD_NOT_ALLOWED', 'method not allowed', { Allow: 'GET' });
      return send(res, 200, { ok: true, version: ver });
    }
    if (p === '/api/scan') {
      if (req.method === 'GET') {
        admit(ip);
        limit(ip, [['scan', 6]]);
        return send(res, 200, await runScan(ip, normalizeUrl(u.searchParams.get('url')), false, false));
      }
      if (req.method !== 'POST') throw new ApiError(405, 'METHOD_NOT_ALLOWED', 'method not allowed', { Allow: 'GET, POST' });
      const body = await readJson(req);
      const wantDeep = body.deep === true;
      admit(ip);
      limit(ip, wantDeep ? [['scan', 6], ['deep', 2]] : [['scan', 6]]);
      const url = normalizeUrl(body.url);
      if (!wantDeep) return send(res, 200, await runScan(ip, url, false, false));
      const target = parseTarget(url, { allowPrivate: process.env.HEADERSCAN_ALLOW_PRIVATE === '1' });
      // Ownership is re-checked on EVERY deep request; a client-supplied `verified` is never read.
      if (!(await isVerified(target.host, resolveTxt, { secret: deps.secret }))) {
        throw new ApiError(403, 'NOT_VERIFIED', `domain ownership not verified: add a DNS TXT record at ${txtNameFor(target.host)} (see POST /api/verify/start)`);
      }
      return send(res, 200, await runScan(ip, url, true, true));
    }
    if (p === '/api/verify/start' || p === '/api/verify/check') {
      if (req.method !== 'POST') throw new ApiError(405, 'METHOD_NOT_ALLOWED', 'method not allowed', { Allow: 'POST' });
      limit(ip, [['verify', 20]]);
      const host = verifyHost((await readJson(req)).host);
      if (p.endsWith('/start')) {
        const t = makeToken(host, { secret: deps.secret });
        return send(res, 200, { host, token: t.token, txtName: t.txtName, txtValue: t.txtValue, expiresAt: t.expiresAt });
      }
      return send(res, 200, { host, verified: await isVerified(host, resolveTxt, { secret: deps.secret }), txtName: txtNameFor(host) });
    }
    throw new ApiError(404, 'NOT_FOUND', 'not found');
  }

  function send(res, status, obj, extra = {}) {
    const body = Buffer.from(JSON.stringify(obj), 'utf8');
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Length': body.length, ...extra });
    res.end(body);
  }

  const server = http.createServer(async (req, res) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    try {
      // DNS-rebinding guard for the default loopback bind: only accept local Host headers.
      if (LOOPBACK.has(bindHost)) {
        const h = String(req.headers.host || '').replace(/:\d+$/, '').replace(/^\[|\]$/g, '').toLowerCase();
        if (!LOOPBACK.has(h)) throw new ApiError(400, 'BAD_REQUEST', 'unexpected Host header');
      }
      await route(req, res, new URL(req.url, 'http://localhost'));
    } catch (e) {
      const err = mapError(e);
      if (err.status === 413) { res.setHeader('Connection', 'close'); res.on('finish', () => req.destroy()); }
      if (res.headersSent) return res.end();
      send(res, err.status, { error: { code: err.code, message: err.message } }, err.headers);
    }
  });
  server.requestTimeout = 15000; // time allowed to RECEIVE the request; it does not cut off long scans (45 s deadline in lib/scan.js)
  server.on('close', () => clearInterval(prune));
  return server;
}

export function start({ port = Number(process.env.PORT) || 8787, host = process.env.HOST || '127.0.0.1', ...deps } = {}) {
  const server = createServer({ host, ...deps });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => resolve(server));
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  start().then((s) => {
    const a = s.address();
    console.log(`header-scan listening on http://${a.address}:${a.port}`);
  });
}
