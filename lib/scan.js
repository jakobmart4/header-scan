// Orchestrator: parse + SSRF-check target, fetch page, run check modules, score. See SPEC.md 2.5 / 2.6.
import { Resolver } from 'node:dns/promises';
import { parseTarget, assertPublicHost, safeFetch, FetchError } from './ssrf.js';
import { score } from './score.js';

const MODULES = ['headers', 'cookies', 'csp', 'tls', 'dns', 'html', 'site', 'probes']; // = category order
const CAT_ORDER = ['headers', 'cookies', 'tls', 'dns', 'mail', 'content', 'seo', 'ai', 'ux', 'exposure'];
const STATUS_ORDER = { fail: 0, warn: 1, info: 2, pass: 3, skipped: 4 };
const DEADLINE_MS = 45000;
const HOST_CONCURRENCY = 4;

let resolver;
const getResolver = () => (resolver ??= new Resolver({ timeout: 4000, tries: 2 }));
const isEmpty = (e) => e && (e.code === 'ENODATA' || e.code === 'ENOTFOUND');
async function q(fn) {
  try { return await fn(); } catch (e) { if (isEmpty(e)) return []; throw e; }
}

// name -> string[] (TXT chunks joined). Throws on real DNS errors; [] when the name has no TXT.
export async function resolveTxt(name) {
  return (await q(() => getResolver().resolveTxt(name))).map((chunks) => chunks.join(''));
}

// Best effort: ask a validating DoH resolver (fixed host) whether the answer was DNSSEC-validated (AD flag).
async function dnssec(host) {
  try {
    const r = await safeFetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A&do=1`,
      { headers: { accept: 'application/dns-json' }, maxBytes: 65536, timeoutMs: 5000 });
    const j = JSON.parse(r.body);
    if (j.Status !== 0) return { status: 'unknown' };
    return { status: j.AD === true ? 'signed' : 'unsigned' };
  } catch { return { status: 'unknown' }; }
}

function defaultResolve(host, allowPrivate) {
  const r = getResolver();
  const res = {
    a: () => q(() => r.resolve4(host)),
    aaaa: () => q(() => r.resolve6(host)),
    ns: () => q(() => r.resolveNs(host)),
    mx: (name = host) => q(() => r.resolveMx(name)),
    caa: async (name = host) => (await q(() => r.resolveCaa(name))).map((c) => {
      const tag = Object.keys(c).find((k) => k !== 'critical');
      return { critical: c.critical, tag, value: c[tag] };
    }),
    txt: (name = host) => resolveTxt(name),
  };
  if (!allowPrivate) res.dnssec = () => dnssec(host); // no third-party lookups in private/test mode
  return res;
}

// Per-host concurrency limiter for ctx.fetch.
function makeLimiter(max) {
  const hosts = new Map();
  return {
    async acquire(h) {
      let s = hosts.get(h);
      if (!s) hosts.set(h, (s = { active: 0, waiting: [] }));
      if (s.active < max) { s.active++; return; }
      await new Promise((r) => s.waiting.push(r));
    },
    release(h) {
      const s = hosts.get(h);
      const next = s.waiting.shift();
      if (next) next(); else s.active--;
    },
  };
}

// Raw response headers for the result (docs/PARITY-SPEC.md section 6). Cookie values never leave this function.
const RAW_MAX_HEADERS = 80, RAW_MAX_VALUE = 512, RAW_MAX_NAME = 128;
const COOKIE_KEEP = new Set(['expires', 'max-age', 'domain', 'path', 'secure', 'httponly', 'samesite', 'partitioned', 'priority']);
const SENSITIVE_NAME = /token|secret|csrf|xsrf|api[-_]?key|jwt|passw|session|^(proxy-)?authorization$/i;

function redactCookie(line) {
  const [pair, ...attrs] = String(line).split(';');
  const eq = pair.indexOf('=');
  const kept = attrs.map((a) => a.trim()).filter((a) => COOKIE_KEEP.has(a.split('=')[0].trim().toLowerCase()));
  return [`${(eq < 0 ? pair : pair.slice(0, eq)).trim()}=<redacted>`, ...kept].join('; ');
}

// headers (lowercase keys, arrival order) -> [{name, value}]; Set-Cookie redacted, long values cut.
export function buildRawHeaders(headers) {
  const out = [];
  const add = (name, value) => {
    out.push({ name, value: value.length > RAW_MAX_VALUE ? value.slice(0, RAW_MAX_VALUE - 3) + '...' : value });
  };
  for (const [key, v] of Object.entries(headers || {})) {
    if (out.length >= RAW_MAX_HEADERS) break;
    const lower = key.toLowerCase();
    const name = lower.slice(0, RAW_MAX_NAME);
    if (lower === 'set-cookie' || lower === 'set-cookie2') {
      for (const line of [].concat(v)) {
        if (out.length >= RAW_MAX_HEADERS) break;
        add(name, redactCookie(line));
      }
    } else add(name, SENSITIVE_NAME.test(key) ? '<redacted>' : Array.isArray(v) ? v.join(', ') : String(v));
  }
  return out;
}

function withDeadline(promise, deadline) {
  let t;
  const timer = new Promise((_, rej) => { t = setTimeout(() => rej(new Error('timeout')), Math.max(0, deadline - Date.now())); });
  return Promise.race([promise, timer]).finally(() => clearTimeout(t));
}

export async function scan({
  url, deep = false, verified = false, allowPrivate = process.env.HEADERSCAN_ALLOW_PRIVATE === '1', resolve, fetch: fetchImpl,
} = {}) {
  const t0 = Date.now();
  const deadline = t0 + DEADLINE_MS;
  deep = deep === true;
  verified = verified === true;
  const target = parseTarget(url, { allowPrivate });
  // An injected fetch is a test double (fake hosts); the server never injects one, so real scans always run this check.
  if (!fetchImpl) await assertPublicHost(target.host, { allowPrivate });

  const doFetch = fetchImpl || safeFetch;
  const limiter = makeLimiter(HOST_CONCURRENCY);
  const budget = { requestsLeft: deep && verified ? 100 : 60 };
  const errors = [];

  const ctx = {
    target, verified: deep && verified, allowPrivate, budget,
    page: { status: 0, headers: {}, body: '', finalUrl: target.url, redirects: [], timingMs: 0 },
    resolve: resolve || defaultResolve(target.host, allowPrivate),
    async fetch(u, o = {}) {
      let abs;
      try { abs = new URL(u, target.url); } catch { throw new FetchError('BAD_URL', 'invalid URL'); }
      if (budget.requestsLeft <= 0) throw new FetchError('BUDGET', 'request budget exhausted');
      budget.requestsLeft--;
      await limiter.acquire(abs.hostname);
      try {
        const left = deadline - Date.now();
        if (left <= 0) throw new FetchError('TIMEOUT', 'scan deadline reached');
        return await doFetch(abs.href, {
          ...o,
          maxBytes: Math.min(o.maxBytes ?? 262144, 1048576),
          timeoutMs: Math.min(o.timeoutMs ?? 10000, 10000, left),
          allowPrivate,
        });
      } finally { limiter.release(abs.hostname); }
    },
  };

  try {
    const r = await ctx.fetch(target.url, { maxBytes: 1048576, headers: { accept: 'text/html,application/xhtml+xml,*/*;q=0.8' } });
    ctx.page = {
      status: r.status, headers: { ...r.headers, 'set-cookie': [].concat(r.headers['set-cookie'] || []) },
      body: r.body, finalUrl: r.finalUrl, redirects: r.redirects, timingMs: r.timingMs,
    };
  } catch (e) {
    errors.push({ module: 'page', message: `error: ${e.code || 'FAILED'}` }); // modules still run and report `skipped`
  }

  // Active probes run only after every other module is done, so the target never sees them on top of the
  // passive traffic (their own 500 ms pacing then really is the request rate).
  const names = MODULES.filter((n) => n !== 'probes' || deep);
  const runModule = async (n) => {
    const m = await import(`./checks/${n}.js`);
    return withDeadline(m.run(ctx), deadline);
  };
  const ran = names.filter((n) => n !== 'probes');
  const settled = await Promise.allSettled(ran.map(runModule));
  if (names.includes('probes')) { ran.push('probes'); settled.push(...(await Promise.allSettled([runModule('probes')]))); }
  const findings = [];
  settled.forEach((s, i) => {
    if (s.status === 'fulfilled' && Array.isArray(s.value)) findings.push(...s.value);
    else {
      const e = s.reason;
      const message = s.status === 'fulfilled' ? 'module returned no findings array'
        : e && e.code === 'ERR_MODULE_NOT_FOUND' ? 'module not available' : String((e && e.message) || e).slice(0, 200);
      errors.push({ module: ran[i], message });
    }
  });

  const rank = (f) => CAT_ORDER.indexOf(f.category);
  findings.sort((a, b) => rank(a) - rank(b) || STATUS_ORDER[a.status] - STATUS_ORDER[b.status] || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

  // Result JSON (SPEC 2.6): rawHeaders = redacted response headers of the page fetch, [] when that fetch failed.
  return {
    url: target.url, host: target.host, scannedAt: new Date().toISOString(), durationMs: Date.now() - t0,
    verified: ctx.verified, deep, rawHeaders: buildRawHeaders(ctx.page.headers), score: score(findings), findings, errors,
  };
}
