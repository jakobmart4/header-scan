// Cloudflare Worker (static assets in dist/ are served by the platform; wrangler.toml run_worker_first routes only /api/* here).
// Thin proxy /api/* -> Node backend (BACKEND_URL). Secrets: BACKEND_URL, PROXY_KEY. The backend only accepts calls carrying PROXY_KEY.
const ROUTES = { '/api/scan': ['GET', 'POST'], '/api/verify/start': ['POST'], '/api/verify/check': ['POST'], '/api/health': ['GET'] };
const LOCAL = new Set(['localhost', '127.0.0.1', '[::1]']);
const WAKING = 'The scan server is waking up, please retry in about 30 seconds.';

// _headers (dist/_headers) is applied by the platform to static files only, never to Worker-generated responses, so the API sets its own.
// Keep in step with scripts/build-pages.mjs. The CSP is the API flavour: a JSON response needs no resources at all.
const SECURITY = {
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'referrer-policy': 'no-referrer',
  'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=()',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'content-security-policy': "default-src 'none'; frame-ancestors 'none'",
};

const json = (status, code, message, extra = {}) => new Response(JSON.stringify({ error: { code, message } }), {
  status, headers: { 'content-type': 'application/json', ...SECURITY, ...extra },
});

async function handle(request, env) {
  const url = new URL(request.url);
  // workers.dev answers plain HTTP too: send non-browser clients to HTTPS (browsers already do: .dev is HSTS-preloaded).
  if (url.protocol === 'http:' && !LOCAL.has(url.hostname)) {
    return new Response(null, { status: 308, headers: { location: `https://${url.host}${url.pathname}${url.search}`, ...SECURITY } });
  }
  const methods = ROUTES[url.pathname];
  if (!methods) return json(404, 'NOT_FOUND', 'not found');
  if (!methods.includes(request.method)) return json(405, 'METHOD_NOT_ALLOWED', 'method not allowed', { allow: methods.join(', ') });
  if (!env.BACKEND_URL || !env.PROXY_KEY) return json(500, 'MISCONFIGURED', 'server is not configured');

  const headers = new Headers({
    'x-headerscan-key': env.PROXY_KEY,
    'x-headerscan-client': request.headers.get('cf-connecting-ip') || '',
  });
  const ct = request.headers.get('content-type');
  if (ct) headers.set('content-type', ct);

  let res;
  try {
    res = await fetch(new URL(url.pathname + url.search, env.BACKEND_URL), {
      method: request.method, headers, redirect: 'manual',
      body: request.method === 'POST' ? request.body : undefined,
    });
  } catch {
    return json(502, 'BACKEND_UNREACHABLE', WAKING, { 'retry-after': '30' }); // free hosts sleep; usually the request just waits (~15 s measured), this is the fallback
  }
  const type = res.headers.get('content-type') || 'application/json';
  // A host that is still waking up (or down) answers with its own HTML 502/503/504: map it to our JSON error. The backend's own JSON 5xx pass through.
  if (res.status >= 502 && res.status <= 504 && !/json/i.test(type)) {
    res.body?.cancel().catch(() => {});
    return json(502, 'BACKEND_UNREACHABLE', WAKING, { 'retry-after': '30' });
  }
  const out = new Headers({ 'content-type': type, ...SECURITY });
  const ra = res.headers.get('retry-after');
  if (ra) out.set('retry-after', ra);
  return new Response(res.body, { status: res.status, headers: out });
}

export default { fetch: handle };
