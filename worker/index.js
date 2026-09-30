// Cloudflare Worker (static assets in dist/ are served by the platform; wrangler.toml run_worker_first routes only /api/* here).
// Thin proxy /api/* -> Node backend (BACKEND_URL). Secrets: BACKEND_URL, PROXY_KEY. The backend only accepts calls carrying PROXY_KEY.
const ROUTES = { '/api/scan': ['GET', 'POST'], '/api/verify/start': ['POST'], '/api/verify/check': ['POST'], '/api/health': ['GET'] };

const json = (status, code) => new Response(JSON.stringify({ error: { code } }), {
  status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
});

async function handle(request, env) {
  const url = new URL(request.url);
  const methods = ROUTES[url.pathname];
  if (!methods) return json(404, 'NOT_FOUND');
  if (!methods.includes(request.method)) return json(405, 'METHOD_NOT_ALLOWED');
  if (!env.BACKEND_URL || !env.PROXY_KEY) return json(500, 'MISCONFIGURED');

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
    return json(502, 'BACKEND_UNREACHABLE'); // free hosts sleep: first call may need a retry
  }
  const out = new Headers({
    'content-type': res.headers.get('content-type') || 'application/json',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  const ra = res.headers.get('retry-after');
  if (ra) out.set('retry-after', ra);
  return new Response(res.body, { status: res.status, headers: out });
}

export default { fetch: handle };
