// Test fixture: a deliberately bad ('bad'), SPA catch-all ('spa'), well-behaved ('good') or always-429 ('limited') site.
// All "secrets" below are obvious dummies. Also exports ctx builders so module tests need no orchestrator.
import http from 'node:http';

const SPA = '<!doctype html><html><head><title>App</title></head><body><div id="root"></div><script type="module" src="/assets/index-abc.js"></script></body></html>';
const SOFT = '<html><body>Nothing to see here</body></html>';

const BAD_HOME = `<!doctype html><html><head><meta charset="utf-8"></head><body>
<h1>Welcome</h1><h1>Welcome again</h1>
<img src="/logo.png">
<script src="http://insecure.example.net/a.js"></script>
<script src="https://cdn.example.net/lib.js"></script>
<script src="/app.js"></script>
<a href="/a">A</a> <a href="/b">B</a> <a href="/c">C</a>
</body></html>`;

const goodPage = (host, title, path) => `<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>${title}</title>
<meta name="description" content="${title}: a well behaved fixture page used by the header-scan test suite.">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#ffffff">
<link rel="canonical" href="http://${host}${path}">
<link rel="icon" href="/favicon.svg">
<meta property="og:title" content="${title}"><meta property="og:description" content="Fixture"><meta property="og:image" content="http://${host}/og.png">
<meta name="twitter:card" content="summary">
<script type="application/ld+json">{"@context":"https://schema.org","@type":"Organization","name":"Good Site"}</script>
</head><body><h1>${title}</h1><h2>Section</h2>
<img src="/logo.png" alt="Company logo">
<p>Questions? <a href="/contact">Contact us</a> or read <a href="/about">about us</a>. <a href="/">Home</a> <a href="/privacy">Privacy policy</a></p>
</body></html>`;

const GOOD_HEADERS = {
  'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=()',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-embedder-policy': 'require-corp',
  'cross-origin-resource-policy': 'same-origin',
  'cache-control': 'no-cache',
  'content-security-policy': "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; upgrade-insecure-requests",
};

function handle(mode, req, res) {
  const path = req.url.split('?')[0];
  const host = req.headers.host;
  const send = (status, type, body, extra = {}) => {
    res.writeHead(status, { 'content-type': type, ...extra });
    res.end(body);
  };
  if (mode === 'limited') return send(429, 'text/plain', 'slow down', { 'retry-after': '60' });
  if (mode === 'spa') return send(200, 'text/html; charset=utf-8', SPA);

  if (mode === 'bad') {
    const cors = req.headers.origin ? { 'access-control-allow-origin': req.headers.origin, 'access-control-allow-credentials': 'true' } : {};
    const base = { server: 'nginx/1.18.0', 'x-powered-by': 'Express', ...cors };
    if (path === '/') return send(200, 'text/html; charset=utf-8', BAD_HOME, { ...base, 'set-cookie': 'sessionid=abc; Path=/' });
    if (path === '/robots.txt') return send(200, 'text/plain', 'User-agent: GPTBot\nDisallow: /\n', base);
    if (path === '/app.js') return send(200, 'application/javascript', 'console.log(1);\n//# sourceMappingURL=app.js.map\n', base);
    if (path === '/.git/HEAD') return send(200, 'text/plain', 'ref: refs/heads/main\n', base);
    if (path === '/.env') return send(200, 'text/plain', 'SECRET_KEY=dummy\nDB_PASSWORD=fake\n', base);
    return send(200, 'text/html; charset=utf-8', SOFT, base); // soft 404 on purpose
  }

  // good
  const h = { ...GOOD_HEADERS };
  const pages = { '/': 'Good Site Home Page', '/about': 'About the Good Site', '/contact': 'Contact the Good Site', '/privacy': 'Privacy Policy of Good Site' };
  if (pages[path]) return send(200, 'text/html; charset=utf-8', goodPage(host, pages[path], path), h);
  if (path === '/robots.txt') return send(200, 'text/plain', `User-agent: *\nAllow: /\nSitemap: http://${host}/sitemap.xml\n`, h);
  if (path === '/sitemap.xml') return send(200, 'application/xml', `<?xml version="1.0"?><urlset><url><loc>http://${host}/</loc></url></urlset>`, h);
  if (path === '/llms.txt') return send(200, 'text/plain', '# Good Site\n> A well behaved fixture site for scanner tests.\n', h);
  if (path === '/.well-known/security.txt') return send(200, 'text/plain', 'Contact: mailto:security@example.test\nExpires: 2099-01-01T00:00:00.000Z\n', h);
  if (path === '/favicon.svg' || path === '/favicon.ico') return send(200, 'image/svg+xml', '<svg xmlns="http://www.w3.org/2000/svg"/>', h);
  return send(404, 'text/html; charset=utf-8', `<!doctype html><html><head><title>Page not found</title></head><body><h1>Page not found</h1><p>${'Sorry, we could not find that page. Try the home page or the contact form. '.repeat(5)}</p><a href="/">Home</a></body></html>`, h);
}

export async function start({ mode = 'bad' } = {}) {
  const requests = [];
  const sockets = new Set();
  const server = http.createServer((req, res) => {
    requests.push({ method: req.method, path: req.url.split('?')[0], headers: req.headers });
    handle(mode, req, res);
  });
  server.on('connection', (s) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}`,
    port,
    requests,
    close: () => new Promise((r) => { for (const s of sockets) s.destroy(); server.close(() => r()); }),
  };
}

// Resolver stub: no records anywhere (never touches real DNS). Override single functions via `over`.
export function stubResolve(over = {}) {
  return { a: async () => [], aaaa: async () => [], ns: async () => [], mx: async () => [], caa: async () => [], txt: async () => [], ...over };
}

// Hand-made ctx for unit tests (no network). `fetch` defaults to an empty 404.
export function fakeCtx({ url = 'https://example.test/', headers = {}, body = '', status = 200, fetch, resolve, verified = false } = {}) {
  const u = new URL(url);
  const empty = async (x) => ({ status: 404, headers: {}, body: '', finalUrl: String(x || url), timingMs: 1, redirects: [], truncated: false });
  return {
    target: { url, host: u.hostname, origin: u.origin },
    verified,
    allowPrivate: false,
    fetch: fetch || empty,
    page: { status, headers, body, finalUrl: url, redirects: [], timingMs: 1 },
    resolve: resolve || stubResolve(),
    budget: { requestsLeft: 50 },
  };
}

// Real ctx against a running fixture (same shape the orchestrator builds), for module tests.
export async function buildCtx(url, { verified = false, resolve } = {}) {
  const { parseTarget, safeFetch } = await import('../lib/ssrf.js');
  const target = parseTarget(url, { allowPrivate: true });
  const budget = { requestsLeft: 100 };
  const fetch = async (u, o = {}) => {
    if (budget.requestsLeft-- <= 0) throw Object.assign(new Error('budget'), { code: 'BUDGET' });
    return safeFetch(u, { allowPrivate: true, ...o });
  };
  let page = { status: 0, headers: {}, body: '', finalUrl: target.url, redirects: [], timingMs: 0 };
  try { page = await fetch(target.url, { maxBytes: 1048576 }); } catch { /* keep empty page */ }
  return { target, verified, allowPrivate: true, fetch, page, resolve: resolve || stubResolve(), budget };
}
