// Writes public/samples/perfect.json and public/samples/mixed.json: clearly labelled SAMPLE reports for the UI.
// Both are produced by the REAL scan() against an in-memory fake site (injected fetch + DNS stub), so findings, titles,
// severities, evidence and fixes come from the real check modules, and the scores from lib/score.js.
// Only the TLS handshake checks cannot run offline: their status and evidence are the TLS_SAMPLE table below (strings copied
// from lib/checks/tls.js). Output is deterministic (fixed date and duration). Run: node scripts/sample-reports.mjs
import { mkdirSync, writeFileSync } from 'node:fs';
import { scan } from '../lib/scan.js';
import { score, finding } from '../lib/score.js';

const HOST = 'sample.invalid';
const SAMPLE_DATE = '2026-10-05T09:00:00.000Z';
const CAT_ORDER = ['headers', 'cookies', 'tls', 'dns', 'mail', 'content', 'seo', 'ai', 'ux', 'exposure']; // same order as lib/scan.js
const STATUS_ORDER = { fail: 0, warn: 1, info: 2, pass: 3, skipped: 4 };

// ---- fake site -------------------------------------------------------------------------------------------------------------
const page = (title, desc, body, { head = '', lang = 'en' } = {}) => `<!doctype html><html${lang ? ` lang="${lang}"` : ''}><head><meta charset="utf-8">
<title>${title}</title>${desc ? `\n<meta name="description" content="${desc}">` : ''}
${head}</head><body>${body}</body></html>`;

const NOT_FOUND = `<!doctype html><html lang="en"><head><title>Page not found</title></head><body><h1>Page not found</h1><p>${'Sorry, we could not find that page. Try the home page or one of the links below. '.repeat(5)}</p><a href="/">Home</a></body></html>`;
const sub = (path, title) => page(title, `${title}: a sample page of the header-scan sample site, used to show what a finished report looks like.`,
  `<h1>${title}</h1><p>Sample content.</p><a href="/">Home</a>`);

const LD_FULL = JSON.stringify([
  { '@context': 'https://schema.org', '@type': 'LocalBusiness', name: 'Sample Site', address: { '@type': 'PostalAddress', streetAddress: '1 Sample Street', addressLocality: 'Sampleville' },
    telephone: '+000 000 0000', openingHours: 'Mo-Fr 09:00-17:00', hasMap: 'https://www.openstreetmap.org/#map=16/0/0',
    aggregateRating: { '@type': 'AggregateRating', ratingValue: '4.8', reviewCount: '12' } },
  { '@context': 'https://schema.org', '@type': 'BreadcrumbList', itemListElement: [{ '@type': 'ListItem', position: 1, name: 'Home' }] },
  { '@context': 'https://schema.org', '@type': 'FAQPage', mainEntity: [1, 2, 3, 4, 5].map((n) => ({ '@type': 'Question', name: `Sample question ${n}?`, acceptedAnswer: { '@type': 'Answer', text: 'Sample answer.' } })) },
]);
const LD_BASIC = JSON.stringify({ '@context': 'https://schema.org', '@type': 'Organization', name: 'Sample Site' });

const PERFECT = {
  home: page('Sample Site: a perfectly configured demo', 'A sample site that passes every header-scan check, used to show what a finished report looks like.',
    `<nav aria-label="Breadcrumb"><a href="/">Home</a></nav>
<h1>Sample Site</h1><p><a href="/contact">Contact us</a> or read <a href="/about">about us</a>. We reply within 24 hours.</p>
<h2>Our work</h2><p><a href="/case-studies">Case studies</a> <a href="/faq">FAQ</a> <a href="/privacy">Privacy policy</a></p>
<img src="/team.svg" alt="The sample team" width="64" height="64">
<iframe src="https://www.openstreetmap.org/export/embed.html" title="Map" width="200" height="100"></iframe>
<p>This site uses no tracking cookies. Cookie notice: only a strictly necessary session cookie is set.</p>`,
    { head: `<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#ffffff">
<link rel="canonical" href="https://${HOST}/">
<link rel="icon" href="/favicon.svg">
<meta property="og:title" content="Sample Site"><meta property="og:description" content="Sample"><meta property="og:image" content="https://${HOST}/og.png">
<meta name="twitter:card" content="summary_large_image">
<script type="application/ld+json">${LD_FULL}</script>
<script src="/assets/app.js"></script>
<script async src="https://plausible.io/js/script.js" integrity="sha384-sample" crossorigin="anonymous"></script>
` }),
  headers: {
    'strict-transport-security': 'max-age=63072000; includeSubDomains; preload', 'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY', 'referrer-policy': 'strict-origin-when-cross-origin', 'permissions-policy': 'camera=()',
    'cross-origin-opener-policy': 'same-origin', 'cross-origin-embedder-policy': 'require-corp', 'cross-origin-resource-policy': 'same-origin',
    'cache-control': 'private, max-age=0, must-revalidate',
    'content-security-policy': "default-src 'none'; script-src 'self' https://plausible.io; style-src 'self'; img-src 'self'; frame-src https://www.openstreetmap.org; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; upgrade-insecure-requests",
    'set-cookie': ['__Host-sid=x; Path=/; Secure; HttpOnly; SameSite=Lax'],
  },
  compressed: true, redirect: 301, sitemap: true, llms: true, robots: 'User-agent: *\nAllow: /\nSitemap: https://sample.invalid/sitemap.xml\n',
  security: 'Contact: https://sample.invalid/security\nExpires: 2099-01-01T00:00:00.000Z\n', thanks: true, subs: ['/about', '/contact', '/privacy', '/case-studies', '/faq'],
  script: true,
};

// A typical neglected site: HTTPS with a half-finished header set, loose cookies, thin SEO, partial mail setup.
const MIXED = {
  home: page('', '', `<h1>Welcome</h1><h1>Welcome again</h1>
<img src="http://${HOST}/logo.png" alt="Logo"><img src="/team.png">
<script src="/assets/app.js"></script>
<script src="http://cdn.example.net/lib.js"></script>`,
    { lang: '', head: `<meta property="og:title" content="Sample Site">
` }),
  headers: {
    server: 'nginx/1.18.0', 'x-powered-by': 'Express', 'x-xss-protection': '1; mode=block', 'access-control-allow-origin': '*', 'access-control-allow-credentials': 'true',
    'set-cookie': ['sid=x; Path=/', 'pref=1; Path=/; Domain=.sample.invalid; Max-Age=63072000; SameSite=None'],
  },
  compressed: false, redirect: 302, sitemap: false, llms: false, robots: 'User-agent: *\nDisallow: /\n',
  security: null, thanks: false, subs: ['/about', '/contact', '/products'], script: true,
};

function makeFetch(p) {
  const html = { 'content-type': 'text/html; charset=utf-8', ...p.headers };
  const plain = (type, body, status = 200) => ({ status, headers: { 'content-type': type }, body });
  const routes = {
    '/': { status: 200, headers: html, body: p.home },
    '/robots.txt': plain('text/plain', p.robots),
    '/favicon.svg': plain('image/svg+xml', '<svg xmlns="http://www.w3.org/2000/svg"/>'),
    '/assets/app.js': plain('application/javascript', 'console.log(1);\n'),
  };
  if (p.sitemap) routes['/sitemap.xml'] = plain('application/xml', `<?xml version="1.0"?><urlset>${['/', ...p.subs].map((s) => `<url><loc>https://${HOST}${s}</loc></url>`).join('')}</urlset>`);
  if (p.llms) routes['/llms.txt'] = plain('text/plain', '# Sample Site\n> A sample site used to show what a finished report looks like.\n');
  if (p.security) routes['/.well-known/security.txt'] = plain('text/plain', p.security);
  if (p.thanks) routes['/thank-you'] = { status: 200, headers: html, body: sub('/thank-you', 'Thank you') };
  for (const s of p.subs) routes[s] = { status: 200, headers: html, body: sub(s, s.slice(1).replace(/-/g, ' ').replace(/^./, (c) => c.toUpperCase()) + ' page') };

  return async (url, o = {}) => {
    const u = new URL(url);
    const req = Object.fromEntries(Object.entries(o.headers || {}).map(([k, v]) => [k.toLowerCase(), v]));
    const base = { finalUrl: u.href, timingMs: 5, redirects: [], truncated: false };
    if (u.protocol === 'http:') return { ...base, status: p.redirect, headers: { location: `https://${HOST}${u.pathname}` }, body: '' };
    let r = routes[u.pathname] || { status: 404, headers: html, body: NOT_FOUND };
    r = { ...r, headers: { ...r.headers } };
    if (p.compressed && req['accept-encoding'] && r.headers['content-type'].startsWith('text/html')) r.headers['content-encoding'] = 'br';
    if (u.pathname === '/assets/app.js' && o.method === 'HEAD') { r.headers['content-length'] = '2048'; if (p.compressed) r.headers['content-encoding'] = 'br'; }
    return { ...base, ...r, body: o.method === 'HEAD' ? '' : r.body };
  };
}

// ---- DNS stub (what the real dns.js module would read from a zone) -----------------------------------------------------------
const resolver = (z) => ({
  a: async () => ['192.0.2.1'], aaaa: async () => z.aaaa || [], ns: async () => ['ns1.sample.invalid', 'ns2.sample.invalid'], mx: async () => [{ priority: 10, exchange: 'mx.sample.invalid' }],
  caa: async () => z.caa || [],
  txt: async (name) => z.txt[name] || [],
  dnssec: async () => ({ status: z.dnssec }),
});
const ZONE_PERFECT = {
  aaaa: ['2001:db8::1'], dnssec: 'signed', caa: [{ critical: 0, tag: 'issue', value: 'letsencrypt.org' }],
  txt: {
    [HOST]: ['v=spf1 mx -all'], [`_dmarc.${HOST}`]: ['v=DMARC1; p=reject; rua=mailto:dmarc@sample.invalid'],
    [`_mta-sts.${HOST}`]: ['v=STSv1; id=1'], [`_smtp._tls.${HOST}`]: ['v=TLSRPTv1; rua=mailto:tls@sample.invalid'], [`default._domainkey.${HOST}`]: ['v=DKIM1; k=rsa; p=AAAA'],
  },
};
const ZONE_MIXED = { aaaa: [], dnssec: 'unsigned', caa: [], txt: { [`_dmarc.${HOST}`]: ['v=DMARC1; p=none'] } };

// ---- TLS handshake checks cannot run offline: [status, evidence] per id; fix texts are those of lib/checks/tls.js ------------
const TLS_FIX = {
  'tls-https': 'Serve the site over HTTPS with a valid certificate.', 'tls-protocol': 'Enable TLS 1.2/1.3 and disable older versions.',
  'tls-legacy-protocols': 'Disable TLS 1.0 and 1.1 on the server.', 'tls-cert-expiry': 'Renew the certificate (automate renewal).',
  'tls-cert-host': 'Issue a certificate that includes this hostname in its SAN list.', 'tls-cert-chain': 'Install a certificate from a trusted CA and serve the full intermediate chain.',
  'tls-cert-key': 'Use an RSA key of at least 2048 bits or an EC key.', 'tls-cert-sigalg': 'Reissue the certificate with a SHA-256 or stronger signature.',
  'tls-alpn-h2': 'Enable HTTP/2 for better performance.',
};
const TLS_PERFECT = {
  'tls-https': ['pass', 'HTTPS reachable'], 'tls-protocol': ['pass', 'negotiated TLSv1.3'], 'tls-legacy-protocols': ['pass', 'TLS 1.0/1.1 rejected'],
  'tls-cert-expiry': ['pass', 'expires in 61 days'], 'tls-cert-host': ['pass', `covers ${HOST}`], 'tls-cert-chain': ['pass', 'chain trusted'],
  'tls-cert-key': ['pass', 'EC 256 bits'], 'tls-cert-sigalg': ['pass', 'ecdsa-with-SHA256'], 'tls-alpn-h2': ['pass', 'ALPN: h2'],
};
const TLS_MIXED = {
  ...TLS_PERFECT, 'tls-protocol': ['pass', 'negotiated TLSv1.2'], 'tls-legacy-protocols': ['fail', 'server accepted TLS 1.0/1.1'],
  'tls-cert-expiry': ['fail', 'expired 3 days ago'], 'tls-cert-key': ['pass', 'RSA 2048 bits'], 'tls-cert-sigalg': ['fail', 'sha1WithRSA'], 'tls-alpn-h2': ['info', 'ALPN: http/1.1'],
};

export async function build(name) {
  const [p, zone, tls] = name === 'perfect' ? [PERFECT, ZONE_PERFECT, TLS_PERFECT] : [MIXED, ZONE_MIXED, TLS_MIXED];
  const r = await scan({ url: `https://${HOST}/`, fetch: makeFetch(p), resolve: resolver(zone) });
  r.findings = r.findings.map((f) => (tls[f.id]
    ? finding(f.id, f.category, f.title, tls[f.id][0], f.severity, { evidence: tls[f.id][1], fix: tls[f.id][0] === 'pass' ? '' : TLS_FIX[f.id], ref: f.ref, checklist: f.checklist })
    : f));
  r.findings.sort((a, b) => CAT_ORDER.indexOf(a.category) - CAT_ORDER.indexOf(b.category) || STATUS_ORDER[a.status] - STATUS_ORDER[b.status] || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  r.score = score(r.findings);
  r.scannedAt = SAMPLE_DATE;
  r.durationMs = 0;
  return { sample: true, ...r };
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/').split('/').pop())) {
  const dir = new URL('../public/samples/', import.meta.url);
  mkdirSync(dir, { recursive: true });
  for (const name of ['perfect', 'mixed']) {
    const r = await build(name);
    writeFileSync(new URL(`${name}.json`, dir), JSON.stringify(r, null, 1) + '\n');
    const c = {};
    for (const f of r.findings) c[f.status] = (c[f.status] || 0) + 1;
    console.log(name, `security ${r.score.security.grade} ${r.score.security.score}, quality ${r.score.quality.grade} ${r.score.quality.score}`, JSON.stringify(c), 'errors', r.errors.length);
  }
}
