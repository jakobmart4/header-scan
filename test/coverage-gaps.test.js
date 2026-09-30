process.env.HEADERSCAN_ALLOW_PRIVATE = '1';
// Coverage for check IDs that no other test asserts on. Hand-made ctx objects only (no real network).
import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import { run as runHeaders } from '../lib/checks/headers.js';
import { run as runHtml } from '../lib/checks/html.js';
import { run as runSite } from '../lib/checks/site.js';
import { run as runTls } from '../lib/checks/tls.js';
import { run as runProbes } from '../lib/checks/probes.js';
import { fakeCtx } from './fixture-server.js';

const by = (fs) => Object.fromEntries(fs.map((f) => [f.id, f]));
const res = (status, headers = {}, body = '') => ({ status, headers, body, finalUrl: '', timingMs: 1, redirects: [], truncated: false });

// ---------------------------------------------------------------- headers.js
describe('headers.js: cache-control + compression', () => {
  const H = (headers, body = '<p>x</p>', fetch) => runHeaders(fakeCtx({ headers: { 'content-type': 'text/html', ...headers }, body, fetch })).then(by);
  test('hdr-cache-control-html', async () => {
    assert.equal((await H({ 'set-cookie': ['a=1'] }))['hdr-cache-control-html'].status, 'warn');
    assert.equal((await H({}))['hdr-cache-control-html'].status, 'warn'); // missing
    assert.equal((await H({ 'set-cookie': ['a=1'], 'cache-control': 'private' }))['hdr-cache-control-html'].status, 'pass');
    assert.equal((await H({ 'cache-control': 'no-cache' }))['hdr-cache-control-html'].status, 'pass');
    assert.equal((await H({ 'content-type': 'application/json' }))['hdr-cache-control-html'].status, 'skipped');
  });
  test('hdr-compression', async () => {
    const enc = (e) => async () => res(200, e ? { 'content-encoding': e } : {});
    assert.equal((await H({}, '<p>x</p>', enc('gzip')))['hdr-compression'].status, 'pass');
    assert.equal((await H({}, 'x'.repeat(3000), enc('')))['hdr-compression'].status, 'warn');
    assert.equal((await H({}, '<p>x</p>', enc('')))['hdr-compression'].status, 'skipped');
  });
});

// ---------------------------------------------------------------- tls.js
describe('tls.js', () => {
  // Handshake to 127.0.0.1:1 is refused instantly; only the stubbed http redirect matters here.
  const T = async (fetch) => by(await runTls({ ...fakeCtx({ url: 'https://127.0.0.1:1/', fetch }), allowPrivate: true }));
  test('tls-http-redirect + tls-redirect-permanent', async () => {
    let f = await T(async () => res(301, { location: 'https://example.test/' }));
    assert.equal(f['tls-http-redirect'].status, 'pass');
    assert.equal(f['tls-redirect-permanent'].status, 'pass');
    f = await T(async () => res(302, { location: 'https://example.test/' }));
    assert.equal(f['tls-http-redirect'].status, 'pass');
    assert.equal(f['tls-redirect-permanent'].status, 'info');
    f = await T(async () => res(200, {}, 'hi'));
    assert.equal(f['tls-http-redirect'].status, 'fail');
    assert.equal(f['tls-redirect-permanent'].status, 'skipped');
    f = await T(async () => { throw Object.assign(new Error('x'), { code: 'NETWORK' }); });
    assert.equal(f['tls-http-redirect'].status, 'info');
    f = await T(async () => res(301, { location: 'http://example.test/other' }));
    assert.equal(f['tls-http-redirect'].status, 'fail');
  });
  test('tls-legacy-protocols', (t) => t.skip('needs a real TLS server (self-signed cert + TLS1.0/1.1 support); not faked'));
  test('tls-alpn-h2', (t) => t.skip('needs a real TLS server negotiating ALPN h2; not faked'));
});

// ---------------------------------------------------------------- html.js
describe('html.js: UX heuristics', () => {
  const ok = async (u) => res(200, {}, '<html>privacy policy text</html>');
  const H = async (body, fetch = ok) => by(await runHtml(fakeCtx({ body, fetch })));
  const st = async (id, body, fetch) => (await H(body, fetch))[id].status;
  const ld = (o) => `<script type="application/ld+json">${JSON.stringify(o)}</script>`;

  test('ux-cta-above-fold', async () => {
    assert.equal(await st('ux-cta-above-fold', '<body><a href="/contact">Contact us</a></body>'), 'pass');
    assert.equal(await st('ux-cta-above-fold', '<body><a href="tel:+3725551234">555</a></body>'), 'pass');
    assert.equal(await st('ux-cta-above-fold', '<body><p>hello</p><a href="/x">Read more</a></body>'), 'warn');
    // CTA beyond the first 3000 chars of body must not count
    assert.equal(await st('ux-cta-above-fold', `<body><p>${'x'.repeat(3200)}</p><a href="/contact">Contact</a></body>`), 'warn');
  });
  test('ux-breadcrumbs', async () => {
    assert.equal(await st('ux-breadcrumbs', '<nav aria-label="Breadcrumb"><a href="/">Home</a></nav>'), 'pass');
    assert.equal(await st('ux-breadcrumbs', ld({ '@type': 'BreadcrumbList', itemListElement: [] })), 'pass');
    assert.equal(await st('ux-breadcrumbs', '<p>none</p>'), 'info');
  });
  test('ux-case-studies', async () => {
    assert.equal(await st('ux-case-studies', '<a href="/portfolio">Work</a>'), 'pass');
    assert.equal(await st('ux-case-studies', '<a href="/tood">Tood</a>'), 'pass');
    assert.equal(await st('ux-case-studies', '<a href="/about">About</a>'), 'info');
  });
  test('ux-faq', async () => {
    const d = (n) => `<body>${'<details><summary>Q?</summary>A</details>'.repeat(n)}</body>`;
    assert.equal(await st('ux-faq', d(5)), 'pass');
    assert.equal(await st('ux-faq', d(2)), 'warn');
    assert.equal(await st('ux-faq', '<p>nothing</p>'), 'info');
    const faq = { '@type': 'FAQPage', mainEntity: Array.from({ length: 5 }, () => ({ '@type': 'Question', name: 'q' })) };
    assert.equal(await st('ux-faq', ld(faq)), 'pass');
  });
  test('ux-response-time', async () => {
    assert.equal(await st('ux-response-time', '<p>We reply within 24 hours.</p>'), 'pass');
    assert.equal(await st('ux-response-time', '<p>Vastame kiiresti</p>'), 'pass');
    assert.equal(await st('ux-response-time', '<p>Contact us anytime.</p>'), 'info');
    // suspected bug: "24 ?h" matches the "24 H" of "2024 Home"
    assert.equal(await st('ux-response-time', '<p>Copyright 2024 Home Ltd</p>'), 'info');
  });
  test('ux-maps', async () => {
    assert.equal(await st('ux-maps', '<iframe src="https://www.google.com/maps/embed?pb=1"></iframe>'), 'pass');
    assert.equal(await st('ux-maps', '<a href="https://maps.app.goo.gl/abc">Map</a>'), 'pass');
    assert.equal(await st('ux-maps', ld({ '@type': 'Place', geo: { latitude: 1 } })), 'pass');
    assert.equal(await st('ux-maps', '<iframe src="https://youtube.com/embed/x"></iframe>'), 'info');
  });
  test('ux-reviews', async () => {
    assert.equal(await st('ux-reviews', ld({ '@type': 'Product', aggregateRating: { ratingValue: 5 } })), 'pass');
    assert.equal(await st('ux-reviews', '<script src="https://static.elfsight.com/platform/platform.js"></script>'), 'pass');
    assert.equal(await st('ux-reviews', '<p>We are not on trustpilot yet</p>'), 'info'); // plain text mention is not a widget
    assert.equal(await st('ux-reviews', '<p>no social proof</p>'), 'info');
  });
  test('ux-local-schema', async () => {
    const full = { '@type': 'Dentist', address: 'x', telephone: '1', openingHours: 'Mo-Fr 9-17' };
    assert.equal(await st('ux-local-schema', ld(full)), 'pass');
    assert.equal(await st('ux-local-schema', ld({ '@type': 'LocalBusiness', address: 'x' })), 'warn');
    assert.equal(await st('ux-local-schema', ld({ '@type': 'Organization', name: 'x' })), 'info');
  });
  test('ux-privacy-policy', async () => {
    const link = '<a href="/privacy">Privacy policy</a>';
    assert.equal(await st('ux-privacy-policy', link), 'pass');
    assert.equal(await st('ux-privacy-policy', link, async () => res(404)), 'warn');
    assert.equal(await st('ux-privacy-policy', link, async () => res(200, {}, '  ')), 'warn');
    assert.equal(await st('ux-privacy-policy', '<form action="/x"></form>'), 'fail');
    assert.equal(await st('ux-privacy-policy', '<p>no form no analytics</p>'), 'warn');
  });
  test('ux-analytics', async () => {
    const f = (await H('<script async src="https://www.googletagmanager.com/gtag/js?id=G-ABCDEF1234"></script>'))['ux-analytics'];
    assert.equal(f.status, 'pass');
    assert.match(f.evidence, /GDPR/); // no consent keywords
    const g = (await H('<script src="https://plausible.io/js/x.js"></script><div>We use cookie consent</div>'))['ux-analytics'];
    assert.equal(g.status, 'pass');
    assert.doesNotMatch(g.evidence, /GDPR/);
    assert.equal(await st('ux-analytics', '<p>none</p>'), 'info');
  });
  test('ux-team-photo', async () => {
    const yes = (await H('<img src="/team.jpg" alt="Our team">'))['ux-team-photo'];
    const no = (await H('<img src="/logo.png" alt="logo">'))['ux-team-photo'];
    assert.equal(yes.status, 'info');
    assert.equal(no.status, 'info');
    assert.match(yes.evidence, /^team-like image found/);
    assert.match(no.evidence, /^no team-like/);
  });
});

// ---------------------------------------------------------------- site.js
// Router-backed fetch: routes[path] = [status, contentType, body, extraHeaders] | fn(opts) -> result
function siteCtx(html, routes = {}, url = 'https://example.test/') {
  const fetch = async (u, opts = {}) => {
    const p = new URL(u).pathname;
    let r = routes[p];
    if (typeof r === 'function') r = r(opts);
    if (!r) return res(404, { 'content-type': 'text/plain' }, '');
    const [status, type = 'text/plain', body = '', extra = {}] = r;
    return { ...res(status, { 'content-type': type, ...extra }, opts.method === 'HEAD' ? '' : body), finalUrl: u };
  };
  return fakeCtx({ url, body: html, fetch });
}
const S = async (html, routes, url) => by(await runSite(siteCtx(html, routes, url)));
const PAGE = '<html><body><p>home</p></body></html>';

describe('site.js: robots-sensitive, thank-you, bundles, source maps', () => {
  test('seo-robots-sensitive', async () => {
    let f = await S(PAGE, { '/robots.txt': [200, 'text/plain', 'User-agent: *\nDisallow: /admin\nDisallow: /wp-admin/\n'] });
    assert.equal(f['seo-robots-sensitive'].status, 'info');
    assert.match(f['seo-robots-sensitive'].evidence, /\/admin/);
    f = await S(PAGE, { '/robots.txt': [200, 'text/plain', 'User-agent: *\nDisallow: /tmp\n'] });
    assert.equal(f['seo-robots-sensitive'].status, 'pass');
    f = await S(PAGE, {});
    assert.equal(f['seo-robots-sensitive'].status, 'skipped');
  });

  test('ux-thank-you', async () => {
    const thanks = { '/thank-you': [200, 'text/html', '<html><body><h1>Thanks for your message, we will be in touch</h1></body></html>'] };
    assert.equal((await S(PAGE, thanks))['ux-thank-you'].status, 'pass');
    assert.equal((await S(PAGE, {}))['ux-thank-you'].status, 'info');
    assert.equal((await S('<html><body><form action="/s"></form></body></html>', {}))['ux-thank-you'].status, 'warn');
    // SPA catch-all serving the home shell on /thank-you must not count
    const shellAll = { '/thank-you': [200, 'text/html', PAGE], '/thanks': [200, 'text/html', PAGE] };
    assert.notEqual((await S(PAGE, shellAll))['ux-thank-you'].status, 'pass');
  });

  const SCRIPT_PAGE = '<html><body><script src="/a.js"></script></body></html>';
  const script = ({ get = {}, head = {}, body = 'console.log(1);' } = {}) => (o) =>
    o.method === 'HEAD' ? [200, 'application/javascript', '', head] : [200, 'application/javascript', body, get];

  test('ux-js-bundle-size', async () => {
    let f = await S(SCRIPT_PAGE, { '/a.js': script({ head: { 'content-encoding': 'gzip', 'content-length': '500' } }) });
    assert.equal(f['ux-js-bundle-size'].status, 'pass');
    f = await S(SCRIPT_PAGE, { '/a.js': script({ get: { 'content-length': '5000' }, head: { 'content-length': '5000' } }) });
    assert.equal(f['ux-js-bundle-size'].status, 'warn'); // uncompressed
    f = await S(SCRIPT_PAGE, { '/a.js': script({ get: { 'content-length': '2000000' }, head: { 'content-encoding': 'gzip', 'content-length': '2000000' } }) });
    assert.equal(f['ux-js-bundle-size'].status, 'fail'); // > 1 MB
    f = await S(PAGE, {});
    assert.equal(f['ux-js-bundle-size'].status, 'info');
  });

  test('exp-source-maps', async () => {
    const withMap = 'console.log(1);\n//# sourceMappingURL=a.js.map\n';
    const head = { 'content-encoding': 'gzip', 'content-length': '500' };
    let f = await S(SCRIPT_PAGE, { '/a.js': script({ body: withMap, head }), '/a.js.map': [200, 'application/json', '{}'] });
    assert.equal(f['exp-source-maps'].status, 'warn');
    f = await S(SCRIPT_PAGE, { '/a.js': script({ body: withMap, head }) }); // .map is 404
    assert.equal(f['exp-source-maps'].status, 'pass');
    // a soft-404 HTML page at the .map URL is not an exposed map
    f = await S(SCRIPT_PAGE, { '/a.js': script({ body: withMap, head }), '/a.js.map': [200, 'text/html', '<html>nope</html>'] });
    assert.equal(f['exp-source-maps'].status, 'pass');
    // inline data: map is not a separate public file
    f = await S(SCRIPT_PAGE, { '/a.js': script({ body: 'x\n//# sourceMappingURL=data:application/json;base64,e30=\n', head }) });
    assert.equal(f['exp-source-maps'].status, 'pass');
    f = await S(SCRIPT_PAGE, { '/a.js': script({ body: 'x', head }) });
    assert.equal(f['exp-source-maps'].status, 'pass');
    f = await S(PAGE, {});
    assert.equal(f['exp-source-maps'].status, 'skipped');
  });
});

// ---------------------------------------------------------------- probes.js
// One run where every probe has a matching signature (all HITs) and one where nothing exists.
// probes.js sleeps 500 ms between requests, so both runs go in parallel in before().
const HIT_BODY = {
  '/.hg/requires': 'revlogv1\nstore\n',
  '/.DS_Store': '\x00\x00\x00\x01Bud1\x00\x00',
  '/backup.sql': '-- MySQL dump 10.13\nCREATE TABLE t (id int);',
  '/backup.tar.gz': '\x1f\x8b\x08\x00binary',
  '/db.sql': 'INSERT INTO t VALUES (1);',
  '/wp-config.php.bak': '<?php // config',
  '/phpinfo.php': '<title>phpinfo()</title>',
  '/server-status': '<h1>Apache Server Status for host</h1>',
  '/actuator': '{"_links":{}}',
  '/admin': '<form><input type="password" name="p"></form>',
  '/debug': 'Traceback (most recent call last):',
  '/swagger.json': '{"swagger":"2.0"}',
  '/openapi.json': '{"openapi":"3.0.0"}',
  '/package.json': '{"dependencies":{}}',
  '/.vercel/project.json': '{"projectId":"x"}',
  '/WEB-INF/web.xml': '<web-app></web-app>',
};
const PROBE_ID = {
  hg: '/.hg/requires', 'ds-store': '/.DS_Store', 'backup-sql': '/backup.sql', 'backup-tgz': '/backup.tar.gz', 'db-sql': '/db.sql',
  'wp-config-bak': '/wp-config.php.bak', phpinfo: '/phpinfo.php', 'server-status': '/server-status', actuator: '/actuator', admin: '/admin',
  debug: '/debug', swagger: '/swagger.json', openapi: '/openapi.json', 'package-json': '/package.json', vercel: '/.vercel/project.json', 'web-inf': '/WEB-INF/web.xml',
};

describe('probes.js: remaining probe ids (hit / no hit)', () => {
  let hit, miss;
  const probeCtx = (handler) => {
    const fetch = async (u) => {
      const [status, body, headers] = handler(new URL(u).pathname);
      return { ...res(status, { 'content-type': 'text/plain', ...headers }, body), finalUrl: u };
    };
    return fakeCtx({ verified: true, fetch });
  };
  before(async () => {
    [hit, miss] = await Promise.all([
      runProbes(probeCtx((p) => (HIT_BODY[p] ? [200, HIT_BODY[p]] : [404, '']))).then(by),
      // nothing exists; /admin is behind auth (403 -> "protected")
      runProbes(probeCtx((p) => (p === '/admin' ? [403, ''] : [404, '']))).then(by),
    ]);
  });

  for (const [key, path] of Object.entries(PROBE_ID)) {
    const id = `exp-probe-${key}`;
    test(`${id} (${path})`, () => {
      const isInfo = key === 'swagger' || key === 'openapi';
      assert.equal(hit[id].status, isInfo ? 'info' : 'fail', 'signature hit');
      assert.match(hit[id].evidence, /^HTTP 200, signature '/);
      assert.equal(miss[id].status, 'pass', 'no hit');
    });
  }
  test('exp-probe-admin: 403 reads as protected; 200 without password form is ignored', async () => {
    assert.equal(miss['exp-probe-admin'].evidence, 'protected');
  });
});
