// Regression tests for the review round: heuristics that gave false greens/reds, module disagreements,
// probe pacing, and check ids that had no test yet. Hand-made ctx only (no sockets) except where noted.
process.env.HEADERSCAN_ALLOW_PRIVATE = '1';
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { scan } from '../lib/scan.js';
import { run as cspRun } from '../lib/checks/csp.js';
import { run as htmlRun } from '../lib/checks/html.js';
import { run as siteRun } from '../lib/checks/site.js';
import { run as headersRun } from '../lib/checks/headers.js';
import { run as dnsRun } from '../lib/checks/dns.js';
import { run as tlsRun } from '../lib/checks/tls.js';
import { fakeCtx, stubResolve } from './fixture-server.js';

const st = (fs, id) => fs.find((f) => f.id === id);
const status = async (run, ctx, id) => st(await run(ctx), id).status;
const html = (body, extra = {}) => fakeCtx({ body, ...extra });
const H = (body, id, extra) => status(htmlRun, html(body, extra), id);
const res = (o) => ({ status: 200, headers: {}, body: '', redirects: [], truncated: false, timingMs: 1, ...o });

describe('csp.js ignores comments and inline script text (mixed content, SRI)', () => {
  const body = `<!-- <script src="http://old.example.net/x.js"></script> -->
    <script>var t='<iframe src="http://x.example/f"></iframe>'; var u='<img src="http://x.example/i.png">';</script>
    <style>/* <link rel="stylesheet" href="http://x.example/s.css"> */</style>`;
  test('commented-out and string-embedded tags are not findings', async () => {
    const out = await cspRun(fakeCtx({ url: 'https://example.test/', body }));
    for (const id of ['mixed-active', 'mixed-passive', 'sri-external']) assert.equal(st(out, id).status, 'pass', id);
  });
  test('a real http:// script still fails and a real cross-origin script still warns', async () => {
    const out = await cspRun(fakeCtx({ url: 'https://example.test/', body: `${body}<script src="http://old.example.net/x.js"></script>` }));
    assert.equal(st(out, 'mixed-active').status, 'fail');
    assert.equal(st(out, 'sri-external').status, 'warn');
  });
});

describe('headers.js / tls.js judge HTTPS by where the page ended up', () => {
  test('typed http:// that redirects to https with HSTS: no "no HTTPS" failure', async () => {
    const ctx = fakeCtx({ url: 'http://example.test/', headers: { 'strict-transport-security': 'max-age=63072000; includeSubDomains; preload' } });
    ctx.page.finalUrl = 'https://example.test/';
    const out = await headersRun(ctx);
    assert.equal(st(out, 'hdr-hsts').status, 'pass');
    assert.equal(st(out, 'hdr-hsts-subdomains').status, 'pass');
    assert.equal(st(out, 'hdr-hsts-preload').status, 'pass');
  });
  test('typed https:// that ends on http:// is still "no HTTPS"', async () => {
    const ctx = fakeCtx({ url: 'https://example.test/' });
    ctx.page.finalUrl = 'http://example.test/';
    assert.equal(await status(headersRun, ctx, 'hdr-hsts'), 'fail');
  });
  test('tls: http redirect findings (fake port-80 responses)', async () => {
    const at = (r) => fakeCtx({ url: 'https://example.test/', fetch: async () => res(r) });
    let f = await tlsRun(at({ status: 301, headers: { location: 'https://example.test/' } }));
    assert.equal(st(f, 'tls-http-redirect').status, 'pass');
    assert.equal(st(f, 'tls-redirect-permanent').status, 'pass');
    f = await tlsRun(at({ status: 302, headers: { location: 'https://example.test/' } }));
    assert.equal(st(f, 'tls-redirect-permanent').status, 'info');
    f = await tlsRun(at({ status: 200 }));
    assert.equal(st(f, 'tls-http-redirect').status, 'fail');
    assert.equal(st(f, 'tls-redirect-permanent').status, 'skipped');
  });
});

describe('dns.js climbs to parent domains and skips IP literals', () => {
  const ctxFor = (url, records, extra = {}) => fakeCtx({ url, resolve: stubResolve({ txt: async (n) => records[n] || [], ...extra }) });
  test('www host inherits CAA, SPF, MX and DMARC of the apex', async () => {
    const out = await dnsRun(ctxFor('https://www.example.test/',
      { 'example.test': ['v=spf1 -all'], '_dmarc.example.test': ['v=DMARC1; p=reject; rua=mailto:d@example.test'] },
      { caa: async (n) => (n === 'example.test' ? [{ critical: 0, tag: 'issue', value: 'letsencrypt.org' }] : []),
        mx: async (n) => (n === 'example.test' ? [{ exchange: 'mx.example.test', priority: 10 }] : []) }));
    for (const id of ['dns-caa', 'mail-mx', 'mail-spf-present', 'mail-spf-all', 'mail-dmarc-present', 'mail-dmarc-policy']) assert.equal(st(out, id).status, 'pass', id);
    assert.match(st(out, 'dns-caa').evidence, /at example\.test/);
  });
  test('multi-label public suffix (co.uk) still finds the org domain record', async () => {
    const out = await dnsRun(ctxFor('https://www.shop.example.co.uk/', { 'example.co.uk': ['v=spf1 -all'] }));
    assert.equal(st(out, 'mail-spf-present').status, 'pass');
  });
  test('no records anywhere still warns', async () => {
    assert.equal(await status(dnsRun, ctxFor('https://www.example.test/', {}), 'mail-spf-present'), 'warn');
  });
  test('IP literal: every DNS/mail check is skipped', async () => {
    for (const url of ['http://127.0.0.1:8080/', 'http://[::1]:8080/']) {
      const out = await dnsRun(ctxFor(url, {}));
      assert.ok(out.length > 0 && out.every((f) => f.status === 'skipped'), url);
    }
  });
});

describe('html.js heuristics', () => {
  test('ux-response-time: "2024 Home" is not a 24h promise; "24h" and "24 hours" are', async () => {
    assert.equal(await H('<p>Copyright 2024 Home. 2024 highlights.</p>', 'ux-response-time'), 'info');
    assert.equal(await H('<p>We answer in 24h.</p>', 'ux-response-time'), 'pass');
    assert.equal(await H('<p>We reply within 2 hours.</p>', 'ux-response-time'), 'pass');
  });
  test('ux-analytics: real script or call only', async () => {
    assert.equal(await H('<script>/* plausible */ var fathom = 1; // umami</script>', 'ux-analytics'), 'info');
    assert.equal(await H('<p>we do not use plausible</p>', 'ux-analytics'), 'info');
    assert.equal(await H('<script async src="https://plausible.io/js/script.js"></script>', 'ux-analytics'), 'pass');
    assert.equal(await H('<script>window.dataLayer=[];gtag("js",1);</script>', 'ux-analytics'), 'pass');
  });
  test('ux-faq: needs an FAQ heading (or details / FAQPage), not just any question marks', async () => {
    assert.equal(await H('<a href=/faq>FAQ</a><p>Why? How? When? Where? Who?</p>', 'ux-faq'), 'info');
    const qs = ['A?', 'B?', 'C?', 'D?', 'E?'].map((q) => `<h3>${q}</h3>`).join('');
    assert.equal(await H(`<h2>FAQ</h2>${qs}`, 'ux-faq'), 'pass');
    assert.equal(await H(`<h2>Contact</h2>${qs}`, 'ux-faq'), 'info');
    assert.equal(await H('<details><summary>a</summary></details>'.repeat(5), 'ux-faq'), 'pass');
    assert.equal(await H('<h2>FAQ</h2><h3>Only one?</h3>', 'ux-faq'), 'warn');
  });
  test('ux-privacy-policy: "Cookies and cream" is not a policy link', async () => {
    assert.equal(await H('<a href=/shop>Cookies and cream flavours</a>', 'ux-privacy-policy'), 'warn');
    const fetch = async () => res({ body: 'We respect your privacy.' });
    assert.equal(await H('<a href=/privacy>Privacy policy</a>', 'ux-privacy-policy', { fetch }), 'pass');
    assert.equal(await H('<a href=/cookie-policy>Read more</a>', 'ux-privacy-policy', { fetch }), 'pass');
    assert.equal(await H('<a href=/privacy>Privacy</a>', 'ux-privacy-policy', { fetch: async () => res({ status: 404 }) }), 'warn');
    assert.equal(await H('<form></form>', 'ux-privacy-policy'), 'fail');
  });
  test('ux-reviews: a widget or markup, not the word in prose', async () => {
    assert.equal(await H('<p>See us on trustpilot!</p>', 'ux-reviews'), 'info');
    assert.equal(await H('<script src="https://widget.trustpilot.com/bootstrap/v5/tp.widget.bootstrap.min.js"></script>', 'ux-reviews'), 'pass');
    assert.equal(await H('<script type="application/ld+json">{"@type":"Thing","aggregateRating":{"ratingValue":5}}</script>', 'ux-reviews'), 'pass');
  });
  test('ux-local-schema: empty values do not count', async () => {
    const ld = (o) => `<script type="application/ld+json">${JSON.stringify({ '@type': 'LocalBusiness', ...o })}</script>`;
    assert.equal(await H(ld({ address: '', telephone: '', openingHours: '' }), 'ux-local-schema'), 'warn');
    assert.equal(await H(ld({ address: { '@type': 'PostalAddress', streetAddress: ' ' }, telephone: '1', openingHours: 'Mo-Fr 9-17' }), 'ux-local-schema'), 'warn');
    assert.equal(await H(ld({ address: { '@type': 'PostalAddress', streetAddress: 'Main 1' }, telephone: '+1 555', openingHoursSpecification: [{ dayOfWeek: 'Monday' }] }), 'ux-local-schema'), 'pass');
    assert.equal(await H('<p>none</p>', 'ux-local-schema'), 'info');
  });
  test('ux-cta-above-fold: word boundary ("Getaway" is not "Get")', async () => {
    assert.equal(await H('<body><a href=/x>Getaway budget</a></body>', 'ux-cta-above-fold'), 'warn');
    assert.equal(await H('<body><a href=/x>Get a quote</a></body>', 'ux-cta-above-fold'), 'pass');
    assert.equal(await H('<body><a href="tel:+3725551234">Ring</a></body>', 'ux-cta-above-fold'), 'pass');
  });
  test('ux-breadcrumbs, ux-case-studies, ux-maps, ux-team-photo', async () => {
    assert.equal(await H('<nav aria-label="Breadcrumb"></nav>', 'ux-breadcrumbs'), 'pass');
    assert.equal(await H('<p>x</p>', 'ux-breadcrumbs'), 'info');
    assert.equal(await H('<a href="/portfolio">Work</a>', 'ux-case-studies'), 'pass');
    assert.equal(await H('<p>x</p>', 'ux-case-studies'), 'info');
    assert.equal(await H('<iframe src="https://www.google.com/maps/embed?pb=1"></iframe>', 'ux-maps'), 'pass');
    assert.equal(await H('<p>x</p>', 'ux-maps'), 'info');
    const team = st(await htmlRun(html('<img src="/team.jpg" alt="Our team">')), 'ux-team-photo');
    assert.match(team.evidence, /team-like image found/);
    assert.match(st(await htmlRun(html('<p>x</p>')), 'ux-team-photo').evidence, /no team-like/);
  });
});

// A fake site for site.js: routes maps "METHOD path" or "path" to a response (or function of the request options).
const site = (routes) => async (u, o = {}) => {
  const p = new URL(u).pathname;
  const r = routes[`${o.method || 'GET'} ${p}`] ?? routes[p];
  return r === undefined ? res({ status: 404 }) : res(typeof r === 'function' ? r(o) : r);
};
const PAGE = '<html><head><title>T</title></head><body><script src="/big.js"></script></body></html>';
const JS_TAIL = '\n//# sourceMappingURL=big.js.map\n';
const bigJs = (kb) => 'x'.repeat(kb * 1024 - JS_TAIL.length) + JS_TAIL;
const siteCtx = (routes) => fakeCtx({ body: PAGE, fetch: site({ '/big.js.map': { body: '{}', headers: { 'content-type': 'application/json' } }, ...routes }) });

describe('site.js bundles and source maps', () => {
  test('400 KB bundle with no Content-Length (Range ignored): map found, real size reported', async () => {
    const out = await siteRun(siteCtx({ '/big.js': { body: bigJs(400) }, 'HEAD /big.js': { headers: {} } }));
    assert.equal(st(out, 'exp-source-maps').status, 'warn');
    assert.match(st(out, 'ux-js-bundle-size').evidence, /400 KB/);
    assert.equal(st(out, 'ux-js-bundle-size').status, 'warn'); // one script over 300 KB
  });
  test('server honours Range: tail is enough, total size comes from Content-Range', async () => {
    const tail = bigJs(400).slice(-2048);
    const out = await siteRun(siteCtx({ '/big.js': { status: 206, body: tail, headers: { 'content-range': `bytes 0-2047/${400 * 1024}`, 'content-length': '2048' } } }));
    assert.equal(st(out, 'exp-source-maps').status, 'warn');
    assert.match(st(out, 'ux-js-bundle-size').evidence, /400 KB/);
  });
  test('over 1 MiB and Range ignored: tail unseen -> info, never a false pass; size is a lower bound', async () => {
    const out = await siteRun(siteCtx({ '/big.js': { body: 'x'.repeat(1048576), truncated: true } }));
    assert.equal(st(out, 'exp-source-maps').status, 'info');
    assert.match(st(out, 'ux-js-bundle-size').evidence, />= 1024 KB/);
  });
  test('small bundle without a map passes; 200 with a map that 404s passes', async () => {
    const out = await siteRun(fakeCtx({ body: PAGE, fetch: site({ '/big.js': { body: `console.log(1);${JS_TAIL}`, headers: { 'content-length': '40' } } }) }));
    assert.equal(st(out, 'exp-source-maps').status, 'pass');
    assert.equal(st(out, 'ux-js-bundle-size').status, 'pass');
  });
  test('a script that only exists inside an HTML comment is not fetched', async () => {
    const seen = [];
    const ctx = fakeCtx({ body: '<!-- <script src="/old.js"></script> -->', fetch: async (u, o) => { seen.push(new URL(u).pathname); return site({})(u, o); } });
    await siteRun(ctx);
    assert.ok(!seen.includes('/old.js'));
  });
});

describe('site.js other rules', () => {
  test('ux-favicon: apple-touch-icon alone is not a favicon; "shortcut icon" is', async () => {
    const f = (body) => siteRun(fakeCtx({ body, fetch: site({}) })).then((o) => st(o, 'ux-favicon').status);
    assert.equal(await f('<link rel="apple-touch-icon" href="/a.png">'), 'warn');
    assert.equal(await f('<link rel="shortcut icon" href="/f.ico">'), 'pass');
    assert.equal(await f('<link href="/f.svg" rel=icon>'), 'pass');
    assert.equal(await f('<!-- <link rel="icon" href="/f.ico"> -->'), 'warn');
  });
  test('seo-robots-sensitive', async () => {
    const r = (txt) => siteRun(fakeCtx({ body: '<p>x</p>', fetch: site({ '/robots.txt': { body: txt, headers: { 'content-type': 'text/plain' } } }) })).then((o) => st(o, 'seo-robots-sensitive').status);
    assert.equal(await r('User-agent: *\nDisallow: /admin/\n'), 'info');
    assert.equal(await r('User-agent: *\nDisallow: /tmp/\n'), 'pass');
  });
  test('ux-thank-you', async () => {
    const f = (body, routes = {}) => siteRun(fakeCtx({ body, fetch: site(routes) })).then((o) => st(o, 'ux-thank-you').status);
    const ty = { '/thank-you': { body: '<html><title>Thanks</title><p>Thank you for your message</p></html>', headers: { 'content-type': 'text/html' } } };
    assert.equal(await f('<p>home</p>', ty), 'pass');
    assert.equal(await f('<form></form>'), 'warn');
    assert.equal(await f('<p>home</p>'), 'info');
  });
});

describe('headers.js cache-control and compression', () => {
  const ctx = (headers, fetch) => fakeCtx({ url: 'https://example.test/', headers: { 'content-type': 'text/html', ...headers }, body: 'x'.repeat(4000), fetch });
  test('hdr-cache-control-html', async () => {
    assert.equal(await status(headersRun, ctx({ 'cache-control': 'no-cache' }), 'hdr-cache-control-html'), 'pass');
    assert.equal(await status(headersRun, ctx({}), 'hdr-cache-control-html'), 'warn');
    assert.equal(await status(headersRun, ctx({ 'set-cookie': ['a=1'], 'cache-control': 'public' }), 'hdr-cache-control-html'), 'warn');
    assert.equal(await status(headersRun, ctx({ 'content-type': 'application/json' }), 'hdr-cache-control-html'), 'skipped');
  });
  test('hdr-compression', async () => {
    assert.equal(await status(headersRun, ctx({}, async () => res({ headers: { 'content-encoding': 'br' } })), 'hdr-compression'), 'pass');
    assert.equal(await status(headersRun, ctx({}, async () => res({})), 'hdr-compression'), 'warn');
  });
});

// Deep scan against a fake site that "exposes" every probed file. One run (probes are paced at 500 ms each):
// checks every probe signature AND that no passive request is made once probing has started.
describe('deep scan: probe signatures and pacing', () => {
  const HITS = {
    '/.git/HEAD': ['exp-probe-git-head', 'ref: refs/heads/main'], '/.git/config': ['exp-probe-git-config', '[core]'],
    '/.env': ['exp-probe-env', 'APP_KEY=x'], '/.svn/wc.db': ['exp-probe-svn', 'SQLite format 3\0'],
    '/.hg/requires': ['exp-probe-hg', 'revlogv1\nstore'], '/.DS_Store': ['exp-probe-ds-store', '\0\0\0\u0001Bud1'],
    '/backup.zip': ['exp-probe-backup-zip', 'PK\x03\x04zz', 206], '/backup.sql': ['exp-probe-backup-sql', 'CREATE TABLE t'],
    '/backup.tar.gz': ['exp-probe-backup-tgz', '\x1f\x8bzz', 206], '/db.sql': ['exp-probe-db-sql', 'INSERT INTO t'],
    '/wp-config.php.bak': ['exp-probe-wp-config-bak', "<?php define('DB_PASSWORD','x');"], '/phpinfo.php': ['exp-probe-phpinfo', 'phpinfo()'],
    '/server-status': ['exp-probe-server-status', 'Apache Server Status'], '/actuator/env': ['exp-probe-actuator-env', '{"propertySources":[]}'],
    '/actuator': ['exp-probe-actuator', '{"_links":{}}'], '/admin': ['exp-probe-admin', '<input type="password">'],
    '/phpmyadmin/': ['exp-probe-phpmyadmin', 'phpMyAdmin'], '/debug': ['exp-probe-debug', 'Traceback (most recent call last)'],
    '/swagger.json': ['exp-probe-swagger', '{"swagger":"2.0"}'], '/openapi.json': ['exp-probe-openapi', '{"openapi":"3.0.0"}'],
    '/package.json': ['exp-probe-package-json', '{"dependencies":{}}'], '/.vercel/project.json': ['exp-probe-vercel', '{"projectId":"p"}'],
    '/WEB-INF/web.xml': ['exp-probe-web-inf', '<web-app>'], '/uploads/': ['exp-probe-dir-listing', 'Index of /uploads'],
  };
  test('every signature hits; passive traffic stops before the first probe request', async () => {
    const log = [];
    const fetch = async (u, o = {}) => {
      const p = new URL(u).pathname;
      log.push(p);
      if (p === '/') return res({ headers: { 'content-type': 'text/html' }, body: '<html><title>Home</title><p>hello</p></html>', finalUrl: u });
      const h = HITS[p];
      return res({ status: h ? h[2] || 200 : 404, body: h ? h[1] : '', finalUrl: u });
    };
    const r = await scan({ url: 'http://example.test/', deep: true, verified: true, allowPrivate: true, resolve: stubResolve(), fetch });
    const f = Object.fromEntries(r.findings.map((x) => [x.id, x]));
    for (const [p, [id]] of Object.entries(HITS)) {
      assert.equal(f[id].status, /swagger|openapi/.test(id) ? 'info' : 'fail', `${id} (${p}): ${f[id].evidence}`);
      assert.match(f[id].evidence, /signature/);
      assert.ok(!/DB_PASSWORD|APP_KEY|refs\/heads|CREATE TABLE/.test(f[id].evidence), id);
    }
    const isProbe = (p) => p in HITS || /-hs-probe$/.test(p);
    const first = log.findIndex((p) => /-hs-probe$/.test(p));
    assert.ok(first > 0, 'baseline probe request happened');
    assert.deepEqual(log.slice(0, first).filter(isProbe), []);
    assert.deepEqual(log.slice(first).filter((p) => !isProbe(p)), [], 'no passive request after probing started');
  });
});
