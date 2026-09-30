import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { IDS, run } from '../lib/checks/html.js';
import { fakeCtx } from './fixture-server.js';

const by = (fs) => Object.fromEntries(fs.map((f) => [f.id, f.status]));
const desc = 'A well behaved test page description that is long enough to satisfy the seventy character minimum.';
const GOOD = `<!doctype html><html lang="en"><head><title>A good page title</title>
<meta name="description" content="${desc}"><meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="canonical" href="https://example.test/"><meta property="og:image" content="https://example.test/og.png">
<meta property="og:title" content="t"><meta property="og:description" content="d"><meta name="twitter:card" content="summary">
<meta name="theme-color" content="#fff"><link rel="icon" href="/f.ico">
<script type="application/ld+json">{"@type":"Organization","name":"X"}</script></head>
<body><h1>Hello</h1><h2>Sub</h2><img src="a.png" alt="a"><a href="/a">a</a><a href="/b">b</a><a href="/c">c</a>
<a href="/contact">Contact us</a></body></html>`;
// privacy page fetch: 200 non-empty
const fetch200 = async (u) => ({ status: 200, headers: {}, body: '<html>privacy</html>', finalUrl: u, timingMs: 1, redirects: [], truncated: false });

describe('html.js', () => {
  test('IDS: 31 unique, all present, none extra', async () => {
    assert.equal(IDS.length, 31);
    assert.equal(new Set(IDS).size, 31);
    for (const body of ['', GOOD, '<html><body><div id="root"></div></body></html>']) {
      const out = await run(fakeCtx({ body, fetch: fetch200 }));
      assert.deepEqual([...out.map((f) => f.id)].sort(), [...IDS].sort());
    }
  });
  test('empty page: basics fail', async () => {
    const s = by(await run(fakeCtx({ body: '<html><body></body></html>', fetch: fetch200 })));
    for (const id of ['seo-title', 'seo-meta-description', 'seo-h1', 'seo-lang', 'seo-viewport', 'seo-og-image']) assert.equal(s[id], 'fail', id);
    assert.equal(s['seo-title-length'], 'skipped');
    assert.equal(s['seo-meta-desc-length'], 'skipped');
  });
  test('good page passes the core checks', async () => {
    const s = by(await run(fakeCtx({ body: GOOD, fetch: fetch200 })));
    for (const id of ['seo-title', 'seo-title-length', 'seo-meta-description', 'seo-meta-desc-length', 'seo-canonical', 'seo-h1', 'seo-heading-order', 'seo-lang', 'seo-viewport', 'seo-og-image', 'seo-og-basic', 'seo-twitter-card', 'seo-structured-data', 'seo-noindex', 'ux-internal-links', 'ux-theme-color']) assert.equal(s[id], 'pass', id);
    assert.equal(s['ux-alt-text'], 'pass');
  });
  test('two H1, skipped heading level, image without alt', async () => {
    const s = by(await run(fakeCtx({ body: '<html lang="en"><body><h1>a</h1><h1>b</h1><h4>x</h4><img src="a.png"></body></html>', fetch: fetch200 })));
    assert.equal(s['seo-h1'], 'warn');
    assert.equal(s['seo-heading-order'], 'warn');
    assert.equal(s['ux-alt-text'], 'fail');
  });
  test('alt="" counts as decorative; no images -> info', async () => {
    assert.equal(by(await run(fakeCtx({ body: '<img src="a.png" alt="">', fetch: fetch200 })))['ux-alt-text'], 'pass');
    assert.equal(by(await run(fakeCtx({ body: '<p>x</p>', fetch: fetch200 })))['ux-alt-text'], 'info');
  });
  test('noindex via meta and via X-Robots-Tag', async () => {
    assert.equal(by(await run(fakeCtx({ body: '<meta name="robots" content="noindex,follow">', fetch: fetch200 })))['seo-noindex'], 'fail');
    assert.equal(by(await run(fakeCtx({ body: '<p>x</p>', headers: { 'x-robots-tag': 'noindex' }, fetch: fetch200 })))['seo-noindex'], 'fail');
  });
  test('invalid JSON-LD fails', async () => {
    const s = by(await run(fakeCtx({ body: '<script type="application/ld+json">{oops</script>', fetch: fetch200 })));
    assert.equal(s['seo-structured-data'], 'fail');
  });
  test('SPA shell is detected', async () => {
    const s = by(await run(fakeCtx({ body: '<html><body><div id="root"></div><script src="/a.js"></script></body></html>', fetch: fetch200 })));
    assert.equal(s['seo-spa-shell'], 'fail');
    assert.equal(s['seo-h1'], 'fail');
    assert.equal(s['ux-internal-links'], 'fail');
  });
  test('headless-only checks are skipped', async () => {
    const s = by(await run(fakeCtx({ body: GOOD, fetch: fetch200 })));
    assert.equal(s['ux-console-errors'], 'skipped');
    assert.equal(s['ux-sticky-mobile-cta'], 'skipped');
  });
  test('failed page fetch -> module still returns every ID', async () => {
    const out = await run(fakeCtx({ status: 0 }));
    assert.equal(out.length, IDS.length);
  });
  test('checklist numbers are within 1..40', async () => {
    for (const f of await run(fakeCtx({ body: GOOD, fetch: fetch200 }))) if (f.checklist !== undefined) assert.ok(f.checklist >= 1 && f.checklist <= 40, f.id);
  });
});
