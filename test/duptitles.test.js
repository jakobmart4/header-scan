// seo-duplicate-titles counts only DIFFERENT pages: the home page under another URL (identical or near-identical body),
// pages sharing a same-origin canonical, and pages sharing a final URL after redirects are one page. Real duplicates still fail.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { run } from '../lib/checks/site.js';
import { fakeCtx } from './fixture-server.js';

const URL0 = 'https://example.test/';
const res = (status, body, u, final = u) => ({ status, headers: { 'content-type': 'text/html' }, body, finalUrl: final, timingMs: 1, redirects: [], truncated: false });
const doc = (t, { head = '', text = `${t} body`, links = '' } = {}) => `<!doctype html><html><head><title>${t}</title>${head}</head><body><p>${text}</p>${links}</body></html>`;
const canon = (href) => `<link rel="canonical" href="${href}">`;
const a = (...ps) => ps.map((p) => `<a href="${p}">${p}</a>`).join('');
// routes: path -> body, or { body, final } to simulate a redirect (finalUrl)
const crawl = async (home, routes) => {
  const fetch = async (u) => {
    const x = new URL(u), r = routes[x.pathname + x.search] ?? routes[x.pathname];
    if (!r) return res(404, /-nf$/.test(x.pathname) ? 'x'.repeat(400) : '', u);
    return typeof r === 'string' ? res(200, r, u) : res(200, r.body, u, r.final);
  };
  const fs = await run(fakeCtx({ url: URL0, body: home, fetch }));
  return fs.find((f) => f.id === 'seo-duplicate-titles');
};
const expect = (f, status, re) => { assert.equal(f.status, status, f.evidence); assert.match(f.evidence, re); };
const ONE = /^only 1 page\(s\) found to compare$/;

// HN-like front page: 30 stories, two distinct words per headline; points, ages and comment counts change per request.
const L = 'abcdefghijklmnopqrstuvwxyz';
const word = (i) => 'w' + L[i % 26] + L[Math.floor(i / 26)];
const hn = (seed, swap = -1, extra = '') => doc('Hacker News', {
  text: 'Hacker News new | past | comments | ask | show | jobs | submit',
  links: a('/news', '/newest') + extra + Array.from({ length: 30 }, (_, i) => {
    const h = i === swap ? 'Totally replaced headline' : `${word(2 * i)} ${word(2 * i + 1)}`;
    return `<tr><td>${i + 1}.</td><td><a href="/item?id=${4000 + i}">${h}</a> ${(i * 7 + seed) % 500} points by user${i} ${(i + seed) % 23} hours ago | ${(i * 3 + seed) % 90} comments</td></tr>`;
  }).join(''),
});

describe('seo-duplicate-titles: aliases count as one page', () => {
  test('1. HN-like: / and /news (same words, different counters, no canonical) are one page', async () => {
    expect(await crawl(hn(1), { '/news': hn(37) }), 'info', ONE);
  });
  test('2. HN-like: one story swapped between the two fetches is still the same page', async () => {
    expect(await crawl(hn(1), { '/news': hn(37, 5) }), 'info', ONE);
  });
  test('3. HN-like: /news merged into home, /newest with its own title is a different page', async () => {
    expect(await crawl(hn(1), { '/news': hn(37), '/newest': doc('New Links | Hacker News') }), 'pass', /^2 pages, all unique$/);
  });
  test('4. a page whose canonical is the home page is the home page', async () => {
    expect(await crawl(doc('Home', { links: a('/a') }), { '/a': doc('Home', { text: 'Something else', head: canon('https://example.test/') }) }), 'info', ONE);
  });
  test('5. a page whose canonical is an already crawled page is that page', async () => {
    expect(await crawl(doc('Home', { links: a('/a', '/b') }), { '/a': doc('A page'), '/b': doc('A page', { text: 'b', head: canon('https://example.test/a') }) }), 'pass', /^2 pages, all unique$/);
  });
  test('6. two pages with the same third canonical URL are one page', async () => {
    const r = { '/a': doc('Same', { text: 'a', head: canon('/c') }), '/b': doc('Same', { text: 'b', head: canon('/c') }) };
    expect(await crawl(doc('Home', { links: a('/a', '/b') }), r), 'pass', /^2 pages, all unique$/);
  });
  test('7. a link redirected to the home page is the home page, even with a different body', async () => {
    expect(await crawl(doc('Home', { links: a('/old') }), { '/old': { body: doc('Home', { text: 'nonce 77 other' }), final: URL0 } }), 'info', ONE);
  });
  test('8. two links with the same final URL count once', async () => {
    const r = { '/x': { body: doc('A', { text: 'x' }), final: 'https://example.test/a' }, '/a': doc('A') };
    expect(await crawl(doc('Home', { links: a('/x', '/a') }), r), 'pass', /^2 pages, all unique$/);
  });
  test('9. a link redirected to another origin is not a page of this site', async () => {
    const r = { '/out': { body: doc('Home', { text: 'elsewhere' }), final: 'https://evil.test/' }, '/a': doc('A') };
    expect(await crawl(doc('Home', { links: a('/out', '/a') }), r), 'pass', /^2 pages, all unique$/);
  });
  test('13. canonical = home merges even a page with another title (intended)', async () => {
    expect(await crawl(doc('Home', { links: a('/a') }), { '/a': doc('About us', { head: canon('https://example.test/') }) }), 'info', ONE);
  });
  test('15. a relative trailing-slash canonical is normalised like the path key', async () => {
    expect(await crawl(doc('Home', { links: a('/a', '/b/') }), { '/a': doc('X'), '/b/': doc('X', { text: 'b', head: canon('/a/') }) }), 'pass', /^2 pages, all unique$/);
  });
  test('18. the home page identity is its own canonical', async () => {
    expect(await crawl(doc('Home', { head: canon('/news'), links: a('/news') }), { '/news': doc('Home', { text: 'Other words entirely here' }) }), 'info', ONE);
  });
  test('21. index.html (identical body) and /about vs /about/ stay merged', async () => {
    const home = doc('Home', { links: a('/index.html', '/?lang=en', '/home', '/about', '/about/') });
    expect(await crawl(home, { '/index.html': home, '/': home, '/home': home, '/about': doc('About'), '/about/': doc('About') }), 'pass', /^2 pages, all unique$/);
  });
  test('22. rel and its value are matched case-insensitively', async () => {
    expect(await crawl(doc('Home', { links: a('/a', '/b') }), { '/a': doc('S'), '/b': doc('S', { text: 'b', head: '<link REL="Canonical" href="/a">' }) }), 'pass', /^2 pages, all unique$/);
  });
});

describe('seo-duplicate-titles: real duplicates still count', () => {
  const home = doc('Home', { links: a('/a', '/b') });
  const DUP3 = /^1 duplicated title\(s\) across 3 pages$/;
  test('10/20. two different pages with the same title fail', async () => {
    expect(await crawl(home, { '/a': doc('Same', { text: 'apples' }), '/b': doc('Same', { text: 'oranges' }) }), 'fail', DUP3);
    expect(await crawl(home, { '/a': doc('Dup', { text: 'one thing' }), '/b': doc('Dup', { text: 'another' }) }), 'fail', DUP3);
  });
  test('11. a cross-origin canonical is ignored', async () => {
    const r = { '/a': doc('Same', { text: 'a', head: canon('https://other.test/p') }), '/b': doc('Same', { text: 'b', head: canon('https://other.test/p') }) };
    expect(await crawl(home, r), 'fail', DUP3);
  });
  test('12. a canonical inside a comment is ignored', async () => {
    expect(await crawl(home, { '/a': doc('Same', { text: 'a', head: '<!-- <link rel=canonical href=/b> -->' }), '/b': doc('Same') }), 'fail', DUP3);
  });
  test('14. the home title on a clearly different page fails', async () => {
    expect(await crawl(doc('Home', { links: a('/a') }), { '/a': doc('Home', { text: 'Totally different content about pricing plans' }) }), 'fail', /^1 duplicated title\(s\) across 2 pages$/);
  });
  test('16/17. an unparseable or href-less canonical is no canonical', async () => {
    expect(await crawl(home, { '/a': doc('Same', { text: 'a', head: canon('http://[bad') }), '/b': doc('Same') }), 'fail', DUP3);
    expect(await crawl(home, { '/a': doc('Same', { text: 'a', head: '<link rel="canonical">' }), '/b': doc('Same') }), 'fail', DUP3);
  });
  test('19. a shared meta description still warns', async () => {
    const d = '<meta name="description" content="Shared">';
    expect(await crawl(doc('Home', { head: d, links: a('/a') }), { '/a': doc('A', { head: d }) }), 'warn', /^1 duplicated meta description\(s\) across 2 pages$/);
  });
  test('23. byte-identical bodies of two other pages are a genuine duplicate', async () => {
    const same = doc('Same');
    expect(await crawl(home, { '/a': same, '/b': same }), 'fail', DUP3);
  });
});

describe('seo-duplicate-titles: hostile candidate bodies stay fast', () => {
  // Same title as home, so canonical and near-identical comparison both run on the 256 KiB body.
  const SIZE = 256 * 1024;
  for (const unit of ['<<', '<link ', '<link rel=canonical ', '<link rel="canonical" href="', '<a href="', '<!--', '<script>', '<title', 'word ', '1 ', '<a>', '</nav>']) {
    test(`256 KiB of ${JSON.stringify(unit)}`, async () => {
      const body = ('<title>Home</title>' + unit.repeat(Math.ceil(SIZE / unit.length))).slice(0, SIZE);
      const t0 = performance.now();
      await crawl(doc('Home', { links: a('/a', '/b') }), { '/a': body, '/b': body });
      assert.ok(performance.now() - t0 < 3000, `${Math.round(performance.now() - t0)} ms`);
    });
  }
});

describe('seo-duplicate-titles: review regressions', () => {
  const DUP3 = /^1 duplicated title\(s\) across 3 pages$/;
  const D = '<meta name="description" content="Shop all">';
  const menu = (wrap) => wrap(Array.from({ length: 300 }, (_, i) => `<li><a href="/c${i}">Category${L[i % 26]}${L[Math.floor(i / 26)]}</a></li>`).join(''));
  test('a shared 300-link menu does not make different pages with a copied head one page', async () => {
    const page = (text, links = '') => doc('Shop', { head: D, text, links: links + menu((x) => `<ul>${x}</ul>`) });
    const r = { '/p1': page('a long product page about blue widgets with a detailed description'), '/p2': page('another product page about red gadgets and their warranty terms') };
    expect(await crawl(page('welcome to the shop and our offers', a('/p1', '/p2')), r), 'fail', DUP3);
  });
  test('a shared plain-text <nav> of 300 words is boilerplate too', async () => {
    const nav = `<nav>${Array.from({ length: 300 }, (_, i) => `menu${L[i % 26]}${L[Math.floor(i / 26)]}`).join(' ')}</nav>`;
    const r = { '/about': doc('Acme', { head: D + nav, text: 'fifteen words that only the about page has: team history mission values office' }) };
    expect(await crawl(doc('Acme', { head: D + nav, text: 'welcome home our widgets are the best widgets anywhere', links: a('/about') }), r), 'fail', /^1 duplicated title\(s\) across 2 pages$/);
  });
  test('link order does not decide: the canonical target itself is kept', async () => {
    const r = { '/a': doc('A', { head: canon('/b') }), '/b': doc('Home', { text: 'bbb different' }) };
    for (const links of [a('/a', '/b'), a('/b', '/a')]) expect(await crawl(doc('Home', { links }), r), 'fail', /^1 duplicated title\(s\) across 2 pages$/);
  });
  test('an alias of a home page over 256 KiB, cut at 256 KiB, is still the home page', async () => {
    const big = doc('Big', { text: Array.from({ length: 60000 }, (_, i) => `w${L[i % 26]}${L[Math.floor(i / 26) % 26]}${L[Math.floor(i / 676) % 26]}`).join(' '), links: a('/index2') });
    const fetch = async (u) => (new URL(u).pathname === '/index2'
      ? { ...res(200, big.slice(0, 262144), u), truncated: true } : res(404, /-nf$/.test(u) ? 'x'.repeat(400) : '', u));
    const f = (await run(fakeCtx({ url: URL0, body: big, fetch }))).find((x) => x.id === 'seo-duplicate-titles');
    expect(f, 'info', ONE);
  });
  test('a canonical href with &amp; is decoded before comparing', async () => {
    const r = { '/x': doc('P'), '/y': doc('P', { text: 'y', head: canon('/x?a=1&amp;b=2') }) };
    const home = doc('Home', { links: '<a href="/x?a=1&b=2">x</a>' + a('/y') });
    const fetch = async (u) => { const x = new URL(u); const b = x.pathname === '/x' ? r['/x'] : x.pathname === '/y' ? r['/y'] : null; return b ? res(200, b, u) : res(404, '', u); };
    const f = (await run(fakeCtx({ url: URL0, body: home, fetch }))).find((x) => x.id === 'seo-duplicate-titles');
    expect(f, 'pass', /^2 pages, all unique$/);
  });
  test('data-rel=canonical or rel=canonical inside another value is not a canonical', async () => {
    const home = doc('Home', { links: a('/a', '/b') });
    expect(await crawl(home, { '/a': doc('S', { text: 'a' }), '/b': doc('S', { text: 'b', head: '<link data-rel="canonical" href="/a">' }) }), 'fail', DUP3);
    expect(await crawl(home, { '/a': doc('S', { text: 'a' }), '/b': doc('S', { text: 'b', head: '<link href="/a?rel=canonical" rel=stylesheet>' }) }), 'fail', DUP3);
  });
});
