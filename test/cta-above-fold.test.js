// ux-cta-above-fold: visible-text window, wider word list, content pages and empty shells skipped, shops stay strict.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { run as runHtml, pageType } from '../lib/checks/html.js';
import { fakeCtx } from './fixture-server.js';

const URL0 = 'https://example.test/';
const by = (fs) => Object.fromEntries(fs.map((f) => [f.id, f]));
const ok200 = async (u) => ({ status: 200, headers: {}, body: '<html>privacy</html>', finalUrl: u, timingMs: 1, redirects: [], truncated: false });
const cta = async (body, url = URL0) => by(await runHtml(fakeCtx({ url, body, fetch: ok200 })))['ux-cta-above-fold'];
const LONG = `<p>${'Plain prose that is long enough to keep the page out of the minimal class. '.repeat(4)}</p>`;
const page = (inner, head = '') => `<!doctype html><html lang="en"><head><title>Test page</title>${head}</head><body>${LONG}${inner}</body></html>`;
const ld = (o) => `<script type="application/ld+json">${JSON.stringify(o)}</script>`;
const fx = (n) => readFileSync(new URL(`./fixtures/ux/${n}.html`, import.meta.url), 'utf8');
const status = async (inner, head, url) => (await cta(page(inner, head), url)).status;

describe('word list', () => {
  test('wider English and Estonian CTA words pass', async () => {
    for (const link of ['<a href="/x">Sign up</a>', '<a href="/x">Try it free</a>', '<a href="/pricing"><svg></svg></a>', '<button>Subscribe</button>',
      '<a href="/x">Donate now</a>', '<a href="/x">Download</a>', '<a href="/x">Request a demo</a>', '<a href="/x">Küsi pakkumist</a>',
      '<a href="/x">Broneeri aeg</a>', '<a href="/x">Tellimus</a>', '<a href="/x">Kontaktid</a>', '<a href="/x">Helista meile</a>',
      '<a href="/x">Osta kohe</a>', '<a href="mailto:hi@example.test">Write</a>', '<a href="/shop">Shop All</a>']) {
      assert.equal(await status(link), 'pass', link);
    }
  });
  test('navigation words and look-alikes stay warn', async () => {
    for (const link of ['<a href="/login">Log in</a>', '<a href="/about">Learn more</a>', '<a href="/x">Read more</a>', '<a href="/x">Getaway budget</a>',
      '<a href="/x">Workshop</a>', '<a href="/x">Ostukorv</a>', '<a href="/industrial">Industry</a>', '<a href="https://facebook.example/x">Facebook</a>']) {
      assert.equal(await status(link), 'warn', link);
    }
  });
});

describe('window: first 2000 characters of visible text', () => {
  test('100 kB of svg and script markup before the hero does not push the CTA out', async () => {
    const noise = `<svg><path d="${'M0 0L1 1'.repeat(8000)}"></path></svg><script>${'var a=1;'.repeat(6000)}</script>`;
    assert.equal((await cta(`<!doctype html><html><head><title>T</title></head><body>${noise}<h1>Acme</h1><a href="/x">Get started</a>${LONG}</body></html>`)).status, 'pass');
  });
  test('1500 visible characters before the CTA pass, 2500 warn', async () => {
    const at = (n) => `<!doctype html><html><head><title>T</title></head><body><p>${'x'.repeat(n)}</p><a href="/x">Contact</a></body></html>`;
    assert.equal((await cta(at(1500))).status, 'pass');
    assert.equal((await cta(at(2500))).status, 'warn');
  });
  test('evidence names the window', async () => {
    assert.equal((await cta(page('<a href="/x">Contact</a>'))).evidence, 'CTA-like link/button in the first 2000 characters of visible text (heuristic)');
    assert.equal((await cta(page('<a href="/x">About</a>'))).evidence, 'no CTA-like link/button in the first 2000 characters of visible text (heuristic)');
  });
  test('a marketing page with a long nav: CTA found; with every CTA word removed: warn (still strict)', async () => {
    const nav = Array.from({ length: 40 }, (_, i) => `<a href="/p${i}"><svg><path d="${'M0 0'.repeat(200)}"></path></svg>Item ${i}</a>`).join('');
    const hero = '<h1>One workspace</h1><a href="/signup">Get Notion free</a><a href="/sales">Request a demo</a>';
    assert.equal((await cta(page(nav + hero))).status, 'pass');
    assert.equal((await cta(page(nav + '<h1>One workspace</h1><a href="/zzz">Zzz Notion</a>'))).status, 'warn');
  });
});

describe('content pages are skipped', () => {
  const skip = async (inner, head = '', url = URL0) => {
    const f = await cta(page(inner, head), url);
    assert.equal(f.status, 'skipped', `${inner} ${head} ${url}: ${f.evidence}`);
    assert.match(f.evidence, /^content page \(.+\): a sales call to action is not expected$/);
    return f.evidence;
  };
  test('JSON-LD article types, og:type article, generator', async () => {
    for (const t of ['Article', 'NewsArticle', 'BlogPosting', 'TechArticle']) await skip('', ld({ '@type': t, headline: 'x' }));
    assert.equal(await skip('', '<meta property="og:type" content="article">'), 'content page (og:type article): a sales call to action is not expected');
    assert.match(await skip('', '<meta name="generator" content="MediaWiki 1.43.0">'), /generator MediaWiki/);
  });
  test('URL path segment and host label', async () => {
    for (const u of ['https://example.test/docs/intro', 'https://example.test/en-US/docs/x', 'https://example.test/blog/hello', 'https://docs.example.test/', 'https://forum.example.test/t/1']) {
      await skip('', '', u);
    }
  });
  test('pagination links and a feed of 5 <article> elements', async () => {
    await skip('<a rel="next" href="/page/2">More</a>');
    await skip('', '<link rel="next" href="/page/2">');
    await skip('<article>a</article>'.repeat(5));
  });
  test('a comment form on a blog post does not make it strict', async () => {
    const form = '<form action="/comment" method="post"><textarea name="c"></textarea><input type="email" name="e"><button>Post comment</button></form>';
    await skip(form, ld({ '@type': 'BlogPosting', headline: 'x' }));
    assert.equal(await status(form), 'warn');
  });
});

describe('not content signals: stays strict', () => {
  test('WebSite/Organization JSON-LD, og:type website, WordPress, 3 articles, docs-like slug, blog fixture', async () => {
    assert.equal(await status('', ld({ '@type': 'WebSite', potentialAction: { '@type': 'SearchAction' } })), 'warn');
    assert.equal(await status('', ld({ '@type': 'Organization', name: 'x' })), 'warn');
    assert.equal(await status('', '<meta property="og:type" content="website">'), 'warn');
    assert.equal(await status('', '<meta name="generator" content="WordPress 6.6">'), 'warn');
    assert.equal(await status('<article>a</article>'.repeat(3)), 'warn');
    assert.equal(await status('', '', 'https://example.test/products/docs-for-x'), 'warn');
    assert.equal(await status('', '', 'https://example.test/'), 'warn'); // two-label host is not a "docs." / "blog." subdomain
    assert.equal((await cta(fx('blog'))).status, 'warn');
    assert.equal(pageType(fx('blog'), URL0).contentSignal, '');
  });
  test('a shop is never a content page', async () => {
    assert.equal(await status('<a href="/cart">Cart</a>', ld({ '@type': 'Article', headline: 'x' })), 'warn');
    assert.equal(await status('', ld({ '@type': 'Product', name: 'x' }) + '<meta property="og:type" content="article">'), 'warn');
    assert.equal(await status('<p>Add to cart</p><a rel="next" href="/p2">Next</a>'), 'warn');
  });
  test('fixtures: leadgen passes, search-site and shop warn', async () => {
    assert.equal((await cta(fx('leadgen'))).status, 'pass');
    assert.equal((await cta(fx('search-site'))).status, 'warn');
    assert.equal((await cta(fx('shop'))).status, 'warn');
  });
});

describe('empty client-rendered shells are skipped', () => {
  test('every recognised root', async () => {
    for (const root of ['<div id="root"></div>', '<app-root></app-root>', '<div id="__nuxt"></div>', '<div id="___gatsby"></div>', '<div id="svelte"></div>', '<div id="app"></div>']) {
      const f = await cta(`<!doctype html><html><head><title>T</title></head><body>${root}<script src="/main.js"></script></body></html>`);
      assert.deepEqual([f.status, f.evidence], ['skipped', 'empty client-rendered shell: no content in the raw HTML to judge (see seo-spa-shell)'], root);
    }
  });
});

describe('hostile input stays linear', () => {
  const MiB = 1048576;
  for (const [name, body] of [['<a href=x> x 110000', '<a href=x>'.repeat(110000)], ['<a>t</a> x 70000', '<a>t</a>'.repeat(70000)],
    ['<p><a>q</a></p> x 40000', '<p><a>q</a></p>'.repeat(40000)], ['1 MiB of <button>', '<button>'.repeat(MiB / 8)]]) {
    test(name, async () => {
      const t0 = performance.now();
      await cta(`<html><body><p>${'word '.repeat(60)}</p>${body}</body></html>`);
      assert.ok(performance.now() - t0 < 3000, `${Math.round(performance.now() - t0)} ms`);
    });
  }
  test('pageType never throws and memoises contentSignal', () => {
    for (const v of [null, '', 'x'.repeat(2e6)]) assert.equal(typeof pageType(v, URL0).contentSignal, 'string');
    const b = page('', '<meta property="og:type" content="article">');
    assert.equal(pageType(b, URL0), pageType(b, URL0));
    assert.equal(pageType(b, URL0).contentSignal, 'og:type article');
  });
});
