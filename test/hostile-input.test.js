// Review fixes: (1) hostile page/404 bodies must not stall the event loop (every HTML/regex scan is linear),
// (2) false verdicts of the page-type, privacy, duplicate-title, robots and thank-you rules.
// Time budgets are ~20x the measured time and orders of magnitude below the old quadratic behaviour (minutes for 1 MiB).
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { run as runHtml, pageType } from '../lib/checks/html.js';
import { run as runSite } from '../lib/checks/site.js';
import { run as runCsp, stripInert, bypassHits } from '../lib/checks/csp.js';
import { run as runHeaders } from '../lib/checks/headers.js';
import { isVerified } from '../lib/verify.js';
import { safeFetch } from '../lib/ssrf.js';
import net from 'node:net';
import v8 from 'node:v8';
import vm from 'node:vm';
import { fakeCtx } from './fixture-server.js';

v8.setFlagsFromString('--expose-gc');
const gc = vm.runInNewContext('gc');
const heapMB = () => { gc(); gc(); return process.memoryUsage().heapUsed / 1048576; };

const URL0 = 'https://example.test/';
const by = (fs) => Object.fromEntries(fs.map((f) => [f.id, f]));
const res = (status, body, headers = {}, u = URL0) => ({ status, headers: { 'content-type': 'text/html', ...headers }, body, finalUrl: u, timingMs: 1, redirects: [], truncated: false });
const ok200 = async (u) => res(200, '<html>privacy</html>', {}, u);
const htmlRun = async (body, o = {}) => by(await runHtml(fakeCtx({ url: URL0, body, fetch: ok200, ...o })));
const short = (inner, head = '') => `<!doctype html><html lang="en"><head><title>T</title>${head}</head><body>${inner}</body></html>`;

describe('hostile bodies stay fast', () => {
  const SIZE = 256 * 1024;
  const UNITS = ['<a "', '<a href="', '<!--', '<script>', '<script src="', '<style>', '<title', '<meta', '<link', '<<', '<a <a ', '</a "', '<form>', '<noscript>',
    '<!x ', '<?x ', '<a href=x>', '</script ', '<script>/*', '<meta name="description" content="', '<label for=x>', '<p><a href=/x>t</a>'];
  for (const unit of UNITS) {
    test(`256 KiB of ${JSON.stringify(unit)}: html, site, csp and headers modules finish`, async () => {
      const body = unit.repeat(Math.ceil(SIZE / unit.length)).slice(0, SIZE);
      const fetch = async (u) => res(200, body, {}, String(u));
      for (const m of [runHtml, runSite, runCsp, runHeaders]) {
        const t0 = performance.now();
        await m(fakeCtx({ url: URL0, body, fetch }));
        assert.ok(performance.now() - t0 < 3000, `${m.name} took ${Math.round(performance.now() - t0)} ms`);
      }
    });
  }
  test('robots.txt and security.txt line scans are linear (long blank and space runs)', async () => {
    for (const body of ['\n'.repeat(SIZE), ' \n'.repeat(SIZE / 2), `User-agent:${' '.repeat(SIZE)}x`, `Expires:${' '.repeat(SIZE)}x`]) {
      const fetch = async (u) => res(200, body, { 'content-type': 'text/plain' }, String(u));
      const t0 = performance.now();
      await runSite(fakeCtx({ url: URL0, body: short('<p>hi</p>'), fetch }));
      assert.ok(performance.now() - t0 < 3000, `${Math.round(performance.now() - t0)} ms`);
    }
  });
  test('a 404 body of "at ( " cannot stall the stack-frame test; real frames are still found', async () => {
    const nfBody = 'at ( '.repeat(SIZE / 5);
    const mk = (nf) => async (u) => (/-nf$/.test(new URL(u).pathname) ? res(404, nf) : res(404, ''));
    const t0 = performance.now();
    const f = by(await runSite(fakeCtx({ url: URL0, body: short('<p>hi</p>'), fetch: mk(nfBody) })));
    assert.ok(performance.now() - t0 < 3000, `${Math.round(performance.now() - t0)} ms`);
    assert.equal(f['exp-error-leak'].status, 'pass');
    const leak = by(await runSite(fakeCtx({ url: URL0, body: short('<p>hi</p>'), fetch: mk('Error: boom\n    at Object.<anonymous> (/srv/app/server.js:10:5)\n') })));
    assert.equal(leak['exp-error-leak'].status, 'fail');
    assert.match(leak['exp-error-leak'].evidence, /stack frame/);
  });
  test('a script body of "/*" repeated is scanned once; analytics after a closed comment is still found', async () => {
    const t0 = performance.now();
    const f = await htmlRun(short(`<script>${'/*'.repeat(SIZE / 2)}</script>`));
    assert.ok(performance.now() - t0 < 3000);
    assert.equal(pageType(short('<script>/* note */ gtag("config","G-ABCDEF1")</script>'), URL0).hasTracker, true);
    assert.equal(pageType(short('<script>// gtag("config","G-ABCDEF1")\n</script>'), URL0).hasTracker, false);
    assert.ok(f['seo-title']);
  });
  test('page parse is shared: a second pageType call on the same body returns the cached result', () => {
    const b = short('<h1>x</h1>');
    assert.equal(pageType(b, URL0), pageType(b, URL0));
  });
  test('tokenizer keeps real content after unclosed tricks', async () => {
    const f = await htmlRun(`<!doctype html><html lang="en"><head><title>Kept</title></head><body><!-- never closed <h1>One</h1><a "x <a href="/a">A</a></body></html>`);
    assert.equal(f['seo-title'].status, 'pass'); // the title token still parsed
  });
  test('stripInert: unclosed openers are left alone, later closed ones still work', () => {
    assert.equal(stripInert('<script>a<!-- x --> b'), '<script>a b');
    assert.equal(stripInert('<!-- open <script>x</script> <style>y</style>'), '<!-- open <script></script> <style></style>');
    assert.equal(stripInert('<p>a</p><SCRIPT type=x>code</SCRIPT ><!-- c -->'), '<p>a</p><SCRIPT type=x></SCRIPT>');
  });
});

describe('minimal pages: shells, sales pages and data collectors keep the strict rules', () => {
  const LINK_RULES = ['ux-internal-links', 'ux-cta-above-fold', 'ux-faq'];
  const strict = async (inner, head) => {
    const f = await htmlRun(short(inner, head));
    for (const id of LINK_RULES) assert.notEqual(f[id].status, 'skipped', id);
    return f;
  };
  test('client-app roots other than #root are shells (never skipped)', async () => {
    for (const root of ['<app-root></app-root>', '<div id="__nuxt"></div>', '<div id="___gatsby"></div>', '<div id="svelte"></div>', '<div id="app"></div>']) {
      const body = short(`${root}<script src="/main.js"></script>`);
      assert.equal(pageType(body, URL0).isAppShell, true, root);
      assert.equal(pageType(body, URL0).isMinimal, false, root);
      assert.equal((await strict(`${root}<script src="/main.js"></script>`))['ux-internal-links'].status, 'fail', root);
    }
  });
  test('a generic #main div plus a first-party bundle is not minimal', async () => {
    const inner = '<div id="main"></div><script src="/bundle.js"></script>';
    assert.equal(pageType(short(inner), URL0).isMinimal, false);
    assert.equal((await strict(inner))['ux-internal-links'].status, 'fail');
    // an analytics script alone does not make a placeholder page an app
    assert.equal(pageType(short('<p>Coming soon</p><script src="https://www.googletagmanager.com/gtm.js?id=GTM-ABC123"></script>'), URL0).isMinimal, true);
  });
  test('one small first-party script on a text-only placeholder (example.com since 2026-10) stays minimal; with a link or a second script it does not', async () => {
    const text = '<p>This domain is for use in documentation examples without needing permission. This is not a service.</p>';
    assert.equal(pageType(short(text + '<script src=/s.js></script>'), URL0).isMinimal, true);
    assert.equal((await htmlRun(short(text + '<script src=/s.js></script>')))['ux-internal-links'].status, 'skipped');
    assert.equal(pageType(short(text + '<a href="https://www.iana.org/">More</a><script src=/s.js></script>'), URL0).isMinimal, false);
    assert.equal(pageType(short(text + '<script src=/s.js></script><script src=/t.js></script>'), URL0).isMinimal, false);
    assert.equal(pageType(short('<p>Loading</p><script src=/s.js></script>'), URL0).isMinimal, false); // too little text: app shell
  });
  test('a root div with 200-249 characters of text is neither an empty shell nor minimal', async () => {
    const inner = `<div id="root"><p>${'a'.repeat(220)}</p></div>`;
    const t = pageType(short(inner), URL0);
    assert.equal(t.isAppShell, false);
    assert.equal(t.isMinimal, false);
    assert.equal((await strict(inner))['ux-internal-links'].status, 'fail');
  });
  test('a short landing page with a sign-up, booking or phone call to action is not minimal', async () => {
    for (const cta of ['<a href="https://booksy.com/x">Book now</a>', '<a href="https://app.acme.io/signup">Start free trial</a>', '<a href="tel:0000">Call us</a>']) {
      const body = short(`<h1>Acme</h1><p>We fix things.</p>${cta}`);
      assert.equal(pageType(body, URL0).isMinimal, false, cta);
      const f = await htmlRun(body);
      assert.equal(f['ux-cta-above-fold'].status, 'pass', cta); // the CTA exists: it must be judged, not skipped
      assert.equal(f['ux-internal-links'].status, 'fail', cta);
    }
  });
  test('iframe embeds and fields outside a <form> (or inside <noscript>) are data collection', async () => {
    for (const inner of ['<iframe src="https://acme.us1.list-manage.com/subscribe"></iframe>', '<iframe src="https://form.typeform.com/to/x"></iframe>',
      '<input type="email" placeholder="Your email"><button>Notify me</button>', '<noscript><form action="/x"><input name="email"></form></noscript>']) {
      assert.equal(pageType(short(inner), URL0).isMinimal, false, inner);
      assert.equal((await htmlRun(short(`<p>Coming soon</p>${inner}`)))['ux-privacy-policy'].status, 'warn', inner);
    }
  });
  test('commerce on a short page: "add to cart" text and Product JSON-LD are not minimal', () => {
    assert.equal(pageType(short('<p>Add to cart</p>'), URL0).isMinimal, false);
    assert.equal(pageType(short('<script type="application/ld+json">{"@type":"Product","name":"x"}</script><p>Mug</p>'), URL0).isMinimal, false);
    assert.equal(pageType(short('<p>Mug</p>'), URL0).isMinimal, true);
  });
  test('the text limit is 250 characters (249 minimal, 250 not) and doctype/xml declarations do not count', () => {
    const t = (n, pre = '') => pageType(`${pre}<html><body><p>${'a'.repeat(n)}</p></body></html>`, URL0).isMinimal;
    assert.equal(t(249), true);
    assert.equal(t(250), false);
    assert.equal(t(236, '<!doctype html>'), true); // 15 doctype characters used to push this over the limit
    assert.equal(t(249, '<?xml version="1.0" encoding="UTF-8"?>'), true);
    assert.equal(t(249, '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">'), true);
  });
  test('the empty-shell limit is 200 characters regardless of a doctype', () => {
    const t = (n) => pageType(`<!doctype html><html><body><div id="root"></div><p>${'a'.repeat(n)}</p></body></html>`, URL0).isAppShell;
    assert.equal(t(199), true);
    assert.equal(t(200), false);
  });
});

describe('search boxes are not lead forms', () => {
  const LONG = `<p>${'Plain prose that is long enough to keep the page out of the minimal class. '.repeat(4)}</p>`;
  const cls = (form) => pageType(short(LONG + form), URL0);
  test('free-text hints on a search field do not make it personal', () => {
    for (const form of [
      '<form role="search" action="/search"><input type="search" name="q" placeholder="Search by name"></form>',
      '<form role="search" action="/search"><input type="text" name="q" placeholder="Search questions and answers"></form>',
      '<form action="/search"><input type="search" name="q" aria-label="Search by address"></form>',
      '<form action="/search"><label for="s">Search by phone model</label><input type="search" id="s" name="q"></form>',
    ]) {
      const t = cls(form);
      assert.equal(t.hasLeadForm, false, form);
      assert.equal(t.onlySearchForms, true, form);
    }
  });
  test('a real contact field keeps the form a lead form, also inside a search-looking form', () => {
    assert.equal(cls('<form><input type="text" name="x" placeholder="Your name"></form>').hasLeadForm, true);
    assert.equal(cls('<form role="search" action="/s"><input type="email" name="q"></form>').hasLeadForm, true);
    assert.equal(cls('<form role="search" action="/s"><input name="email"></form>').hasLeadForm, true);
  });
});

describe('privacy policy link', () => {
  const LEAD = '<form action="/send" method="post"><input type="email" name="e"><button>Send</button></form>';
  const LONGP = `<p>${'Plain prose that is long enough to keep the page out of the minimal class. '.repeat(4)}</p>`;
  const withLinks = async (links) => {
    const asked = [];
    const fetch = async (u) => { asked.push(new URL(u).pathname); return res(200, '<html>policy</html>', {}, u); };
    const f = await htmlRun(short(LONGP + LEAD + links), { fetch });
    return { f: f['ux-privacy-policy'], asked };
  };
  test('a blog slug and a sentence that merely contain "privacy" are not the policy', async () => {
    // known limit: a short link text that names the topic ("Your privacy matters") still counts
    for (const link of ['<a href="/blog/privacy-friendly-analytics">Read our blog</a>', '<a href="/about">Your privacy matters to us, read more</a>']) {
      const { f, asked } = await withLinks(link);
      assert.equal(f.status, 'fail', link);
      assert.deepEqual(asked, [], link);
    }
  });
  test('real policy links still count: short text, short path, other languages, file extension', async () => {
    for (const [link, path] of [['<a href="/legal/privacy-policy/">Policy</a>', '/legal/privacy-policy/'], ['<a href="/x">Privacy policy</a>', '/x'],
      ['<a href="/privaatsus.html">Reeglid</a>', '/privaatsus.html'], ['<a href="/y">Privacy &amp; Cookies</a>', '/y'], ['<a href="/datenschutz">Impressum</a>', '/datenschutz']]) {
      const { f, asked } = await withLinks(link);
      assert.equal(f.status, 'pass', link);
      assert.deepEqual(asked, [path], link);
    }
  });
  test('a whitespace-prefixed javascript: or # anchor is not preferred over a real link', async () => {
    const { f, asked } = await withLinks('<a href=" javascript:void(0)">Privacy settings</a><a href=" #privacy">Privacy</a><a href="/privacy">Privacy policy</a>');
    assert.equal(f.status, 'pass');
    assert.deepEqual(asked, ['/privacy']);
    // an anchor starting with the letter s is not a non-policy scheme (the old pattern read "s*" literally)
    const s = await withLinks('<a href="sjavascript:x">Privacy</a>');
    assert.equal(s.f.status, 'warn');
    assert.match(s.f.evidence, /not http/);
  });
});

describe('duplicate titles', () => {
  const page = (title, links = '') => `<!doctype html><html><head><title>${title}</title></head><body><p>${title} body</p>${links}</body></html>`;
  const crawl = async (home, routes) => {
    const fetch = async (u) => {
      const x = new URL(u), r = routes[x.pathname + x.search] ?? routes[x.pathname];
      return r ? res(200, r, {}, u) : res(404, /-nf$/.test(x.pathname) ? 'x'.repeat(400) : '', {}, u);
    };
    return by(await runSite(fakeCtx({ url: URL0, body: home, fetch })))['seo-duplicate-titles'];
  };
  test('links to the home page under another URL do not count as duplicates', async () => {
    const home = page('Home', '<a href="/index.html">Home</a><a href="/?lang=en">EN</a><a href="/home">Start</a><a href="/about">About</a><a href="/about/">About 2</a>');
    const f = await crawl(home, { '/index.html': home, '/': home, '/home': home, '/about': page('About'), '/about/': page('About') });
    assert.equal(f.status, 'pass', f.evidence);
    assert.match(f.evidence, /2 pages/);
  });
  test('two genuinely different pages with the same title still fail', async () => {
    const home = page('Home', '<a href="/a">A</a><a href="/b">B</a>');
    const f = await crawl(home, { '/a': page('Same'), '/b': page('Same') });
    assert.equal(f.status, 'fail');
  });
});

describe('robots.txt validity', () => {
  const robots = async (body, ct = 'text/plain') => {
    const fetch = async (u) => (new URL(u).pathname === '/robots.txt' ? res(200, body, { 'content-type': ct }, u) : res(404, '', {}, u));
    return by(await runSite(fakeCtx({ url: URL0, body: short('<p>hi</p>'), fetch })));
  };
  test('an empty file, or one with only Sitemap/Allow/Disallow lines, is valid', async () => {
    for (const body of ['', '\n\n', 'Sitemap: https://example.test/sitemap.xml\n', 'Disallow: /private\n', 'Allow: /\n']) {
      const f = await robots(body);
      assert.equal(f['seo-robots-txt'].status, 'pass', JSON.stringify(body));
      assert.equal(f['ai-robots-blocks-all'].status, 'pass');
    }
  });
  test('HTML and plain garbage still fail', async () => {
    assert.equal((await robots('<html><body>hi</body></html>', 'text/html'))['seo-robots-txt'].status, 'fail');
    assert.equal((await robots('hello world, not a robots file'))['seo-robots-txt'].status, 'fail');
  });
});

describe('thank-you shell comparison', () => {
  test('a /thank-you that serves the raw home page is a shell even when the home page has comments and inline scripts up front', async () => {
    const home = '<!-- build 123 --><script>window.x=1</script><!doctype html><html><head><title>Home</title></head><body><p>hello</p><form action="/send" method="post"><input name="email"></form></body></html>';
    const fetch = async (u) => {
      const p = new URL(u).pathname;
      if (['/thank-you', '/thanks', '/aitah', '/tanks'].includes(p)) return res(200, home, {}, u);
      return res(404, /-nf$/.test(p) ? 'Not here, sorry. '.repeat(30) : '', {}, u);
    };
    const f = by(await runSite(fakeCtx({ url: URL0, body: home, fetch })));
    assert.equal(f['ux-thank-you'].status, 'warn');
  });
});

describe('review round 3: hostile input', () => {
  const MiB = 1048576;
  test('a JSON-LD @type object with a non-callable toString does not turn every HTML finding into skipped', async () => {
    const body = '<html><body><script type="application/ld+json">{"@type":{"toString":1}}</script><p>Some text about us.</p>'
      + '<img src=a.png><form action=/c method=post><input name=email></form></body></html>';
    const f = await htmlRun(body);
    assert.equal(f['seo-title'].status, 'fail');
    assert.equal(f['seo-h1'].status, 'fail');
    assert.equal(f['seo-structured-data'].status, 'warn'); // a non-string @type is no type
    assert.equal(pageType(body, URL0).hasLeadForm, true);
    assert.ok(Object.values(f).filter((x) => x.status === 'skipped').length < 10);
    // string types in arrays still count, other values are ignored
    assert.match((await htmlRun(short('<script type="application/ld+json">{"@type":["Organization",5,{"a":1}]}</script>')))['seo-structured-data'].evidence, /^types: Organization$/);
  });
  test('a 1 MiB page of "<p>" does not keep hundreds of thousands of tag objects alive', () => {
    const body = ('<a href=/privacy>Privacy</a>' + '<p>'.repeat(MiB / 3)).slice(0, MiB - 8) + Math.random().toString(36).slice(2, 8);
    const before = heapMB();
    const t = pageType(body, URL0); // the parse stays in the module cache
    const grown = heapMB() - before;
    assert.equal(t.internalLinks, 1);
    assert.ok(grown < 15, `${grown.toFixed(1)} MB retained`); // was ~43 MB
  });
  test('link text, labels and headings drop comments, script bodies and quoted ">" like the page parse', async () => {
    const LONGP = `<p>${'Plain prose that is long enough to keep the page out of the minimal class. '.repeat(4)}</p>`;
    const cta = await htmlRun(short(`<a href="/services">Services<!-- <span class="pill">Get a quote</span> --></a><h1>X</h1>${LONGP}<a href="/about">About</a>`));
    assert.equal(cta['ux-cta-above-fold'].status, 'warn');
    const q = ['How long?', 'How much?', 'Where?', 'When?', 'Why?'].map((x) => `<h3>${x}<!-- <span class="new">New</span> --></h3><p>Answer.</p>`).join('');
    assert.equal((await htmlRun(short(`<h2>FAQ</h2>${q}`)))['ux-faq'].status, 'pass');
    for (const inner of ['<img src="i.png" alt="Home > Legal > Data"> Privacy policy', '<script>window.track && track("footer link click")</script>Privacy policy']) {
      const f = await htmlRun(short(`<a href="/en/legal">${inner}</a><h1>X</h1>`));
      assert.equal(f['ux-privacy-policy'].status, 'pass', inner);
    }
  });
  test('generator meta: a long digit run and an unclosed tag full of name=generator stay fast; real tags still warn', async () => {
    for (const body of [`<meta name=generator content="${'1'.repeat(256 * 1024)}">`, '<meta ' + 'name=generator '.repeat(MiB / 15)]) {
      const t0 = performance.now();
      await runHeaders(fakeCtx({ body }));
      assert.ok(performance.now() - t0 < 3000, `${Math.round(performance.now() - t0)} ms`); // was 28 s and 32 s
    }
    const gen = async (body) => by(await runHeaders(fakeCtx({ body })))['hdr-generator-leak'].status;
    assert.equal(await gen('<meta content="Hugo 0.120.4" name=generator>'), 'warn');
    assert.equal(await gen('<meta name="generator" content="WordPress">'), 'pass');
    assert.equal(await gen('<meta name="description" content="v1.2"><meta name="generator" content="Joomla! 4.1">'), 'warn');
  });
  test('bypassHits matches at most 1000 distinct sources, each once', () => {
    const many = Array.from({ length: 1e6 }, (_, i) => `a${i}.example.net`);
    const t0 = performance.now();
    assert.deepEqual(bypassHits([...many, 'unpkg.com']), []);
    assert.ok(performance.now() - t0 < 1000, `${Math.round(performance.now() - t0)} ms`); // was several seconds
    assert.deepEqual(bypassHits(['unpkg.com', 'unpkg.com', 'cdnjs.cloudflare.com']).map((h) => h.source), ['unpkg.com', 'cdnjs.cloudflare.com']);
  });
  test('isVerified skips oversized TXT records before any regex (a 64 KB quote run used to stall ~1.5 s each)', async () => {
    const rec = 'a' + '"'.repeat(65000) + 'a';
    const t0 = performance.now();
    assert.equal(await isVerified('example.com', async () => [rec, rec, rec]), false);
    assert.ok(performance.now() - t0 < 1000, `${Math.round(performance.now() - t0)} ms`);
  });
  test('safeFetch does not keep one buffer per HTTP chunk (1-byte chunks used to cost ~200 bytes of heap per byte)', async () => {
    const N = 256 * 1024;
    let release, flushed;
    const sent = new Promise((r) => { flushed = r; });
    const srv = net.createServer((s) => {
      s.on('error', () => {});
      s.write('HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ntransfer-encoding: chunked\r\n\r\n' + '1\r\nx\r\n'.repeat(N), () => flushed());
      release = () => s.end('0\r\n\r\n');
    });
    await new Promise((r) => srv.listen(0, '127.0.0.1', r));
    try {
      const before = heapMB();
      const p = safeFetch(`http://127.0.0.1:${srv.address().port}/`, { allowPrivate: true, maxBytes: MiB });
      await sent;
      await new Promise((r) => setTimeout(r, 1000)); // let the client read what is buffered
      const grown = heapMB() - before;
      release();
      const r = await p;
      assert.equal(r.body.length, N);
      assert.ok(grown < 15, `${grown.toFixed(1)} MB retained mid-body`); // was ~60 MB for 256 KiB
    } finally { srv.close(); }
  });
});
