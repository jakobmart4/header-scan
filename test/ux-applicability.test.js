// Applicability-aware ux-* rules (docs/specs/UX-SPEC.md): page-type signals, skipped/info for tools, strict for marketing.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { run as runHtml, pageType } from '../lib/checks/html.js';
import { run as runSite } from '../lib/checks/site.js';
import { score } from '../lib/score.js';
import { fakeCtx } from './fixture-server.js';

const fx = (n) => readFileSync(new URL(`./fixtures/ux/${n}.html`, import.meta.url), 'utf8');
const URL0 = 'https://example.test/';
const by = (fs) => Object.fromEntries(fs.map((f) => [f.id, f]));
const ok200 = async (u) => ({ status: 200, headers: {}, body: '<html>privacy</html>', finalUrl: u, timingMs: 1, redirects: [], truncated: false });
const htmlRun = async (body, o = {}) => by(await runHtml(fakeCtx({ url: URL0, body, fetch: ok200, ...o })));

// Site-level run: unknown paths 404 with a tiny body unless `routes`/`nf` say otherwise; records every requested path.
async function site(body, { nf = { status: 404, body: '' }, routes = {}, url = URL0 } = {}) {
  const seen = [];
  const fetch = async (u) => {
    const p = new URL(u).pathname;
    seen.push(p);
    const r = routes[p] ?? (/^\/[0-9a-f]{16}-nf$/.test(p) ? nf : { status: 404 });
    return { status: r.status, headers: { 'content-type': 'text/html', ...r.headers }, body: r.body ?? '', finalUrl: u, timingMs: 1, redirects: [], truncated: false };
  };
  return { f: by(await runSite(fakeCtx({ url, body, fetch }))), seen };
}

const LONG = `<p>${'Plain prose that is long enough to keep the page out of the empty shell class. '.repeat(4)}</p>`;
const page = (inner, head = '') => `<!doctype html><html lang="en"><head><title>Test page</title>${head}</head><body>${LONG}${inner}</body></html>`;
const ld = (o) => `<script type="application/ld+json">${JSON.stringify(o)}</script>`;
const pt = (inner, head) => pageType(page(inner, head), URL0);
const TOOL_LD = ld({ '@context': 'https://schema.org', '@type': 'WebApplication', name: 'T' });
const TOOL_FORM = '<form id="f" novalidate><input type="text" name="url"><button>Go</button></form>';

describe('pageType classifier', () => {
  test('noscript-only form and <form-field> are not forms', () => {
    assert.equal(pt('<noscript><form action="/x"><input type="email" name="e"></form></noscript>').formCount, 0);
    assert.equal(pt('<form-field><input type="text" name="q"></form-field>').formCount, 0);
  });
  test('unknown stays strict: empty forms are lead forms', () => {
    for (const f of ['<form></form>', '<form action="/s"></form>']) {
      const t = pt(f);
      assert.equal(t.formCount, 1, f);
      assert.equal(t.hasLeadForm, true, f);
    }
  });
  test('newsletter, textarea and name-like forms are lead forms; login and button-only forms are not', () => {
    assert.equal(pt('<form><input type="email" name="x"></form>').hasLeadForm, true);
    assert.equal(pt('<form><input type="text" name="u"><input type="password" name="p"></form>').hasLeadForm, false); // auth form
    assert.equal(pt('<form><input type="hidden" name="x" value="1"><input type="submit"></form>').hasLeadForm, false); // collects nothing
    assert.equal(pt('<form><textarea name="q"></textarea></form>').hasLeadForm, true);
    assert.equal(pt('<form><input type="text" name="fullname"></form>').hasLeadForm, true);
  });
  test('a single type=search form is benign', () => {
    const t = pt('<form role="search" action="/search"><input type="search" name="q"></form>');
    assert.deepEqual([t.formCount, t.hasLeadForm], [1, false]);
  });
  test('a benign form next to a lead form does not hide the lead form', () => {
    assert.equal(pt('<form><input type="search" name="q"></form><form action="/c"><input type="email" name="e"></form>').hasLeadForm, true);
  });
  test('WebApplication JSON-LD alone makes a tool', () => {
    const t = pt('', TOOL_LD);
    assert.deepEqual([t.isSinglePageTool, t.hasLeadForm], [true, false]);
  });
  test('one benign JS-only form makes a tool; a form with a real action does not', () => {
    assert.equal(pt(TOOL_FORM).isSinglePageTool, true);
    assert.equal(pt('<form action="/search"><input type="search" name="q"></form>').isSinglePageTool, false);
    assert.equal(pt(TOOL_FORM + TOOL_FORM).isSinglePageTool, false);
  });
  test('tool status needs positive evidence and no other pages, contact or shop signals', () => {
    assert.equal(pt('', TOOL_LD).isSinglePageTool, true);
    assert.equal(pt('<a href="/a">a</a><a href="/b">b</a><a href="/c">c</a>', TOOL_LD).isSinglePageTool, false);
    assert.equal(pt('<a href="mailto:a@example.test">mail</a>', TOOL_LD).isSinglePageTool, false);
    assert.equal(pt('<a href="/cart">cart</a>', TOOL_LD).isSinglePageTool, false);
    assert.equal(pt('', '').isSinglePageTool, false); // brochure: 0 links, no form, no JSON-LD
    assert.equal(pt('<a href="https://www.iana.org/domains/example">More</a>').isSinglePageTool, false); // example.com shape
    assert.equal(pt(TOOL_FORM + '<form action="/c"><input type="email" name="e"></form>', TOOL_LD).isSinglePageTool, false);
    assert.equal(pageType('<html><body><div id="root"></div></body></html>', URL0).isSinglePageTool, false); // empty shell
  });
  test('a tracker does not stop tool status', () => {
    const t = pt('', TOOL_LD + '<script async src="https://static.cloudflareinsights.com/beacon.min.js"></script>');
    assert.deepEqual([t.hasTracker, t.isSinglePageTool], [true, true]);
  });
  test('commerce: Offer alone and a bare /shop link are not commerce; Product, cart, add-to-cart, payment script are', () => {
    assert.equal(pt('', ld({ '@type': 'Offer', price: '0' })).hasCommerce, false);
    assert.equal(pt('<a href="/shop">Shop</a>').hasCommerce, false);
    assert.equal(pt('', ld({ '@type': 'Product', name: 'x' })).hasCommerce, true);
    assert.equal(pt('<a href="/checkout">x</a>').hasCommerce, true);
    assert.equal(pt('<p>Add to cart</p>').hasCommerce, true);
    assert.equal(pt('', '<script src="https://js.stripe.com/v3/"></script>').hasCommerce, true);
  });
  test('trackers: widened src and call lists', () => {
    assert.equal(pt('', '<script src="https://static.hotjar.com/c/hotjar-1.js"></script>').hasTracker, true);
    assert.equal(pt('', '<script>fbq("init","1")</script>').hasTracker, true);
    assert.equal(pt('', '<script>var x = 1; // fbq( in a comment</script>').hasTracker, false);
    assert.equal(pt('<p>we love google-analytics and hotjar</p>').hasTracker, false);
  });
  test('internal links are distinct same-origin paths; contact links are detected', () => {
    const t = pt('<a href="/a">1</a><a href="/a#x">2</a><a href="https://example.test/b">3</a><a href="https://other.test/c">4</a><a href="#top">5</a><a href="tel:1">6</a>');
    assert.equal(t.internalLinks, 2);
    assert.equal(t.hasContactLink, true);
    assert.equal(pt('<a href="/a">1</a>').hasContactLink, false);
  });
  test('never throws and cuts huge input', () => {
    for (const v of ['', null, undefined, '<', '<form', '<noscript><form>', 'x'.repeat(2e6)]) assert.doesNotThrow(() => pageType(v, URL0));
    assert.doesNotThrow(() => pageType('<a href="http://[">x</a>', 'not a url'));
  });
});

// [internal-links, cta, faq, privacy] from html.js; [thank-you, 404] from site.js
const MATRIX = {
  tool: [['skipped', 'skipped', 'skipped', 'info'], ['skipped', 'info']],
  'tool-tracker': [['skipped', 'skipped', 'skipped', 'fail'], ['skipped', 'info']],
  'search-site': [['pass', 'warn', 'info', 'warn'], ['skipped', 'warn']],
  leadgen: [['pass', 'pass', 'warn', 'fail'], ['warn', 'warn']],
  shop: [['pass', 'warn', 'info', 'fail'], ['skipped', 'warn']],
  blog: [['pass', 'warn', 'info', 'warn'], ['info', 'warn']],
  'spa-shell': [['fail', 'warn', 'info', 'warn'], ['info', 'fail']],
};
const HTML_IDS = ['ux-internal-links', 'ux-cta-above-fold', 'ux-faq', 'ux-privacy-policy'];

describe('fixture matrix', () => {
  for (const [name, [h, s]] of Object.entries(MATRIX)) {
    test(name, async () => {
      const body = fx(name);
      const f = await htmlRun(body);
      assert.deepEqual(HTML_IDS.map((id) => f[id].status), h, HTML_IDS.map((id) => `${id}: ${f[id].evidence}`).join(' | '));
      const { f: sf } = await site(body, name === 'spa-shell' ? { nf: { status: 200, body: '<html>app</html>' } } : {});
      assert.deepEqual(['ux-thank-you', 'ux-404-page'].map((id) => sf[id].status), s, `${sf['ux-thank-you'].evidence} | ${sf['ux-404-page'].evidence}`);
    });
  }

  test('fixture page types', () => {
    const t = (n) => pageType(fx(n), URL0);
    assert.deepEqual([t('tool').isSinglePageTool, t('tool').hasLeadForm, t('tool').formCount], [true, false, 1]);
    assert.deepEqual([t('tool-tracker').hasTracker, t('tool-tracker').isSinglePageTool], [true, true]);
    assert.deepEqual([t('search-site').formCount, t('search-site').hasLeadForm, t('search-site').isSinglePageTool], [1, false, false]);
    assert.equal(t('leadgen').hasLeadForm, true);
    assert.deepEqual([t('shop').hasCommerce, t('shop').isSinglePageTool], [true, false]);
    assert.deepEqual([t('blog').formCount, t('blog').isSinglePageTool], [0, false]);
    assert.deepEqual([t('spa-shell').isAppShell, t('spa-shell').isSinglePageTool], [true, false]);
  });

  test('tool: skipped rows explain themselves, nothing is fail/warn', async () => {
    const f = await htmlRun(fx('tool'));
    assert.equal(f['ux-internal-links'].evidence, 'single-page tool: no other pages to link to');
    assert.equal(f['ux-cta-above-fold'].evidence, 'single-page tool: the on-page form is the primary action');
    assert.equal(f['ux-faq'].evidence, 'single-page tool: FAQ content not expected');
    assert.match(f['ux-privacy-policy'].evidence, /single-page tool/);
    for (const id of [...HTML_IDS, 'ux-case-studies']) assert.ok(!['fail', 'warn'].includes(f[id].status), id);
  });

  test('tool: thank-you makes no fetches; 404 is info with an explanation', async () => {
    const { f, seen } = await site(fx('tool'));
    for (const p of ['/thank-you', '/thanks', '/aitah', '/tanks']) assert.ok(!seen.includes(p), p);
    assert.equal(f['ux-thank-you'].evidence, 'no lead or conversion form: only search/tool form(s) on the page');
    assert.equal(f['ux-404-page'].evidence, 'real HTTP 404; a custom 404 page is not needed on a single-page tool');
  });

  test('lead-gen: thank-you probes the 4 paths and keeps the old warning evidence', async () => {
    const { f, seen } = await site(fx('leadgen'));
    for (const p of ['/thank-you', '/thanks', '/aitah', '/tanks']) assert.ok(seen.includes(p), p);
    assert.equal(f['ux-thank-you'].evidence, 'form present but no thank-you page found');
    const found = await site(fx('leadgen'), { routes: { '/thank-you': { status: 200, body: '<html><body>Thanks for your message, we will be in touch soon.</body></html>' } } });
    assert.equal(found.f['ux-thank-you'].status, 'pass');
  });

  test('marketing fixtures keep byte-identical quality scores', async () => {
    const OLD = { leadgen: [['pass', 'pass', 'warn', 'fail']], blog: [['pass', 'warn', 'info', 'warn']], 'spa-shell': [['fail', 'warn', 'info', 'warn']] };
    for (const [name, [old]] of Object.entries(OLD)) {
      const fs = await runHtml(fakeCtx({ url: URL0, body: fx(name), fetch: ok200 }));
      const before = fs.map((x) => (HTML_IDS.includes(x.id) ? { ...x, status: old[HTML_IDS.indexOf(x.id)] } : x));
      assert.deepEqual(score(fs), score(before), name);
    }
  });

  test('search-only pages improve: privacy fail -> warn, thank-you warn -> skipped', async () => {
    const f = await htmlRun(fx('search-site'));
    assert.equal(f['ux-privacy-policy'].status, 'warn');
    assert.equal(f['ux-privacy-policy'].evidence, 'no privacy policy link');
  });
});

describe('per-rule: still flagged', () => {
  test('privacy: leadgen/commerce/tracker/empty form keep their old fail evidence', async () => {
    const old = 'no privacy policy link but page has a form or analytics';
    assert.equal((await htmlRun(fx('leadgen')))['ux-privacy-policy'].evidence, old);
    assert.equal((await htmlRun(fx('tool-tracker')))['ux-privacy-policy'].evidence, old);
    assert.equal((await htmlRun('<html><body><form></form></body></html>'))['ux-privacy-policy'].status, 'fail');
    const shop = (await htmlRun(fx('shop')))['ux-privacy-policy'];
    assert.deepEqual([shop.status, shop.evidence], ['fail', 'no privacy policy link but page has checkout/cart links']);
  });
  test('privacy: a working link still passes on a tool (link branch untouched)', async () => {
    const f = await htmlRun(page('<a href="/privacy">Privacy policy</a>', TOOL_LD));
    assert.equal(f['ux-privacy-policy'].status, 'pass');
  });
  test('internal links: 0 fails, 1-2 warn on a non-tool', async () => {
    assert.equal((await htmlRun(page('<a href="https://other.test/x">x</a>')))['ux-internal-links'].status, 'fail');
    assert.equal((await htmlRun(page('<a href="/a">a</a>')))['ux-internal-links'].status, 'warn');
    assert.equal((await htmlRun(page('<a href="/a">a</a><a href="/b">b</a>', TOOL_LD)))['ux-internal-links'].status, 'warn'); // links: not a tool
  });
  test('internal links: an empty shell is not skipped (seo-spa-shell owns it)', async () => {
    const f = await htmlRun('<html><body><div id="root"></div><script src="/a.js"></script></body></html>');
    assert.equal(f['ux-internal-links'].status, 'fail');
    assert.match(f['ux-internal-links'].evidence, /SPA shell/);
  });
  test('cta: warn without a CTA word, pass with one, strict for a search-form site', async () => {
    assert.equal((await htmlRun(fx('blog')))['ux-cta-above-fold'].status, 'warn');
    assert.equal((await htmlRun(fx('search-site')))['ux-cta-above-fold'].status, 'warn');
    assert.equal((await htmlRun(fx('leadgen')))['ux-cta-above-fold'].status, 'pass');
  });
  test('faq: lone <details> is not an FAQ; 2 warn; 5 pass (also on a tool)', async () => {
    const d = (n) => Array.from({ length: n }, (_, i) => `<details><summary>Q${i}?</summary><p>A</p></details>`).join('');
    assert.equal((await htmlRun(page(d(1))))['ux-faq'].status, 'info');
    assert.equal((await htmlRun(page(d(2))))['ux-faq'].status, 'warn');
    assert.equal((await htmlRun(page(d(5))))['ux-faq'].status, 'pass');
    assert.equal((await htmlRun(page(d(5), TOOL_LD)))['ux-faq'].status, 'pass');
    assert.equal((await htmlRun(page(d(2), TOOL_LD)))['ux-faq'].status, 'skipped');
  });
  test('thank-you: no counted form stays info (noscript-only form, <form-field>)', async () => {
    for (const inner of ['<noscript><form action="/x"><input type="email" name="e"></form></noscript>', '<form-field><input type="text" name="q"></form-field>']) {
      const { f } = await site(page(inner));
      assert.deepEqual([f['ux-thank-you'].status, f['ux-thank-you'].evidence], ['info', 'no thank-you page and no form'], inner);
    }
  });
  test('thank-you: every fetch failing is still skipped with the error', async () => {
    const boom = async () => { throw Object.assign(new Error('x'), { code: 'NETWORK' }); };
    const f = by(await runSite(fakeCtx({ url: URL0, body: fx('leadgen'), fetch: boom })));
    assert.equal(f['ux-thank-you'].status, 'skipped');
    assert.match(f['ux-thank-you'].evidence, /NETWORK/);
  });
});

describe('ux-404-page', () => {
  test('401 is info on a marketing page; 403 stays warn there', async () => {
    const r401 = (await site(fx('leadgen'), { nf: { status: 401, body: 'denied' } })).f['ux-404-page'];
    assert.equal(r401.status, 'info');
    assert.match(r401.evidence, /HTTP 401 .*custom 404 not assessable/);
    const r403 = (await site(fx('leadgen'), { nf: { status: 403, body: 'denied' } })).f['ux-404-page'];
    assert.deepEqual([r403.status, r403.evidence], ['warn', 'random path returns HTTP 403']);
  });
  test('403 is info on a tool and on a Cloudflare bot filter (header or challenge body)', async () => {
    for (const [name, nf] of [['tool', { status: 403, body: 'denied' }], ['leadgen', { status: 403, body: '', headers: { 'cf-mitigated': 'challenge' } }], ['leadgen', { status: 403, body: '<title>Just a moment...</title>' }]]) {
      const r = (await site(fx(name), { nf })).f['ux-404-page'];
      assert.equal(r.status, 'info', name);
      assert.match(r.evidence, /HTTP 403 .*custom 404 not assessable/);
    }
  });
  test('200 is a soft-404 fail on a tool page too', async () => {
    const { f } = await site(fx('tool'), { nf: { status: 200, body: '<html>app</html>' } });
    assert.equal(f['ux-404-page'].status, 'fail');
  });
  test('tiny 404 is warn on leadgen, info on a tool; a real custom 404 passes on both', async () => {
    assert.equal((await site(fx('leadgen'))).f['ux-404-page'].status, 'warn');
    assert.equal((await site(fx('tool'))).f['ux-404-page'].status, 'info');
    const custom = { status: 404, body: `<html><body>${'Sorry, that page does not exist. Try the home page. '.repeat(10)}</body></html>` };
    assert.equal((await site(fx('tool'), { nf: custom })).f['ux-404-page'].status, 'pass');
    assert.equal((await site(fx('leadgen'), { nf: custom })).f['ux-404-page'].status, 'pass');
  });
  test('other statuses stay warn', async () => {
    assert.equal((await site(fx('tool'), { nf: { status: 500, body: '' } })).f['ux-404-page'].status, 'warn');
  });
});

describe('ux-case-studies', () => {
  const cs = async (href) => (await htmlRun(page(`<a href="${href}">x</a>`)))['ux-case-studies'];
  test('external links and slug substrings are info', async () => {
    assert.equal((await cs('https://news.example.org/projects/x')).status, 'info');
    assert.equal((await cs('/eeltood-uute-1')).status, 'info');
  });
  test('whole same-origin path segments pass', async () => {
    assert.equal((await cs('/tood')).status, 'pass');
    assert.equal((await cs('/case-studies/acme')).status, 'pass');
    assert.equal((await cs('https://example.test/portfolio')).status, 'pass');
  });
});

describe('ux-analytics', () => {
  test('cloudflareinsights beacon passes; no tracker is info', async () => {
    assert.equal((await htmlRun(fx('tool-tracker')))['ux-analytics'].status, 'pass');
    assert.equal((await htmlRun(fx('tool')))['ux-analytics'].status, 'info');
  });
});

describe('scanner own page regression', () => {
  test('public/index.html: none of the six rules is fail/warn', async () => {
    const own = 'https://header-scan.jakobmart4.workers.dev/';
    const body = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
    const f = by(await runHtml(body, { url: own }));
    for (const id of HTML_IDS) assert.ok(!['fail', 'warn'].includes(f[id].status), `${id}: ${f[id].status} ${f[id].evidence}`);
    const { f: sf } = await site(body, { url: own });
    for (const id of ['ux-thank-you', 'ux-404-page']) assert.ok(!['fail', 'warn'].includes(sf[id].status), `${id}: ${sf[id].status} ${sf[id].evidence}`);
  });
});

// Reviewer round: tool detection must survive normal tool-page furniture, lead forms must not hide behind unfamiliar field names.
describe('tool detection tolerates furniture', () => {
  const tool = (inner) => pt(inner + TOOL_FORM, TOOL_LD).isSinglePageTool;
  test('home/self links, one docs page and www/apex links do not end tool status; two real pages do', () => {
    assert.equal(tool('<a href="/">Home</a>'), true);
    assert.equal(tool('<a href="/docs">Docs</a>'), true);
    assert.equal(tool('<a href="https://www.example.test/docs">Docs</a>'), true);
    assert.equal(tool('<a href="/about">About</a><a href="/pricing">Pricing</a>'), false);
  });
  test('legal and utility links (privacy, terms, security.txt, robots, llms.txt) are not other pages', () => {
    assert.equal(tool('<a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/.well-known/security.txt">Security</a><a href="/llms.txt">llms</a>'), true);
    assert.equal(pt('<a href="/privacy">Privacy</a><a href="/.well-known/security.txt">Security</a>' + TOOL_FORM, TOOL_LD).internalLinks, 2); // raw count unchanged
  });
  test('www and apex hosts are the same site (one-page business with a form is not a tool)', () => {
    assert.equal(pt('<a href="https://www.example.test/a">1</a>').internalLinks, 1);
    assert.equal(pt('<a href="https://www.example.test/a">1</a><a href="/b">2</a><form action="/c" method="post"><input type="email" name="e"></form>', TOOL_LD).isSinglePageTool, false);
  });
  test('privacy link plus tool form: still a tool, ux rules skipped, privacy passes', async () => {
    const f = await htmlRun(page('<a href="/privacy">Privacy</a>' + TOOL_FORM, TOOL_LD));
    assert.deepEqual(HTML_IDS.map((id) => f[id].status), ['skipped', 'skipped', 'skipped', 'pass']);
  });
  test('a mailto feedback link keeps tool status only with app JSON-LD and a search form', () => {
    assert.equal(tool('<a href="mailto:a@example.test">Feedback</a>'), true);
    assert.equal(pt('<a href="mailto:a@example.test">Feedback</a>', TOOL_LD).isSinglePageTool, false); // no form: contact link wins
    assert.equal(pt('<a href="mailto:a@example.test">Feedback</a>' + TOOL_FORM).isSinglePageTool, false); // no JSON-LD
  });
});

describe('form classes', () => {
  const lead = (inner, head) => pt(inner, head).hasLeadForm;
  test('tool fields named hostname, domain_name, ip_address, hotel or a text box on a WebApplication are not lead forms', () => {
    for (const n of ['hostname', 'domain_name', 'ip_address', 'ip', 'q']) assert.equal(lead(`<form><input type="text" name="${n}"></form>`), false, n);
    assert.equal(lead('<form action="/s"><input type="text" name="hotel"></form>'), false); // "tel" inside "hotel" is not a phone field
    assert.equal(lead('<form><textarea name="a"></textarea><textarea name="b"></textarea></form>', TOOL_LD), false); // diff tool
    assert.equal(lead('<form><textarea name="a"></textarea></form>'), true); // no app evidence: textarea is a lead signal
    assert.equal(lead('<form><textarea name="msg"></textarea><input name="email"></form>', TOOL_LD), true);
  });
  test('button-only and hidden-only forms (logout, consent, toggle) collect nothing', () => {
    for (const f of ['<form method="post" action="/logout"><button>Log out</button></form>', '<form method="POST" action="/run/toggle"><input type="hidden" name="t" value="1"><button>x</button></form>']) {
      const t = pt(f);
      assert.deepEqual([t.formCount, t.hasLeadForm], [1, false], f);
    }
    assert.equal(lead('<form></form>'), true); // truly empty stays strict
  });
  test('unfamiliar names do not make a form benign: placeholder, label, post/contact action and no positive signal', () => {
    for (const f of [
      '<form><input type="text" name="field1" placeholder="Your phone number"></form>',
      '<form><input type="text" name="field2" placeholder="Your question"></form>',
      '<form><input type="text" name="wl" placeholder="you@company.com"><button>Join</button></form>',
      '<form><input type="text" name="subscribe" aria-label="Your email"></form>',
      '<form><label for="x">Telephone</label><input type="text" id="x" name="zz"></form>',
      '<form><input type="text" name="nombre"><input type="text" name="consulta"></form>',
      '<form><input type="text" name="nom"><input type="text" name="mail"></form>',
      '<form action="/contact" method="post"><input type="text" name="q"></form>',
      '<form action="/book"><input type="text" name="q"></form>',
      '<form method="post"><input type="text" name="q"></form>',
      '<form><input type="text" name="zz"></form>', // no positive search/tool signal
      '<form><input type="text" name="q"><select name="service"><option>a</option></select></form>',
    ]) assert.equal(lead(f), true, f);
  });
  test('positive signals still make a benign form: type=search, role=search, GET action, tool name', () => {
    for (const f of ['<form><input type="search" name="zz"></form>', '<form role="search"><input type="text" name="zz"></form>',
      '<form action="/s"><input type="text" name="zz"></form>', '<form><input type="text" name="url"></form>']) assert.equal(lead(f), false, f);
  });
  test('login form: no thank-you probes, privacy only on tracker/commerce; with an email it is still a lead form', async () => {
    const login = page('<form id="f"><input type="text" name="username"><input type="password" name="pw"></form><a href="/a">a</a><a href="/b">b</a><a href="/c">c</a>');
    const { f, seen } = await site(login);
    assert.equal(f['ux-thank-you'].status, 'skipped');
    assert.match(f['ux-thank-you'].evidence, /login/);
    assert.ok(!seen.includes('/thank-you'));
    const h = await htmlRun(login);
    assert.deepEqual([h['ux-privacy-policy'].status, h['ux-privacy-policy'].evidence], ['warn', 'no privacy policy link']);
    assert.equal((await htmlRun(login + '<script src="https://static.hotjar.com/c/hotjar-1.js"></script>'))['ux-privacy-policy'].status, 'fail');
    const signup = page('<form><input type="email" name="e"><input type="password" name="p"></form>');
    assert.equal((await site(signup)).f['ux-thank-you'].status, 'warn');
    assert.equal((await htmlRun(signup))['ux-privacy-policy'].status, 'fail');
  });
});

describe('marketing pages with app JSON-LD stay strict', () => {
  const SAAS_LD = ld({ '@type': 'SoftwareApplication', name: 'Acme' });
  test('SaaS landing page with cross-origin signup links is not a tool; CTA is evaluated', async () => {
    const body = page('<a href="https://app.acme.io/signup">Start free trial</a><a href="https://docs.acme.io">Docs</a>', SAAS_LD);
    assert.equal(pageType(body, URL0).isSinglePageTool, false);
    const f = await htmlRun(body);
    assert.equal(f['ux-cta-above-fold'].status, 'pass');
    assert.equal(f['ux-internal-links'].status, 'fail');
  });
  test('app-store landing page is not a tool', () => {
    assert.equal(pt('<a href="https://apps.apple.com/app/id1">Download on the App Store</a><a href="https://play.google.com/store/apps/details?id=x">Google Play</a>', SAAS_LD).isSinglePageTool, false);
  });
  test('the same JSON-LD with a real tool form and no promo links is a tool', () => {
    assert.equal(pt(TOOL_FORM, SAAS_LD).isSinglePageTool, true);
    assert.equal(pt('<a href="https://github.com/acme/tool">Source</a>', SAAS_LD).isSinglePageTool, true);
  });
});

describe('ux-privacy-policy link detection', () => {
  const labels = ['Datenschutz', 'Datenschutzerklärung', 'Politique de confidentialité', 'Confidentialité', 'Tietosuoja', 'Política de privacidad', 'Integritetspolicy', 'Isikuandmete töötlemise põhimõtted'];
  test('German, French, Finnish, Spanish, Swedish and Estonian labels pass on a lead-gen page', async () => {
    for (const l of labels) {
      const f = await htmlRun(page(`<form action="/c" method="post"><input type="email" name="e"></form><a href="/x">${l}</a>`));
      assert.equal(f['ux-privacy-policy'].status, 'pass', l);
    }
  });
  test('a javascript: anchor does not hide the real policy link; a lone one still warns', async () => {
    const both = await htmlRun(page('<a href="javascript:void(0)" onclick="x()">Privacy settings</a><a href="/privacy-policy-cookie-restriction-mode">Privacy policy</a>'));
    assert.equal(both['ux-privacy-policy'].status, 'pass');
    const lone = await htmlRun(page('<a href="javascript:void(0)">Privacy settings</a>'));
    assert.deepEqual([lone['ux-privacy-policy'].status, lone['ux-privacy-policy'].evidence], ['warn', 'privacy link is not http(s)']);
  });
  test('no policy link on a lead-gen page is still a fail', async () => {
    assert.equal((await htmlRun(fx('leadgen')))['ux-privacy-policy'].status, 'fail');
  });
});

describe('pageType is linear on hostile input', () => {
  const fast = (name, body) => test(name, () => {
    const t0 = performance.now();
    pageType(body, URL0);
    const ms = performance.now() - t0;
    assert.ok(ms < 1000, `${name}: ${Math.round(ms)} ms`);
  });
  fast('200k bare <form>', '<form>'.repeat(200000));
  fast('50k <form><input name=q>', '<form><input name=q>'.repeat(50000));
  fast('closed forms', '<form action="#"><input name=q></form>'.repeat(26000));
  fast('comment then forms', '<!--' + '<form><input>'.repeat(70000));
  fast('noscript forms', '<noscript><form>'.repeat(60000));
  fast('forms with textareas under app JSON-LD', TOOL_LD + '<form><textarea name=a></textarea><label for=a>x</label></form>'.repeat(15000));
  test('html.run and site.run on 1 MiB of <form> finish and classify once', async () => {
    const body = page('<form>'.repeat(150000));
    const t0 = performance.now();
    const f = await htmlRun(body);
    await site(body);
    assert.ok(performance.now() - t0 < 3000);
    assert.equal(f['ux-privacy-policy'].status, 'fail'); // empty forms stay lead forms
  });
});

describe('minimal pages', () => {
  const MIN = '<!doctype html><html lang="en"><head><title>Example Domain</title></head><body><h1>Example Domain</h1><p>This domain is for use in examples.</p><p><a href="https://www.iana.org/domains/example">More information</a></p></body></html>';
  test('a placeholder page skips the business-site rules instead of failing them', async () => {
    assert.equal(pageType(MIN, URL0).isMinimal, true);
    const f = await htmlRun(MIN);
    for (const id of ['ux-internal-links', 'ux-cta-above-fold', 'ux-faq']) assert.equal(f[id].status, 'skipped', id);
    assert.equal(f['ux-privacy-policy'].status, 'info');
  });
  test('minimal needs all of: little text, no other page, no form, no shop', () => {
    assert.equal(pageType(page(''), URL0).isMinimal, false); // long prose
    assert.equal(pageType(MIN.replace('</body>', '<a href="/about">About</a></body>'), URL0).isMinimal, false);
    assert.equal(pageType(MIN.replace('</body>', '<form><input name=email></form></body>'), URL0).isMinimal, false);
    assert.equal(pageType(MIN.replace('</body>', '<a href="/cart">Cart</a></body>'), URL0).isMinimal, false);
  });
  test('other analytics still fail the privacy rule', async () => {
    const f = await htmlRun(page('<a href="/a">A</a>', '<script src="https://www.googletagmanager.com/gtm.js?id=GTM-ABC123"></script>'));
    assert.equal(f['ux-privacy-policy'].status, 'fail');
  });
});
