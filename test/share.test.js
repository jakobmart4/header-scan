// Share links and compare (ui/src/share.js): the report travels in the URL fragment as base64url(deflate-raw(JSON)), nothing is
// stored server-side. share.js is browser code without DOM; it is loaded here in a vm context with the web globals it uses.
process.env.HEADERSCAN_ALLOW_PRIVATE = '1';
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import zlib from 'node:zlib';
import { scan } from '../lib/scan.js';
import { start, stubResolve } from './fixture-server.js';
import { parseTarget } from '../lib/ssrf.js';
import { IDS as PROBE_IDS } from '../lib/checks/probes.js';

const root = new URL('../', import.meta.url);
const read = (p) => readFileSync(new URL(p, root), 'utf8');
const HS = vm.runInNewContext(read('ui/src/share.js') + '\n;HS', { CompressionStream, DecompressionStream, Blob, Response, TextEncoder, TextDecoder, btoa, atob });
const plain = (x) => JSON.parse(JSON.stringify(x)); // vm objects have other-realm prototypes
const sample = (n) => JSON.parse(read(`public/samples/${n}.json`));
const tok = (v) => Buffer.from(zlib.deflateRawSync(typeof v === 'string' ? v : JSON.stringify(v))).toString('base64url');
async function rejects(p, what) {
  await assert.rejects(p, (e) => { assert.match(e.message, /^(bad |duplicate id|too large)/, what); return true; }, what);
}
const mixed = sample('mixed'), perfect = sample('perfect');
const withF = (r, i, patch) => ({ ...r, findings: r.findings.map((f, k) => (k === i ? { ...f, ...patch } : f)) });

describe('share link round trip', () => {
  let srv, live;
  before(async () => { srv = await start({ mode: 'bad' }); live = await scan({ url: srv.url + '/', resolve: stubResolve(), allowPrivate: true }); });
  after(() => srv.close());

  test('a live scan and both samples survive encode -> decode; raw headers, refs and the sample flag are dropped', async () => {
    assert.ok(live.rawHeaders.length, 'the live scan has raw headers');
    live = withF(live, 0, { ref: 'https://example.test/doc' });
    for (const r of [live, mixed, perfect]) {
      const t = await HS.encode(r), back = plain(await HS.decode(t));
      assert.match(t, /^[A-Za-z0-9_-]+$/);
      for (const k of ['url', 'host', 'scannedAt', 'durationMs', 'deep', 'errors']) assert.deepEqual(back[k], r[k], k);
      assert.deepEqual(back.score, r.score);
      assert.deepEqual(back.findings, r.findings.map(({ ref, ...f }) => f));
      assert.deepEqual(back.rawHeaders, []);
      assert.equal(back.shared, true);
      assert.equal(back.verified, false);
      assert.equal(back.sample, undefined);
      assert.ok(back.findings.every((f) => !('ref' in f)));
    }
  });

  test('url limit follows the server: a 2048-character input whose href is percent-encoded up to 9x still shares and compares', async () => {
    for (const ch of ['é', '中', '😀']) {
      const input = 'https://a.example/?q=' + ch.repeat(Math.floor((2048 - 21) / ch.length));
      assert.ok(input.length <= 2048);
      const { url } = parseTarget(input, { allowPrivate: true });
      assert.ok(url.length > 2048, 'the normalised href is longer than the input');
      const r = { ...mixed, url };
      assert.equal(HS.parse(JSON.parse(JSON.stringify(r))).url, url, 'Compare by file');
      assert.equal((await HS.decode(await HS.encode(r))).url, url, 'share link round trip');
    }
  });

  test('size limits: a real-sized report (144 findings at the field caps) shares; 300 at the caps is "too large" for a link but compares from a file', async () => {
    const at = (n) => ({ ...mixed, errors: [], findings: Array.from({ length: n }, (_, i) => ({ id: 'f' + i, category: 'headers', title: ('Title ' + i + ' ').padEnd(200, 'x'), status: 'fail', severity: 5, evidence: ('evidence ' + i + ' ').padEnd(400, 'e'), fix: ('fix ' + i + ' ').padEnd(400, 'f') })) });
    assert.equal((await HS.decode(await HS.encode(at(144)))).findings.length, 144);
    await assert.rejects(HS.encode(at(300)), /^Error: too large$/);
    assert.equal(HS.parse(at(300)).findings.length, 300);
  });

  test('link size: a full report stays under 8000 characters', async () => {
    for (const r of [live, mixed, perfect]) assert.ok((await HS.encode(r)).length < 8000, r.url);
  });
});

describe('share link decode rejects hostile tokens', () => {
  test('token pre-checks run before atob and decompression', async () => {
    for (const t of ['', 'A'.repeat(32769), 'abc$', 'ab=c', 'ab+c', 'abcde', null, 42]) await rejects(HS.decode(t), String(t).slice(0, 10));
  });

  test('a deflate bomb (5 MB of spaces in a ~5 KB token) is cut at the read limit, fast', async () => {
    const t = Buffer.from(zlib.deflateRawSync(Buffer.alloc(5_000_000, 0x20))).toString('base64url');
    assert.ok(t.length < 32768);
    const t0 = performance.now();
    await assert.rejects(HS.decode(t), /too large/);
    assert.ok(performance.now() - t0 < 500, `took ${Math.round(performance.now() - t0)} ms`);
  });

  test('truncated or corrupt deflate, invalid UTF-8 and non-JSON content fail', async () => {
    const good = await HS.encode(mixed);
    const half = good.slice(0, good.length >> 1);
    await assert.rejects(HS.decode(half.length % 4 === 1 ? half.slice(0, -1) : half));
    await assert.rejects(HS.decode('____' + good.slice(4)));
    await assert.rejects(HS.decode(Buffer.from(zlib.deflateRawSync(Buffer.from([0xff, 0xfe, 0x7b]))).toString('base64url')));
    await assert.rejects(HS.decode(tok('not json')));
    await rejects(HS.decode(tok('[1,2]')), 'array');
    await rejects(HS.decode(tok('null')), 'null');
  });

  test('schema: every off-shape field is refused and the message never echoes the input', async () => {
    const bads = [
      withF(mixed, 0, { category: 'x<b>' }), withF(mixed, 0, { status: 'ok' }), withF(mixed, 0, { severity: 6 }), withF(mixed, 0, { severity: 1.5 }),
      withF(mixed, 0, { title: 'x'.repeat(201) }), withF(mixed, 0, { evidence: 'x'.repeat(401) }), withF(mixed, 0, { fix: 'x'.repeat(401) }),
      withF(mixed, 0, { id: mixed.findings[1].id }), withF(mixed, 0, { id: 7 }), withF(mixed, 0, { checklist: '3' }),
      { ...mixed, findings: Array.from({ length: 301 }, (_, i) => ({ ...mixed.findings[0], id: 'x' + i })) },
      { ...mixed, findings: {} }, { ...mixed, url: 'u'.repeat(18433) }, { ...mixed, scannedAt: 5 }, { ...mixed, durationMs: -1 },
      { ...mixed, errors: Array.from({ length: 21 }, () => ({ module: 'm', message: 'e' })) }, { ...mixed, errors: [{ module: 'm' }] },
      { ...mixed, score: { ...mixed.score, security: { score: '5', grade: 'A' } } },
      { ...mixed, score: { ...mixed.score, quality: { score: 50, grade: 'Z' } } },
      { ...mixed, score: { ...mixed.score, categories: { ...mixed.score.categories, tls: { ...mixed.score.categories.tls, fail: -1 } } } },
      { ...mixed, score: null }
    ];
    for (const [i, r] of bads.entries()) {
      await assert.rejects(HS.decode(tok(r)), (e) => !/x<b>|xxxx|uuuu/.test(e.message) && e.message.length < 30, 'case ' + i);
      assert.throws(() => HS.parse(r), undefined, 'parse case ' + i);
    }
  });

  test('hostile text stays text; __proto__ / constructor keys do not touch prototypes; ref links are dropped', async () => {
    const evil = withF(mixed, 0, { id: 'constructor', title: '<img src=x onerror=1>', evidence: '</script><script>alert(1)</script>', ref: 'https://evil.example' });
    const json = JSON.stringify(evil).replace(/^\{/, '{"__proto__":{"polluted":1},');
    const r = await HS.decode(tok(json));
    assert.equal(r.findings[0].title, '<img src=x onerror=1>');
    assert.equal(r.findings[0].evidence, '</script><script>alert(1)</script>');
    assert.equal(r.findings[0].ref, undefined);
    assert.equal(r.polluted, undefined);
    assert.equal(({}).polluted, undefined);
    assert.equal(HS.compare(r, r).same, r.findings.length, '"constructor" is an ordinary id');
  });

  test('encode refuses a report that would not decode again (no broken links are handed out)', async () => {
    await rejects(HS.encode(withF(mixed, 0, { evidence: 'x'.repeat(500) })), 'long evidence');
  });

  test('hostile-input timing: token extraction and decode pre-checks are linear', async () => {
    let t0 = performance.now();
    assert.equal(HS.token('#' + '&r'.repeat(500_000)), '');
    assert.equal(HS.token('x'.repeat(1_000_000)).length, 1_000_000);
    assert.equal(HS.token('https://h/#view=x&r=abcd&sample=y'), 'abcd');
    assert.equal(HS.token('  abcd  '), 'abcd');
    assert.equal(HS.token('#view=details'), '');
    assert.equal(HS.token(''), '');
    await rejects(HS.decode('A'.repeat(1_000_000) + '$'), 'long');
    await rejects(HS.decode('A'.repeat(32767) + '$'), 'charset at the end');
    assert.ok(performance.now() - t0 < 500, `took ${Math.round(performance.now() - t0)} ms`);
    // a 300-finding report at every field limit parses quickly
    const big = { ...mixed, errors: [], findings: Array.from({ length: 300 }, (_, i) => ({ id: 'f' + i, category: 'headers', title: 't'.repeat(200), status: 'fail', severity: 5, evidence: 'e'.repeat(400), fix: 'f'.repeat(400) })) };
    t0 = performance.now();
    assert.equal(HS.parse(big).findings.length, 300);
    assert.ok(performance.now() - t0 < 200);
  });
});

describe('compare', () => {
  const old = HS.parse(mixed);
  const idx = (st) => old.findings.findIndex((f) => f.status === st);
  test('fixed, new problems, changed, unchanged, other and only-in-previous', () => {
    const iFail = idx('fail'), iPass = idx('pass'), iWarn = idx('warn'), iInfo = idx('info');
    let cur = old;
    cur = withF(cur, iFail, { status: 'pass' }); // fixed
    cur = withF(cur, iPass, { status: 'fail' }); // new problem
    cur = withF(cur, iWarn, { status: 'fail' }); // changed
    cur = withF(cur, iInfo, { status: 'skipped' }); // other
    cur = { ...cur, findings: [...cur.findings.filter((_, k) => k !== cur.findings.length - 1), { ...old.findings[0], id: 'brand-new', status: 'warn' }, { ...old.findings[0], id: 'new-pass', status: 'pass' }] };
    const c = HS.compare(old, cur);
    assert.deepEqual(plain(c.fixed.map((r) => [r.f.id, r.from])), [[old.findings[iFail].id, 'fail']]);
    assert.deepEqual(plain(c.added.map((r) => r.f.id)).sort(), [old.findings[iPass].id, 'brand-new'].sort());
    assert.deepEqual(plain(c.changed.map((r) => [r.from, r.f.status])), [['warn', 'fail']]);
    assert.equal(c.other, 2); // info -> skipped, a new passing finding
    assert.equal(c.gone, 1);
    assert.equal(c.same, old.findings.length - 5);
  });

  test('a problem that becomes skipped is not counted as fixed', () => {
    const c = HS.compare(old, withF(old, idx('fail'), { status: 'skipped' }));
    assert.equal(c.fixed.length, 0);
    assert.equal(c.other, 1);
  });

  test('different scan depth: deep-only probe findings are counted apart, not listed as new problems or as gone', () => {
    const probes = PROBE_IDS.map((id) => ({ id, category: 'exposure', title: 'Exposed ' + id, status: 'fail', severity: 5, evidence: '', fix: '' }));
    const deep = { ...old, deep: true, findings: [...old.findings, ...probes, { ...old.findings[0], id: 'brand-new', status: 'warn' }] };
    for (const [a, b] of [[old, deep], [deep, old]]) {
      const c = HS.compare(a, b);
      assert.equal(c.depth, PROBE_IDS.length);
      assert.equal(c.same, old.findings.length);
      assert.deepEqual(plain(c.added.map((r) => r.f.id)), a === old ? ['brand-new'] : []);
      assert.equal(c.gone, a === old ? 0 : 1);
    }
    // Probes score in Security only: its delta is withheld across depths, Quality still compares.
    const scored = (r, sec, q) => ({ ...r, score: { ...r.score, security: { ...r.score.security, score: sec }, quality: { ...r.score.quality, score: q } } });
    assert.deepEqual(plain(HS.compare(scored(old, 44, 60), scored(deep, 70, 65)).delta), { security: null, quality: 5 });
    assert.deepEqual(plain(HS.compare(scored(deep, 44, 60), scored(deep, 70, 65)).delta), { security: 26, quality: 5 });
    assert.deepEqual(plain(HS.compare(scored(old, null, 60), scored(old, 70, 65)).delta), { security: null, quality: 5 });
    assert.equal(HS.compare(deep, deep).depth, 0, 'same depth: probes compare normally');
    assert.equal(HS.compare(deep, deep).same, deep.findings.length);
  });

  test('a full downloaded JSON (raw headers, refs, sample flag) and a share link give the same comparison', async () => {
    const fromFile = HS.parse(JSON.parse(JSON.stringify(mixed, null, 2)));
    const fromLink = await HS.decode(HS.token('https://header-scan.example/#r=' + (await HS.encode(mixed)) + '&view=details'));
    assert.deepEqual(plain(HS.compare(fromFile, perfect)), plain(HS.compare(fromLink, perfect)));
  });
});

describe('UI wiring (built page)', () => {
  const ui = read('public/index.html'), app = read('ui/src/app.js');
  test('share.js is inlined before app.js and the page keeps the CSP-safe build rules', () => {
    assert.ok(ui.includes('var HS = (function'), 'share.js inlined');
    assert.ok(ui.indexOf('var HS = (function') < ui.indexOf("var $ = function (id)"), 'share.js before app.js');
    assert.doesNotMatch(ui, /innerHTML|style="| on[a-z]+=/);
    for (const id of ['share-banner', 'share-link', 'cmp-card', 'cmp-file', 'cmp-link', 'cmp-btn', 'cmp-out', 'cmp-msg']) assert.match(ui, new RegExp(`id="${id}"`), id);
  });
  test('share links are feature-gated, keep r= in the hash on tab changes, and never re-fill the verify host', () => {
    assert.match(app, /CAN_SHARE = typeof CompressionStream === 'function' && typeof DecompressionStream === 'function'/);
    assert.match(app, /'r=' \+ shareTok/);
    assert.match(app, /!r\.sample && !r\.shared/);
    assert.match(app, /This browser cannot open share links/);
    assert.match(app, /size > 1048576/, 'the compare file size is checked before reading');
    assert.ok(app.includes("e.message === 'too large' ? 'This report is too large for a share link"), 'only a size failure says "too large"');
  });
  test('compare UX: the same file can be picked twice, Enter in the link field compares, deep-only findings get a note', () => {
    const file = app.slice(app.indexOf("$('cmp-file').addEventListener"), app.indexOf("$('cmp-form').addEventListener"));
    assert.ok(file.indexOf("this.value = ''") > 0 && file.indexOf("this.value = ''") < file.indexOf('await f.text()'), 'file input reset on every pick');
    assert.match(ui, /<form id="cmp-form" class="row" novalidate>[^]*?id="cmp-link"[^]*?<button type="submit" id="cmp-btn"[^]*?<\/form>/);
    const submit = app.indexOf("$('cmp-form').addEventListener('submit', async function (ev) {");
    assert.ok(submit > 0 && app.indexOf('ev.preventDefault();', submit) - submit < 120, 'the link form is handled on submit');
    assert.match(app, /Different scan depth/);
    assert.match(app, /d = c\.delta\[p\[0\]\]/, 'the shown delta comes from HS.compare (withheld across depths)');
    assert.match(app, /Security scores are not comparable/);
  });
  test('privacy page explains share links', () => {
    const p = read('public/privacy.html');
    assert.match(p, /<h2>Share links<\/h2>/);
    assert.match(p, /fragment/);
    assert.match(p, /not signed|not verified/i);
  });
});
