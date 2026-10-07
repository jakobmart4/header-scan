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
      { ...mixed, findings: {} }, { ...mixed, url: 'u'.repeat(2049) }, { ...mixed, scannedAt: 5 }, { ...mixed, durationMs: -1 },
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
  });
  test('privacy page explains share links', () => {
    const p = read('public/privacy.html');
    assert.match(p, /<h2>Share links<\/h2>/);
    assert.match(p, /fragment/);
    assert.match(p, /not signed|not verified/i);
  });
});
