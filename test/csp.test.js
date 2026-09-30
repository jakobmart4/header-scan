import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { IDS, run, parseCsp, hasEffectiveUnsafeInline } from '../lib/checks/csp.js';
import { fakeCtx } from './fixture-server.js';

const by = (fs) => Object.fromEntries(fs.map((f) => [f.id, f.status]));
const ids = (fs) => fs.map((f) => f.id);

describe('parseCsp', () => {
  test('lowercases directives, first occurrence wins', () => {
    const d = parseCsp("Default-Src 'self'; script-src a.test b.test; default-src x.test;;");
    assert.deepEqual(d.get('default-src'), ["'self'"]);
    assert.deepEqual(d.get('script-src'), ['a.test', 'b.test']);
    assert.equal(d.has('style-src'), false);
  });
  test('empty / undefined input', () => {
    assert.equal(parseCsp('').size, 0);
    assert.equal(parseCsp(undefined).size, 0);
  });
  test("'unsafe-inline' is ineffective with nonce, hash or strict-dynamic", () => {
    assert.equal(hasEffectiveUnsafeInline(["'unsafe-inline'"]), true);
    assert.equal(hasEffectiveUnsafeInline(["'unsafe-inline'", "'nonce-abc'"]), false);
    assert.equal(hasEffectiveUnsafeInline(["'unsafe-inline'", "'sha256-abc='"]), false);
    assert.equal(hasEffectiveUnsafeInline(["'unsafe-inline'", "'strict-dynamic'"]), false);
    assert.equal(hasEffectiveUnsafeInline(["'self'"]), false);
  });
});

describe('run()', () => {
  test('one finding per ID, no duplicates', async () => {
    for (const ctx of [fakeCtx({}), fakeCtx({ headers: { 'content-security-policy': "default-src 'self'" } })]) {
      const out = await run(ctx);
      assert.deepEqual(new Set(ids(out)), new Set(IDS));
      assert.equal(out.length, IDS.length);
    }
  });
  test('no CSP: present fails, dependent checks skipped', async () => {
    const s = by(await run(fakeCtx({})));
    assert.equal(s['csp-present'], 'fail');
    for (const id of ['csp-unsafe-inline', 'csp-unsafe-eval', 'csp-wildcard', 'csp-data-uri', 'csp-object-src', 'csp-base-uri', 'csp-frame-ancestors', 'csp-default-src', 'csp-upgrade-insecure']) assert.equal(s[id], 'skipped', id);
  });
  test('weak policy', async () => {
    const s = by(await run(fakeCtx({ headers: { 'content-security-policy': "script-src * 'unsafe-inline' 'unsafe-eval' data:" } })));
    assert.equal(s['csp-present'], 'pass');
    assert.equal(s['csp-unsafe-inline'], 'fail');
    assert.equal(s['csp-unsafe-eval'], 'warn');
    assert.equal(s['csp-wildcard'], 'fail');
    assert.equal(s['csp-data-uri'], 'warn');
    assert.equal(s['csp-object-src'], 'warn');
    assert.equal(s['csp-base-uri'], 'warn');
    assert.equal(s['csp-frame-ancestors'], 'warn');
    assert.equal(s['csp-default-src'], 'warn');
  });
  test('script-src falls back to default-src', async () => {
    const s = by(await run(fakeCtx({ headers: { 'content-security-policy': "default-src 'unsafe-inline' https:" } })));
    assert.equal(s['csp-unsafe-inline'], 'fail');
    assert.equal(s['csp-wildcard'], 'fail');
  });
  test('nonce neutralizes unsafe-inline', async () => {
    const s = by(await run(fakeCtx({ headers: { 'content-security-policy': "script-src 'unsafe-inline' 'nonce-abc'" } })));
    assert.equal(s['csp-unsafe-inline'], 'pass');
  });
  test('strong policy passes everything', async () => {
    const csp = "default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; upgrade-insecure-requests";
    const s = by(await run(fakeCtx({ headers: { 'content-security-policy': csp } })));
    for (const id of ['csp-present', 'csp-unsafe-inline', 'csp-unsafe-eval', 'csp-wildcard', 'csp-data-uri', 'csp-object-src', 'csp-base-uri', 'csp-frame-ancestors', 'csp-default-src', 'csp-upgrade-insecure']) assert.equal(s[id], 'pass', id);
  });
  test('report-only alone is info, meta CSP is only a warning', async () => {
    const ro = by(await run(fakeCtx({ headers: { 'content-security-policy-report-only': "default-src 'self'" } })));
    assert.equal(ro['csp-present'], 'fail');
    assert.equal(ro['csp-report-only'], 'info');
    const meta = by(await run(fakeCtx({ body: `<meta http-equiv="Content-Security-Policy" content="default-src 'self'">` })));
    assert.equal(meta['csp-present'], 'warn');
  });
  test('mixed content and SRI on an https page', async () => {
    const body = '<script src="http://a.test/x.js"></script><img src="http://a.test/i.png"><script src="https://cdn.other.test/l.js"></script>';
    const s = by(await run(fakeCtx({ body })));
    assert.equal(s['mixed-active'], 'fail');
    assert.equal(s['mixed-passive'], 'warn');
    assert.equal(s['sri-external'], 'warn');
    const ok = by(await run(fakeCtx({ body: '<script src="/a.js"></script><script src="https://cdn.other.test/l.js" integrity="sha384-x"></script>' })));
    assert.equal(ok['mixed-active'], 'pass');
    assert.equal(ok['sri-external'], 'pass');
  });
  test('http target: mixed-content checks skipped', async () => {
    const s = by(await run(fakeCtx({ url: 'http://example.test/', body: '<script src="http://a.test/x.js"></script>' })));
    assert.equal(s['mixed-active'], 'skipped');
    assert.equal(s['mixed-passive'], 'skipped');
  });
  test('evidence never carries the full policy body of secrets: <= 300 chars', async () => {
    const out = await run(fakeCtx({ headers: { 'content-security-policy': "script-src " + 'a.test '.repeat(200) } }));
    for (const f of out) assert.ok(f.evidence.length <= 300);
  });
});
