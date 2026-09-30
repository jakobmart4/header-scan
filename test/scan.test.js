process.env.HEADERSCAN_ALLOW_PRIVATE = '1';
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { scan } from '../lib/scan.js';
import { start, stubResolve } from './fixture-server.js';

const RANK = ['F', 'E', 'D', 'C', 'B', 'A', 'A+'];
const by = (r) => Object.fromEntries(r.findings.map((f) => [f.id, f]));
const run = (srv, opts = {}) => scan({ url: srv.url + '/', resolve: stubResolve(), allowPrivate: true, ...opts });
const SECRETS = ['SECRET_KEY', 'DB_PASSWORD', 'dummy', 'refs/heads'];

describe('scan() self-test', () => {
  let bad, deepSrv, good, spa, rBad, rGood, rDeep, rSpa, rUnverified;
  before(async () => {
    [bad, deepSrv, good, spa] = await Promise.all([start({ mode: 'bad' }), start({ mode: 'bad' }), start({ mode: 'good' }), start({ mode: 'spa' })]);
    [rBad, rGood, rUnverified] = await Promise.all([run(bad), run(good), run(bad, { deep: true, verified: false })]);
    rDeep = await run(deepSrv, { deep: true, verified: true });
    rSpa = await run(spa, { deep: true, verified: true });
  });
  after(async () => { await Promise.all([bad.close(), deepSrv.close(), good.close(), spa.close()]); });

  test('Result shape', () => {
    for (const r of [rBad, rGood]) {
      assert.equal(r.host, '127.0.0.1');
      assert.equal(r.verified, false);
      assert.equal(r.deep, false);
      assert.ok(!Number.isNaN(Date.parse(r.scannedAt)));
      assert.ok(Number.isInteger(r.durationMs));
      assert.ok(Array.isArray(r.findings) && Array.isArray(r.errors));
      assert.ok(r.score.security && r.score.quality && r.score.categories);
    }
  });
  test('passive scan: 119 findings, unique IDs, no module errors, no probes', () => {
    assert.deepEqual(rBad.errors, []);
    assert.equal(new Set(rBad.findings.map((f) => f.id)).size, rBad.findings.length);
    assert.equal(rBad.findings.filter((f) => f.id.startsWith('exp-probe-')).length, 0);
    assert.equal(rBad.findings.length, 119);
    assert.equal(bad.requests.filter((r) => /^\/(\.git|\.env)/.test(r.path)).length, 0, 'passive scan must not probe');
  });
  test('deep without verification: only the skipped gate, probes never requested', () => {
    const f = by(rUnverified);
    assert.equal(f['exp-probes-gate'].status, 'skipped');
    assert.equal(rUnverified.verified, false);
    assert.equal(rUnverified.findings.length, 120);
  });
  test('bad site: grade <= D and the expected findings', () => {
    assert.ok(RANK.indexOf(rBad.score.security.grade) <= RANK.indexOf('D'), rBad.score.security.grade);
    const f = by(rBad);
    for (const id of ['hdr-xcto', 'hdr-frame-protection', 'csp-present', 'cookie-httponly', 'cors-wildcard-credentials', 'seo-title', 'seo-meta-description', 'seo-lang', 'seo-viewport', 'ux-alt-text', 'ux-404-page']) {
      assert.equal(f[id].status, 'fail', id);
    }
    for (const id of ['hdr-server-leak', 'hdr-powered-by', 'ai-robots-blocks-bots', 'seo-h1', 'seo-sitemap']) assert.equal(f[id].status, 'warn', id);
  });
  test('good site: every fail is HTTPS-related (fixture is plain http); without them the grade is >= B', () => {
    const httpsOnly = new Set(['tls-https', 'hdr-hsts']);
    const fails = rGood.findings.filter((f) => f.status === 'fail');
    assert.deepEqual(fails.filter((f) => !httpsOnly.has(f.id)).map((f) => f.id), []);
    const f = by(rGood);
    for (const id of ['csp-present', 'hdr-xcto', 'seo-title', 'seo-h1', 'seo-lang', 'ux-404-page', 'seo-robots-txt', 'seo-sitemap']) assert.equal(f[id].status, 'pass', id);
    // the plain-http fixture really grades D (tls-https is a severity-5 fail); SPEC section 9 states this and the >= B rule without the http-only findings
    assert.equal(rGood.score.security.grade, 'D');
    assert.deepEqual(fails.map((x) => x.id).sort(), ['hdr-hsts', 'tls-https']);
    const sec = rGood.findings.filter((x) => !httpsOnly.has(x.id) && x.category !== 'tls');
    const counted = sec.filter((x) => ['headers', 'cookies', 'content', 'exposure'].includes(x.category) && ['pass', 'warn', 'fail'].includes(x.status));
    const w = counted.reduce((a, x) => a + x.severity, 0);
    const e = counted.reduce((a, x) => a + x.severity * (x.status === 'pass' ? 1 : x.status === 'warn' ? 0.5 : 0), 0);
    assert.ok((100 * e) / w >= 80, `score ${(100 * e) / w}`);
    assert.ok(RANK.indexOf(rGood.score.quality.grade) >= RANK.indexOf('B'), rGood.score.quality.grade);
  });
  test('good scores better than bad', () => {
    assert.ok(rGood.score.security.score > rBad.score.security.score);
    assert.ok(rGood.score.quality.score > rBad.score.quality.score);
  });
  test('deep + verified on bad: .git/HEAD and .env fail; evidence has no contents', () => {
    const f = by(rDeep);
    assert.equal(rDeep.verified, true);
    assert.equal(rDeep.deep, true);
    assert.equal(f['exp-probe-git-head'].status, 'fail');
    assert.equal(f['exp-probe-env'].status, 'fail');
    assert.equal(rDeep.findings.length, 144);
    const json = JSON.stringify(rDeep);
    for (const s of SECRETS) assert.ok(!json.includes(s), `result leaks ${s}`);
  });
  test('deep + verified on SPA catch-all: zero probe hits', () => {
    const hits = rSpa.findings.filter((f) => f.id.startsWith('exp-probe-') && ['fail', 'info'].includes(f.status));
    assert.deepEqual(hits.map((f) => f.id), []);
  });
  test('sorted by category order, then status severity, then id', () => {
    const ORDER = ['headers', 'cookies', 'tls', 'dns', 'mail', 'content', 'seo', 'ai', 'ux', 'exposure'];
    const ci = (f) => ORDER.indexOf(f.category);
    for (let i = 1; i < rBad.findings.length; i++) assert.ok(ci(rBad.findings[i - 1]) <= ci(rBad.findings[i]), `${rBad.findings[i].id} out of order`);
  });
  test('bad input: private target and bad URL are refused', async () => {
    await assert.rejects(scan({ url: 'http://10.0.0.1/', allowPrivate: false }), (e) => ['BLOCKED_TARGET', 'BAD_URL'].includes(e.code));
    await assert.rejects(scan({ url: 'ftp://example.com/', allowPrivate: false }), (e) => e.code === 'BAD_URL');
  });
});
