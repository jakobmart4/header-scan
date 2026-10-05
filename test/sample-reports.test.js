process.env.HEADERSCAN_ALLOW_PRIVATE = '1';
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { scan } from '../lib/scan.js';
import { score } from '../lib/score.js';
import { start, stubResolve } from './fixture-server.js';

const load = (n) => JSON.parse(readFileSync(new URL(`../public/samples/${n}.json`, import.meta.url), 'utf8'));
const perfect = load('perfect'), mixed = load('mixed');
const near50 = (g) => g.score >= 47 && g.score <= 53;

describe('sample reports (public/samples)', () => {
  let srv, live;
  before(async () => { srv = await start({ mode: 'bad' }); live = await scan({ url: srv.url + '/', resolve: stubResolve(), allowPrivate: true }); });
  after(() => srv.close());

  test('labelled as samples, with the fake host', () => {
    for (const r of [perfect, mixed]) {
      assert.equal(r.sample, true);
      assert.equal(r.host, 'sample.invalid');
      assert.equal(r.url, 'https://sample.invalid/');
      assert.ok(Array.isArray(r.rawHeaders) && r.rawHeaders.length > 0);
    }
  });
  test('stored scores are exactly what lib/score.js computes from the findings', () => {
    for (const r of [perfect, mixed]) assert.deepEqual(r.score, score(r.findings));
  });
  test('perfect is A+ 100 for security and quality', () => {
    for (const g of [perfect.score.security, perfect.score.quality]) assert.deepEqual([g.grade, g.score], ['A+', 100]);
    assert.ok(perfect.findings.every((f) => ['pass', 'info', 'skipped'].includes(f.status)));
  });
  test('mixed lands within 47..53 for security and quality, with every status present', () => {
    assert.ok(near50(mixed.score.security), `security ${mixed.score.security.score}`);
    assert.ok(near50(mixed.score.quality), `quality ${mixed.score.quality.score}`);
    for (const st of ['pass', 'warn', 'fail', 'info']) assert.ok(mixed.findings.some((f) => f.status === st), st);
  });
  test('finding ids equal the live catalog (119)', () => {
    const ids = (r) => r.findings.map((f) => f.id).sort();
    assert.equal(live.findings.length, 119);
    assert.deepEqual(ids(perfect), ids(live));
    assert.deepEqual(ids(mixed), ids(live));
  });
  test('no e-mail address in the samples', () => {
    for (const n of ['perfect', 'mixed']) {
      const raw = readFileSync(new URL(`../public/samples/${n}.json`, import.meta.url), 'utf8');
      assert.doesNotMatch(raw, /[\w.+-]+@[\w-]+\.[\w.-]+/, n);
    }
  });
});
