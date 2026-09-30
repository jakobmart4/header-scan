process.env.HEADERSCAN_ALLOW_PRIVATE = '1';
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { IDS, run } from '../lib/checks/headers.js';
import { fakeCtx, start, buildCtx } from './fixture-server.js';

const by = (fs) => Object.fromEntries(fs.map((f) => [f.id, f.status]));
const res = (headers) => async () => ({ status: 200, headers, body: '', finalUrl: 'https://example.test/', timingMs: 1, redirects: [], truncated: false });
const GOOD = {
  'strict-transport-security': 'max-age=63072000; includeSubDomains; preload', 'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer', 'permissions-policy': 'camera=()', 'cross-origin-opener-policy': 'same-origin',
  'cross-origin-embedder-policy': 'require-corp', 'cross-origin-resource-policy': 'same-origin', 'cache-control': 'no-cache',
};

describe('headers.js (hand-made ctx)', () => {
  test('exactly the owned IDs, once each', async () => {
    const out = await run(fakeCtx({ headers: GOOD }));
    assert.deepEqual([...out.map((f) => f.id)].sort(), [...IDS].sort());
    assert.equal(new Set(IDS).size, IDS.length);
  });
  test('all good headers pass', async () => {
    const s = by(await run(fakeCtx({ headers: GOOD, fetch: res({}) })));
    for (const id of ['hdr-hsts', 'hdr-hsts-subdomains', 'hdr-hsts-preload', 'hdr-xcto', 'hdr-frame-protection', 'hdr-referrer-policy', 'hdr-permissions-policy', 'hdr-coop', 'hdr-coep', 'hdr-corp', 'hdr-server-leak', 'hdr-powered-by', 'cors-wildcard-credentials', 'cors-reflected-origin', 'cors-null-origin']) assert.equal(s[id], 'pass', id);
  });
  test('missing headers on https', async () => {
    const s = by(await run(fakeCtx({ fetch: res({}) })));
    assert.equal(s['hdr-hsts'], 'fail');
    assert.equal(s['hdr-hsts-subdomains'], 'skipped');
    assert.equal(s['hdr-xcto'], 'fail');
    assert.equal(s['hdr-frame-protection'], 'fail');
    assert.equal(s['hdr-referrer-policy'], 'warn');
    assert.equal(s['hdr-permissions-policy'], 'warn');
    assert.equal(s['hdr-coop'], 'info');
  });
  test('weak HSTS max-age is a warning', async () => {
    const s = by(await run(fakeCtx({ headers: { 'strict-transport-security': 'max-age=100' }, fetch: res({}) })));
    assert.equal(s['hdr-hsts'], 'warn');
    assert.equal(s['hdr-hsts-subdomains'], 'warn');
  });
  test('http target: HSTS fails (no HTTPS)', async () => {
    const s = by(await run(fakeCtx({ url: 'http://example.test/', fetch: res({}) })));
    assert.equal(s['hdr-hsts'], 'fail');
  });
  test('CSP frame-ancestors satisfies frame protection', async () => {
    const s = by(await run(fakeCtx({ headers: { 'content-security-policy': "frame-ancestors 'none'" }, fetch: res({}) })));
    assert.equal(s['hdr-frame-protection'], 'pass');
  });
  test('information leaks', async () => {
    const s = by(await run(fakeCtx({ headers: { server: 'nginx/1.18.0', 'x-powered-by': 'Express' }, body: '<meta name="generator" content="WordPress 6.4.2">', fetch: res({}) })));
    assert.equal(s['hdr-server-leak'], 'warn');
    assert.equal(s['hdr-powered-by'], 'warn');
    assert.equal(s['hdr-generator-leak'], 'warn');
    assert.equal(by(await run(fakeCtx({ headers: { server: 'nginx' }, fetch: res({}) })))['hdr-server-leak'], 'pass');
  });
  test('CORS: credentials with reflected origin fails; null origin', async () => {
    const reflect = async (u, o = {}) => {
      const origin = (o.headers || {}).Origin || (o.headers || {}).origin;
      return { status: 200, headers: origin ? { 'access-control-allow-origin': origin, 'access-control-allow-credentials': 'true' } : {}, body: '', finalUrl: u, timingMs: 1, redirects: [], truncated: false };
    };
    const s = by(await run(fakeCtx({ fetch: reflect })));
    assert.equal(s['cors-wildcard-credentials'], 'fail');
    assert.equal(s['cors-null-origin'], 'fail');
    const star = by(await run(fakeCtx({ fetch: res({ 'access-control-allow-origin': '*', 'access-control-allow-credentials': 'true' }) })));
    assert.equal(star['cors-wildcard-credentials'], 'fail');
  });
  test('failed page fetch never throws', async () => {
    const ctx = fakeCtx({ status: 0 });
    const out = await run(ctx);
    assert.equal(out.length, IDS.length);
  });
});

describe('headers.js (fixture)', () => {
  let bad, good;
  before(async () => { bad = await start({ mode: 'bad' }); good = await start({ mode: 'good' }); });
  after(async () => { await bad.close(); await good.close(); });
  test('bad site: missing headers, leaks, reflected CORS with credentials', async () => {
    const s = by(await run(await buildCtx(bad.url + '/')));
    assert.equal(s['hdr-hsts'], 'fail');
    assert.equal(s['hdr-xcto'], 'fail');
    assert.equal(s['hdr-server-leak'], 'warn');
    assert.equal(s['hdr-powered-by'], 'warn');
    assert.equal(s['cors-wildcard-credentials'], 'fail');
  });
  test('good site: security headers pass, no CORS problems', async () => {
    const s = by(await run(await buildCtx(good.url + '/')));
    for (const id of ['hdr-xcto', 'hdr-frame-protection', 'hdr-referrer-policy', 'hdr-permissions-policy', 'hdr-coop', 'hdr-coep', 'hdr-corp', 'hdr-server-leak', 'hdr-powered-by', 'cors-wildcard-credentials', 'cors-reflected-origin', 'cors-null-origin']) assert.equal(s[id], 'pass', id);
  });
});
