import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import path from 'node:path';

const { default: worker } = await import(pathToFileURL(path.resolve('worker/index.js')).href);
const env = { BACKEND_URL: 'https://backend.example', PROXY_KEY: 'k' };
const call = (url, init, e = env) => worker.fetch(new Request(url, init), e);

test('unknown path / wrong method / missing env are rejected before any fetch', async () => {
  const orig = globalThis.fetch; globalThis.fetch = () => { throw new Error('must not fetch'); };
  try {
    assert.equal((await call('https://s.test/api/other')).status, 404);
    assert.equal((await call('https://s.test/api/verify/start')).status, 405);
    assert.equal((await call('https://s.test/api/health', {}, {})).status, 500);
  } finally { globalThis.fetch = orig; }
});

test('forwards key + client ip, strips other headers, returns backend body', async () => {
  const orig = globalThis.fetch; let seen;
  globalThis.fetch = async (u, init) => { seen = { u: String(u), init }; return new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json', 'set-cookie': 'x=1' } }); };
  try {
    const r = await call('https://s.test/api/scan?url=https://a.com', { headers: { 'cf-connecting-ip': '198.51.100.9', cookie: 'secret=1' } });
    assert.equal(seen.u, 'https://backend.example/api/scan?url=https://a.com');
    assert.equal(seen.init.headers.get('x-headerscan-key'), 'k');
    assert.equal(seen.init.headers.get('x-headerscan-client'), '198.51.100.9');
    assert.equal(seen.init.headers.get('cookie'), null);
    assert.equal(r.headers.get('set-cookie'), null);
    assert.equal(r.status, 200);
  } finally { globalThis.fetch = orig; }
});

test('unreachable backend -> 502 JSON', async () => {
  const orig = globalThis.fetch; globalThis.fetch = async () => { throw new Error('down'); };
  try { assert.equal((await call('https://s.test/api/health')).status, 502); } finally { globalThis.fetch = orig; }
});

const SEC = ['strict-transport-security', 'content-security-policy', 'cross-origin-opener-policy', 'cross-origin-resource-policy', 'permissions-policy', 'referrer-policy', 'x-content-type-options'];
const hasSecurityHeaders = (r) => SEC.every((h) => r.headers.get(h)) && /no-store/.test(r.headers.get('cache-control'));

test('Worker-generated responses (errors, proxied replies) carry the security headers', async () => {
  const orig = globalThis.fetch;
  globalThis.fetch = async () => new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } });
  try {
    for (const r of [await call('https://s.test/api/other'), await call('https://s.test/api/verify/start'), await call('https://s.test/api/health', {}, {}), await call('https://s.test/api/health')]) {
      assert.ok(hasSecurityHeaders(r), `status ${r.status} lacks headers`);
    }
    const m = await call('https://s.test/api/verify/start');
    assert.equal(m.status, 405);
    assert.equal(m.headers.get('allow'), 'POST');
    assert.equal((await m.json()).error.message, 'method not allowed');
  } finally { globalThis.fetch = orig; }
});

test('plain HTTP is redirected to HTTPS (308), localhost is exempt', async () => {
  const orig = globalThis.fetch; globalThis.fetch = () => { throw new Error('must not fetch'); };
  try {
    const r = await call('http://s.test/api/scan?url=https://a.com');
    assert.equal(r.status, 308);
    assert.equal(r.headers.get('location'), 'https://s.test/api/scan?url=https://a.com');
    assert.equal((await call('http://localhost:8787/api/other')).status, 404);
  } finally { globalThis.fetch = orig; }
});

test('backend waking up: network error or upstream HTML 502/503/504 -> JSON 502 with message + Retry-After', async () => {
  const orig = globalThis.fetch;
  try {
    globalThis.fetch = async () => { throw new Error('down'); };
    let r = await call('https://s.test/api/health');
    assert.equal(r.status, 502);
    assert.equal(r.headers.get('retry-after'), '30');
    assert.match((await r.json()).error.message, /waking up/);
    for (const st of [502, 503, 504]) {
      globalThis.fetch = async () => new Response('<html>Service waking</html>', { status: st, headers: { 'content-type': 'text/html' } });
      r = await call('https://s.test/api/health');
      assert.equal(r.status, 502);
      assert.match(r.headers.get('content-type'), /json/);
      assert.equal((await r.json()).error.code, 'BACKEND_UNREACHABLE');
    }
    // the backend's own JSON errors are passed through untouched
    globalThis.fetch = async () => new Response('{"error":{"code":"BUSY","message":"server busy"}}', { status: 503, headers: { 'content-type': 'application/json; charset=utf-8', 'retry-after': '10' } });
    r = await call('https://s.test/api/health');
    assert.equal(r.status, 503);
    assert.equal(r.headers.get('retry-after'), '10');
    assert.equal((await r.json()).error.code, 'BUSY');
    assert.ok(hasSecurityHeaders(r));
  } finally { globalThis.fetch = orig; }
});
