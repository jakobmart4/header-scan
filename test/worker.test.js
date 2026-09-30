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
