// HEADERSCAN_PROXY_KEY gate: /api/* (except health) only via the Cloudflare proxy. Child process, random port, killed in after().
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const KEY = 'proxy-test-key-not-real';
let child, base;

before(async () => {
  const port = 41000 + Math.floor(Math.random() * 8000);
  child = spawn(process.execPath, ['server.js'], {
    cwd: root, stdio: 'ignore', windowsHide: true,
    env: { ...process.env, PORT: String(port), HOST: '127.0.0.1', HEADERSCAN_PROXY_KEY: KEY, HEADERSCAN_SECRET: 'proxy-test-secret-not-real' },
  });
  base = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 60; i++) {
    try { if ((await fetch(base + '/api/health')).ok) return; } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('server did not start');
});
after(() => child.kill());

describe('proxy key', () => {
  const start = (headers) => fetch(base + '/api/verify/start', { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: '{"host":"example.com"}' });

  test('health stays open', async () => assert.equal((await fetch(base + '/api/health')).status, 200));
  test('no key -> 403', async () => assert.equal((await start({})).status, 403));
  test('wrong key -> 403', async () => assert.equal((await start({ 'x-headerscan-key': 'nope' })).status, 403));
  test('right key -> passes the gate', async () => assert.equal((await start({ 'x-headerscan-key': KEY })).status, 200));
  test('rate limit is per forwarded client, not per proxy', async () => {
    const h = (ip) => ({ 'x-headerscan-key': KEY, 'x-headerscan-client': ip });
    const codes = [];
    for (let i = 0; i < 40; i++) codes.push((await start(h('203.0.113.7'))).status);
    assert.ok(codes.includes(429), 'first client gets limited');
    assert.equal((await start(h('203.0.113.8'))).status, 200, 'second client unaffected');
  });
});
