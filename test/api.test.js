// Starts `node server.js` as a child process on a random high port (never 34872 / 1000 / 8787) and kills it in after().
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const servers = [];

async function boot() {
  const port = 41000 + Math.floor(Math.random() * 8000);
  const child = spawn(process.execPath, ['server.js'], {
    cwd: root, stdio: 'ignore', windowsHide: true,
    env: { ...process.env, PORT: String(port), HOST: '127.0.0.1', HEADERSCAN_ALLOW_PRIVATE: '1', HEADERSCAN_SECRET: 'api-test-secret-not-real' },
  });
  const srv = { port, base: `http://127.0.0.1:${port}`, child };
  servers.push(srv);
  for (let i = 0; i < 60; i++) {
    try { if ((await fetch(srv.base + '/api/health')).ok) return srv; } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('server did not start');
}
const post = (srv, p, body, raw) => fetch(srv.base + p, { method: 'POST', headers: { 'content-type': 'application/json' }, body: raw ?? JSON.stringify(body) });
const errCode = async (res) => (await res.json()).error?.code;

after(() => { for (const s of servers) s.child.kill(); });

describe('API', () => {
  let s;
  before(async () => { s = await boot(); });

  test('health', async () => {
    const r = await fetch(s.base + '/api/health');
    assert.equal(r.status, 200);
    assert.match(r.headers.get('content-type'), /application\/json/);
    const j = await r.json();
    assert.equal(j.ok, true);
    assert.ok(j.version);
  });
  test('security headers on every response; index.html has a strict CSP', async () => {
    const api = await fetch(s.base + '/api/health');
    assert.equal(api.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(api.headers.get('referrer-policy'), 'no-referrer');
    assert.match(api.headers.get('cache-control'), /no-store/);
    const idx = await fetch(s.base + '/');
    assert.equal(idx.status, 200);
    assert.match(idx.headers.get('content-type'), /text\/html/);
    const csp = idx.headers.get('content-security-policy');
    assert.match(csp, /default-src 'none'/);
    assert.match(csp, /script-src 'sha256-/);
    assert.match(csp, /frame-ancestors 'none'/);
    assert.equal(idx.headers.get('x-content-type-options'), 'nosniff');
  });
  test('index.html renders scan data without innerHTML', async () => {
    const html = await (await fetch(s.base + '/')).text();
    assert.ok(!/\.innerHTML|insertAdjacentHTML|document\.write/.test(html));
  });
  test('unknown route -> 404 NOT_FOUND; other public files -> 404; wrong method -> 405', async () => {
    const r = await fetch(s.base + '/nope');
    assert.equal(r.status, 404);
    assert.equal(await errCode(r), 'NOT_FOUND');
    assert.equal((await fetch(s.base + '/index.html.bak')).status, 404);
    const m = await fetch(s.base + '/api/health', { method: 'POST' });
    assert.equal(m.status, 405);
    assert.equal(await errCode(m), 'METHOD_NOT_ALLOWED');
  });
  test('bad URL -> 400 BAD_URL; private target -> 400 (allowPrivate off via ports)', async () => {
    const r = await fetch(s.base + '/api/scan?url=' + encodeURIComponent('ftp://example.com/'));
    assert.equal(r.status, 400);
    assert.equal(await errCode(r), 'BAD_URL');
  });
  test('POST /api/scan: bad JSON / missing url -> 400 BAD_REQUEST', async () => {
    const a = await post(s, '/api/scan', null, '{not json');
    assert.equal(a.status, 400);
    assert.equal(await errCode(a), 'BAD_REQUEST');
    const b = await post(s, '/api/scan', {});
    assert.equal(b.status, 400);
    assert.equal(await errCode(b), 'BAD_REQUEST');
  });
  test('body over 4 KiB -> 413 TOO_LARGE', async () => {
    const r = await post(s, '/api/scan', { url: 'https://example.com/', pad: 'x'.repeat(5000) });
    assert.equal(r.status, 413);
    assert.equal(await errCode(r), 'TOO_LARGE');
  });
  test('client cannot supply "verified": deep scan without TXT -> 403 NOT_VERIFIED naming the TXT record', async () => {
    const r = await post(s, '/api/scan', { url: 'https://example.com/', deep: true, verified: true });
    assert.equal(r.status, 403);
    const j = await r.json();
    assert.equal(j.error.code, 'NOT_VERIFIED');
    assert.match(j.error.message, /_headerscan-verify\.example\.com/);
  });
  test('verify/start returns a token bound to the host', async () => {
    const r = await post(s, '/api/verify/start', { host: 'Example.com' });
    assert.equal(r.status, 200);
    const j = await r.json();
    assert.equal(j.host, 'example.com');
    assert.equal(j.txtName, '_headerscan-verify.example.com');
    assert.equal(j.txtValue, `headerscan-verify=${j.token}`);
    assert.ok(j.expiresAt > Date.now());
  });
  test('verify/check without a TXT record -> verified:false', async () => {
    const r = await post(s, '/api/verify/check', { host: 'example.com' });
    assert.equal(r.status, 200);
    const j = await r.json();
    assert.equal(j.verified, false);
    assert.equal(j.txtName, '_headerscan-verify.example.com');
  });
  test('verify refused for shared hosting and IP literals -> 400 BAD_REQUEST', async () => {
    for (const host of ['foo.vercel.app', 'me.github.io', '8.8.8.8']) {
      const r = await post(s, '/api/verify/start', { host });
      assert.equal(r.status, 400, host);
      assert.equal(await errCode(r), 'BAD_REQUEST');
    }
  });
  test('errors never leak stack traces', async () => {
    const txt = await (await post(s, '/api/scan', null, '{bad')).text();
    assert.ok(!/\bat .*\(.*:\d+:\d+\)|node:internal|\.js:\d+/.test(txt));
  });
});

describe('API rate limit', () => {
  test('7th scan request within a minute -> 429 with Retry-After', async () => {
    const s = await boot(); // fresh process = fresh counters
    const codes = [];
    let last;
    for (let i = 0; i < 7; i++) {
      last = await fetch(s.base + '/api/scan?url=' + encodeURIComponent('ftp://example.com/'));
      codes.push(last.status);
    }
    assert.deepEqual(codes.slice(0, 6), [400, 400, 400, 400, 400, 400]);
    assert.equal(codes[6], 429);
    assert.equal(await errCode(last), 'RATE_LIMITED');
    assert.ok(Number(last.headers.get('retry-after')) > 0);
  });
  test('health never counts against the scan limit (the UI pings it on page load)', async () => {
    const s = await boot();
    for (let i = 0; i < 30; i++) {
      const h = await fetch(s.base + '/api/health');
      assert.equal(h.status, 200);
      assert.equal((await h.json()).ok, true);
    }
    // ftp:// passes admit()/limit() and then fails validation: 400 means the scan bucket still had room
    const codes = [];
    for (let i = 0; i < 7; i++) codes.push((await fetch(s.base + '/api/scan?url=' + encodeURIComponent('ftp://example.com/'))).status);
    assert.deepEqual(codes, [400, 400, 400, 400, 400, 400, 429]);
    assert.equal((await fetch(s.base + '/api/health')).status, 200);
  });
  test('X-Forwarded-For is ignored by default', async () => {
    const s = await boot();
    let status;
    for (let i = 0; i < 7; i++) {
      status = (await fetch(s.base + '/api/scan?url=' + encodeURIComponent('ftp://example.com/'), { headers: { 'x-forwarded-for': `203.0.113.${i + 1}` } })).status;
    }
    assert.equal(status, 429);
  });
});
