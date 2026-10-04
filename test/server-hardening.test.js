// In-process server with a fake scan: per-client concurrency cap, capacity checks that do not burn quota, /64 limiter key, no UI on the proxied backend.
import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, limiterKey } from '../server.js';

const servers = [];
async function boot({ key } = {}) {
  const gates = [];
  const scan = () => new Promise((resolve) => gates.push(() => resolve({ ok: true })));
  if (key) process.env.HEADERSCAN_PROXY_KEY = key;
  const server = createServer({ scan, host: '127.0.0.1' });
  delete process.env.HEADERSCAN_PROXY_KEY;
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  servers.push(server);
  const base = `http://127.0.0.1:${server.address().port}`;
  const get = (client) => fetch(`${base}/api/scan?url=https://example.com`, { headers: key ? { 'x-headerscan-key': key, 'x-headerscan-client': client } : {} });
  const started = async (n) => { for (let i = 0; i < 100 && gates.length < n; i++) await new Promise((r) => setTimeout(r, 10)); assert.equal(gates.length, n); };
  const release = () => { gates.splice(0).forEach((g) => g()); };
  return { base, get, started, release };
}
after(() => { for (const s of servers) { s.closeAllConnections(); s.close(); } });

describe('limiterKey', () => {
  test('IPv4 unchanged; IPv6 collapses to its /64; mapped IPv4 and zone ids handled', () => {
    assert.equal(limiterKey('203.0.113.7'), '203.0.113.7');
    assert.equal(limiterKey('2001:db8:1:2:aaaa:bbbb:cccc:dddd'), '2001:db8:1:2::/64');
    assert.equal(limiterKey('2001:db8:1:2:ffff::1'), limiterKey('2001:0DB8:1:2::9'));
    assert.equal(limiterKey('2001:db8::1'), '2001:db8:0:0::/64');
    assert.equal(limiterKey('::1'), '0:0:0:0::/64');
    assert.equal(limiterKey('::ffff:203.0.113.7'), '203.0.113.7');
    assert.equal(limiterKey('fe80::1%eth0'), 'fe80:0:0:0::/64');
    assert.notEqual(limiterKey('2001:db8:1:2::1'), limiterKey('2001:db8:1:3::1'));
    assert.equal(limiterKey('unknown'), 'unknown');
  });
});

describe('capacity', () => {
  test('one client cannot hold more than 2 scans; the rejection costs no quota', async () => {
    const t = await boot();
    const held = [t.get(), t.get()];
    await t.started(2);
    const r = await t.get();
    assert.equal(r.status, 429);
    assert.equal(r.headers.get('retry-after'), '10');
    assert.equal((await r.json()).error.code, 'RATE_LIMITED');
    t.release(); await Promise.all(held);
    for (let i = 0; i < 4; i++) { const p = t.get(); await t.started(1); t.release(); assert.equal((await p).status, 200, `scan ${i + 3}`); } // 2 held + 4 = the full 6/min
  });

  test('global BUSY (4 slots) is answered before the rate limiter and does not use the client quota', async () => {
    const t = await boot({ key: 'hardening-test-key-not-real' });
    const held = ['203.0.113.1', '203.0.113.2', '203.0.113.3', '203.0.113.4'].map((c) => t.get(c));
    await t.started(4);
    const r = await t.get('203.0.113.5');
    assert.equal(r.status, 503);
    assert.equal(r.headers.get('retry-after'), '10');
    t.release(); await Promise.all(held);
    for (let i = 0; i < 6; i++) { const p = t.get('203.0.113.5'); await t.started(1); t.release(); assert.equal((await p).status, 200, `scan ${i + 1}`); }
    assert.equal((await t.get('203.0.113.5')).status, 429); // the 7th is limited by the per-minute limiter
    t.release();
  });
});

describe('proxied backend', () => {
  test('/ is 404 without the proxy key (no second public UI), 200 with it; no key configured -> UI served', async () => {
    const keyed = await boot({ key: 'hardening-test-key-not-real' });
    assert.equal((await fetch(keyed.base + '/')).status, 404);
    assert.equal((await fetch(keyed.base + '/index.html', { headers: { 'x-headerscan-key': 'wrong' } })).status, 404);
    assert.equal((await fetch(keyed.base + '/', { headers: { 'x-headerscan-key': 'hardening-test-key-not-real' } })).status, 200);
    assert.equal((await fetch(keyed.base + '/api/health')).status, 200);
    const open = await boot();
    assert.equal((await fetch(open.base + '/')).status, 200);
  });
});
