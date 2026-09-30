process.env.HEADERSCAN_ALLOW_PRIVATE = '1';
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { IDS, run } from '../lib/checks/tls.js';
import { start, buildCtx } from './fixture-server.js';

const by = (fs) => Object.fromEntries(fs.map((f) => [f.id, f]));

// No TLS listener exists on the fixture (plain http on a random port): exercises the "no HTTPS" branch offline.
describe('tls.js', () => {
  let srv;
  before(async () => { srv = await start({ mode: 'good' }); });
  after(async () => { await srv.close(); });

  test('exactly the owned IDs, once each; never throws when https is unreachable', async () => {
    const out = await run(await buildCtx(srv.url + '/'));
    assert.deepEqual([...out.map((f) => f.id)].sort(), [...IDS].sort());
    assert.equal(new Set(IDS).size, 11);
  });
  test('http-only site: tls-https fails, certificate checks are skipped', async () => {
    const f = by(await run(await buildCtx(srv.url + '/')));
    assert.equal(f['tls-https'].status, 'fail');
    for (const id of ['tls-protocol', 'tls-cert-expiry', 'tls-cert-host', 'tls-cert-chain', 'tls-cert-key', 'tls-cert-sigalg']) assert.ok(['skipped', 'fail'].includes(f[id].status), id);
  });
  test('evidence stays short and free of raw certificate blobs', async () => {
    for (const f of await run(await buildCtx(srv.url + '/'))) {
      assert.ok(f.evidence.length <= 300);
      assert.ok(!f.evidence.includes('BEGIN CERTIFICATE'));
    }
  });
});
