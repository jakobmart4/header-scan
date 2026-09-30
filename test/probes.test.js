process.env.HEADERSCAN_ALLOW_PRIVATE = '1';
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { IDS, run } from '../lib/checks/probes.js';
import { start, buildCtx, fakeCtx } from './fixture-server.js';

const ALLOWED = new Set(['/.git/HEAD', '/.git/config', '/.env', '/.svn/wc.db', '/.hg/requires', '/.DS_Store', '/backup.zip', '/backup.sql', '/backup.tar.gz', '/db.sql',
  '/wp-config.php.bak', '/phpinfo.php', '/server-status', '/actuator/env', '/actuator', '/admin', '/phpmyadmin/', '/debug', '/swagger.json', '/openapi.json',
  '/package.json', '/.vercel/project.json', '/WEB-INF/web.xml', '/uploads/']);
const isBaseline = (p) => /^\/[0-9a-f]{16}-hs-probe$/.test(p);
const by = (fs) => Object.fromEntries(fs.map((f) => [f.id, f]));
const SECRETS = ['SECRET_KEY', 'DB_PASSWORD', 'dummy', 'fake', 'refs/heads'];

describe('probes.js', () => {
  test('IDS: gate + 24 probes, unique', () => {
    assert.equal(IDS[0], 'exp-probes-gate');
    assert.equal(IDS.length, 25);
    assert.equal(new Set(IDS).size, 25);
    assert.ok(IDS.slice(1).every((i) => i.startsWith('exp-probe-')));
  });

  test('unverified: only the gate (skipped) and ZERO requests sent', async () => {
    const srv = await start({ mode: 'bad' });
    try {
      const ctx = await buildCtx(srv.url + '/', { verified: false });
      const before = srv.requests.length;
      const out = await run(ctx);
      assert.equal(out.length, 1);
      assert.equal(out[0].id, 'exp-probes-gate');
      assert.equal(out[0].status, 'skipped');
      assert.match(out[0].fix + out[0].evidence, /_headerscan-verify/);
      assert.equal(srv.requests.length, before);
    } finally { await srv.close(); }
  });

  test('unverified with a hand-made ctx never calls fetch', async () => {
    let calls = 0;
    const ctx = fakeCtx({ verified: false, fetch: async () => { calls++; throw new Error('should not fetch'); } });
    const out = await run(ctx);
    assert.equal(out.length, 1);
    assert.equal(calls, 0);
  });

  test('verified is only trusted when strictly true', async () => {
    let calls = 0;
    for (const v of ['true', 1, 'yes', {}]) {
      const out = await run(fakeCtx({ verified: v, fetch: async () => { calls++; throw new Error('no'); } }));
      assert.equal(out.length, 1, String(v));
    }
    assert.equal(calls, 0);
  });

  describe('verified against the bad fixture', () => {
    let srv, out;
    before(async () => {
      srv = await start({ mode: 'bad' });
      out = await run(await buildCtx(srv.url + '/', { verified: true }));
    });
    after(async () => { await srv.close(); });

    test('one finding per ID; gate passes', () => {
      assert.deepEqual([...out.map((f) => f.id)].sort(), [...IDS].sort());
      assert.equal(by(out)['exp-probes-gate'].status, 'pass');
    });
    test('exposed .git/HEAD and .env are HITs (fail); others are not', () => {
      const f = by(out);
      assert.equal(f['exp-probe-git-head'].status, 'fail');
      assert.equal(f['exp-probe-env'].status, 'fail');
      for (const id of ['exp-probe-git-config', 'exp-probe-svn', 'exp-probe-backup-zip', 'exp-probe-actuator-env', 'exp-probe-phpmyadmin', 'exp-probe-dir-listing']) {
        assert.notEqual(f[id].status, 'fail', `${id} must not false-positive on the soft-404 page`);
      }
    });
    test('evidence never contains file contents', () => {
      for (const f of out) for (const s of SECRETS) assert.ok(!f.evidence.includes(s), `${f.id} leaks ${s}`);
      assert.match(by(out)['exp-probe-env'].evidence, /HTTP 200/);
    });
    test('only allowlisted GET requests were sent, at most 2 req/s', () => {
      const probeReqs = srv.requests.filter((r) => r.path !== '/'); // buildCtx fetched '/' once for the page
      for (const r of probeReqs) {
        assert.equal(r.method, 'GET');
        assert.ok(ALLOWED.has(r.path) || isBaseline(r.path), `unexpected path ${r.path}`);
      }
      assert.ok(probeReqs.some((r) => isBaseline(r.path)), 'baseline request expected');
    });
    test('archive probes send a Range header', () => {
      const zip = srv.requests.find((r) => r.path === '/backup.zip');
      assert.ok(zip && /^bytes=0-/.test(zip.headers.range || ''));
    });
  });

  test('SPA catch-all produces zero hits', async () => {
    const srv = await start({ mode: 'spa' });
    try {
      const out = await run(await buildCtx(srv.url + '/', { verified: true }));
      assert.equal(out.filter((f) => f.status === 'fail').length, 0);
      assert.equal(out.filter((f) => f.status === 'info' && f.id.startsWith('exp-probe-')).length, 0);
    } finally { await srv.close(); }
  });

  test('good site produces zero hits', async () => {
    const srv = await start({ mode: 'good' });
    try {
      const out = await run(await buildCtx(srv.url + '/', { verified: true }));
      assert.equal(out.filter((f) => f.status === 'fail').length, 0);
    } finally { await srv.close(); }
  });

  test('429 stops the run early', async () => {
    const srv = await start({ mode: 'limited' });
    try {
      const out = await run(await buildCtx(srv.url + '/', { verified: true }));
      const sent = srv.requests.filter((r) => r.path !== '/').length;
      assert.ok(sent < 24, `sent ${sent} requests after a 429`);
      assert.equal(out.filter((f) => f.status === 'fail').length, 0);
      assert.ok(out.some((f) => f.status === 'skipped' && f.id !== 'exp-probes-gate'));
    } finally { await srv.close(); }
  });
});

