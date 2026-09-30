process.env.HEADERSCAN_ALLOW_PRIVATE = '1';
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { IDS, run } from '../lib/checks/cookies.js';
import { fakeCtx, start, buildCtx } from './fixture-server.js';

const by = (fs) => Object.fromEntries(fs.map((f) => [f.id, f.status]));
const withCookies = (list, extra = {}) => fakeCtx({ headers: { 'set-cookie': list, ...extra } });

describe('cookies.js', () => {
  test('exactly the owned IDs, once each', async () => {
    for (const ctx of [fakeCtx({}), withCookies(['a=1'])]) {
      const out = await run(ctx);
      assert.deepEqual([...out.map((f) => f.id)].sort(), [...IDS].sort());
    }
  });
  test('no cookies -> info', async () => {
    const s = by(await run(fakeCtx({})));
    for (const id of ['cookie-secure', 'cookie-httponly', 'cookie-samesite', 'cookie-samesite-none', 'cookie-domain', 'cookie-lifetime', 'cookie-cache-control']) assert.equal(s[id], 'info', id);
  });
  test('bare session cookie on https fails Secure and HttpOnly, warns SameSite', async () => {
    const s = by(await run(withCookies(['sessionid=abc; Path=/'])));
    assert.equal(s['cookie-secure'], 'fail');
    assert.equal(s['cookie-httponly'], 'fail');
    assert.equal(s['cookie-samesite'], 'warn');
  });
  test('non-session cookie without HttpOnly only warns', async () => {
    assert.equal(by(await run(withCookies(['theme=dark; Secure; SameSite=Lax'])))['cookie-httponly'], 'warn');
  });
  test('well-formed cookie passes', async () => {
    const s = by(await run(withCookies(['sessionid=abc; Path=/; Secure; HttpOnly; SameSite=Strict'])));
    assert.equal(s['cookie-secure'], 'pass');
    assert.equal(s['cookie-httponly'], 'pass');
    assert.equal(s['cookie-samesite'], 'pass');
    assert.equal(s['cookie-samesite-none'], 'pass');
    assert.equal(s['cookie-domain'], 'pass');
    assert.equal(s['cookie-lifetime'], 'pass');
  });
  test('SameSite=None without Secure fails', async () => {
    assert.equal(by(await run(withCookies(['a=1; SameSite=None'])))['cookie-samesite-none'], 'fail');
  });
  test('__Host- prefix: valid passes, invalid warns', async () => {
    assert.equal(by(await run(withCookies(['__Host-sid=1; Secure; Path=/; HttpOnly'])))['cookie-prefix'], 'pass');
    assert.equal(by(await run(withCookies(['__Host-sid=1; Secure; Path=/app; Domain=example.test'])))['cookie-prefix'], 'warn');
    assert.equal(by(await run(withCookies(['a=1'])))['cookie-prefix'], 'info');
  });
  test('Domain attribute and long lifetime on session cookies warn', async () => {
    assert.equal(by(await run(withCookies(['sessionid=1; Domain=example.test; Secure; HttpOnly'])))['cookie-domain'], 'warn');
    assert.equal(by(await run(withCookies(['sessionid=1; Max-Age=99999999; Secure; HttpOnly'])))['cookie-lifetime'], 'warn');
  });
  test('cookie on a publicly cacheable page warns', async () => {
    assert.equal(by(await run(withCookies(['a=1'], { 'cache-control': 'public, max-age=600' })))['cookie-cache-control'], 'warn');
  });
  test('evidence names cookies but never their values', async () => {
    const out = await run(withCookies(['sessionid=SUPERSECRETVALUE; Path=/']));
    for (const f of out) assert.ok(!f.evidence.includes('SUPERSECRETVALUE'), f.id);
    assert.ok(out.some((f) => f.evidence.includes('sessionid')));
  });
  test('fixture bad site', async () => {
    const srv = await start({ mode: 'bad' });
    try {
      const s = by(await run(await buildCtx(srv.url + '/')));
      assert.equal(s['cookie-httponly'], 'fail');
      assert.equal(s['cookie-samesite'], 'warn');
    } finally { await srv.close(); }
  });
});
