process.env.HEADERSCAN_ALLOW_PRIVATE = '1';
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { makeToken, tokenValid, isVerified, txtNameFor, isSharedHost, getSecret } from '../lib/verify.js';

const secret = 'test-secret-not-real';
const now = 1_700_000_000_000;

describe('tokens', () => {
  test('roundtrip', () => {
    const t = makeToken('example.com', { secret, now });
    assert.equal(t.txtName, '_headerscan-verify.example.com');
    assert.equal(t.txtValue, `headerscan-verify=${t.token}`);
    assert.equal(t.expiresAt, now + 86400000);
    assert.equal(tokenValid('example.com', t.token, { secret, now }), true);
    assert.equal(tokenValid('EXAMPLE.com', t.token, { secret, now }), true);
  });
  test('valid only for the exact host', () => {
    const t = makeToken('example.com', { secret, now });
    assert.equal(tokenValid('www.example.com', t.token, { secret, now }), false);
    assert.equal(tokenValid('other.com', t.token, { secret, now }), false);
  });
  test('expired -> false', () => {
    const t = makeToken('example.com', { secret, now });
    assert.equal(tokenValid('example.com', t.token, { secret, now: now + 86400001 }), false);
  });
  test('wrong secret -> false', () => {
    const t = makeToken('example.com', { secret, now });
    assert.equal(tokenValid('example.com', t.token, { secret: 'other', now }), false);
  });
  test('tampered signature, tampered expiry, garbage -> false', () => {
    const t = makeToken('example.com', { secret, now });
    const [exp, sig] = t.token.split('.');
    const flip = sig[0] === 'A' ? 'B' : 'A';
    assert.equal(tokenValid('example.com', `${exp}.${flip}${sig.slice(1)}`, { secret, now }), false);
    const later = Buffer.from(String(now + 999999999)).toString('base64url');
    assert.equal(tokenValid('example.com', `${later}.${sig}`, { secret, now }), false);
    for (const junk of ['', 'abc', 'a.b', '.', null, undefined, 42]) assert.equal(tokenValid('example.com', junk, { secret, now }), false);
  });
  test('secret is random per process unless env set, and stable within the process', () => {
    assert.equal(getSecret(), getSecret());
    assert.ok(getSecret().length >= 32);
  });
});

describe('isVerified', () => {
  const t = makeToken('example.com', { secret, now });
  const asked = [];
  const txt = (records) => async (name) => { asked.push(name); return records; };

  test('plain, quoted, spaced, and case-insensitive prefix', async () => {
    for (const rec of [t.txtValue, `"${t.txtValue}"`, `  ${t.txtValue}  `, ` "${t.txtValue}" `, t.txtValue.replace('headerscan-verify', 'HeaderScan-Verify')]) {
      assert.equal(await isVerified('example.com', txt(['unrelated', rec]), { secret, now }), true, rec);
    }
    assert.equal(asked[0], txtNameFor('example.com'));
  });
  test('token itself is case-sensitive', async () => {
    const swapped = t.token.replace(/[a-z]/, (c) => c.toUpperCase());
    if (swapped !== t.token) assert.equal(await isVerified('example.com', txt([`headerscan-verify=${swapped}`]), { secret, now }), false);
  });
  test('missing / wrong prefix / other host token -> false', async () => {
    assert.equal(await isVerified('example.com', txt([]), { secret, now }), false);
    assert.equal(await isVerified('example.com', txt([t.token]), { secret, now }), false);
    const other = makeToken('other.com', { secret, now });
    assert.equal(await isVerified('example.com', txt([other.txtValue]), { secret, now }), false);
  });
  test('DNS error -> false, never true', async () => {
    const boom = async () => { throw Object.assign(new Error('SERVFAIL'), { code: 'ESERVFAIL' }); };
    assert.equal(await isVerified('example.com', boom, { secret, now }), false);
  });
  test('expired token in DNS -> false', async () => {
    assert.equal(await isVerified('example.com', txt([t.txtValue]), { secret, now: now + 86400001 }), false);
  });
});

describe('isSharedHost', () => {
  test('deny-list', () => {
    for (const h of ['vercel.app', 'foo.vercel.app', 'a.b.netlify.app', 'x.pages.dev', 'me.github.io', 'x.onrender.com', 'x.herokuapp.com',
      'x.azurewebsites.net', 'x.web.app', 'x.firebaseapp.com', 'x.workers.dev', '8.8.8.8', '::1']) assert.equal(isSharedHost(h), true, h);
    for (const h of ['example.com', 'notvercel.app', 'vercel.app.example.com', 'github.io.example.org']) assert.equal(isSharedHost(h), false, h);
  });
});
