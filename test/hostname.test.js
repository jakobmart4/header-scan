// ux-default-hostname: label-bounded suffix match on the final hostname (trailing dot ignored), no network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { run } from '../lib/checks/site.js';
import { fakeCtx } from './fixture-server.js';

const check = async (url) => (await run(fakeCtx({ url }))).find((f) => f.id === 'ux-default-hostname');

const WARN = [
  ['https://header-scan.acme.workers.dev/', 'header-scan.acme.workers.dev'],
  ['https://shop.vercel.app/', 'shop.vercel.app'],
  ['https://a.b.pages.dev:8443/p?q=1', 'a.b.pages.dev'],
  ['https://X.Vercel.APP/', 'x.vercel.app'],
  ['https://x.vercel.app./', 'x.vercel.app'],
  ['https://my-app.fly.dev/', 'my-app.fly.dev'],
  ['https://my-app.up.railway.app/', 'my-app.up.railway.app'],
  ['https://myproj.firebaseapp.com/', 'myproj.firebaseapp.com'],
  ['https://myproj.appspot.com/', 'myproj.appspot.com'],
  ['https://app.azurewebsites.net/', 'app.azurewebsites.net'],
  ['https://d111111abcdef8.cloudfront.net/', 'd111111abcdef8.cloudfront.net'],
  ['https://dave.wixsite.com/portfolio', 'dave.wixsite.com'],
  ['https://blog.blogspot.com/', 'blog.blogspot.com'],
];
const PASS = [
  ['https://myvercel.app/', 'myvercel.app'],
  ['https://vercel.app/', 'vercel.app'],
  ['https://workers.dev/', 'workers.dev'],
  ['https://x.vercel.app.evil.example/', 'x.vercel.app.evil.example'],
  ['https://notfly.dev/', 'notfly.dev'],
  ['https://docs.railway.app/', 'docs.railway.app'],
  ['https://support.squarespace.com/', 'support.squarespace.com'],
  ['https://developer.wordpress.com/', 'developer.wordpress.com'],
  ['https://example.com/', 'example.com'],
  ['https://localhost:3000/', 'localhost'],
];

for (const [url, host] of WARN) {
  test(`ux-default-hostname warns: ${url}`, async () => {
    const f = await check(url);
    assert.equal(f.status, 'warn');
    assert.equal(f.evidence, `served from ${host}`);
  });
}
for (const [url, host] of PASS) {
  test(`ux-default-hostname passes: ${url}`, async () => {
    const f = await check(url);
    assert.equal(f.status, 'pass');
    assert.equal(f.evidence, host);
  });
}

test('ux-default-hostname: a hostname of 200k dots is stripped in linear time', async () => {
  const url = `https://x${'.'.repeat(200000)}a.vercel.app${'.'.repeat(200000)}/`;
  const t = Date.now();
  const f = await check(url);
  assert.ok(Date.now() - t < 2000, `took ${Date.now() - t} ms`);
  assert.equal(f.status, 'warn');
  assert.match(f.evidence, /^served from x\./); // evidence is capped at 300 chars by score.js, so the tail is not checked here
});

test('ux-default-hostname: only trailing dots are stripped, inner dot runs stay', async () => {
  const f = await check('https://x..vercel.app.../');
  assert.equal(f.status, 'warn');
  assert.equal(f.evidence, 'served from x..vercel.app');
});
