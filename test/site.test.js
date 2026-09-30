process.env.HEADERSCAN_ALLOW_PRIVATE = '1';
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { IDS, run } from '../lib/checks/site.js';
import { start, buildCtx, fakeCtx } from './fixture-server.js';

const by = (fs) => Object.fromEntries(fs.map((f) => [f.id, f]));

describe('site.js', () => {
  test('IDS: 16 unique', () => assert.equal(new Set(IDS).size, 16));

  test('unreachable site never throws and still returns every ID', async () => {
    const boom = async () => { throw Object.assign(new Error('x'), { code: 'NETWORK' }); };
    const out = await run(fakeCtx({ url: 'https://example.test/', fetch: boom }));
    assert.deepEqual([...out.map((f) => f.id)].sort(), [...IDS].sort());
  });

  describe('bad fixture', () => {
    let srv, f, out;
    before(async () => { srv = await start({ mode: 'bad' }); out = await run(await buildCtx(srv.url + '/')); f = by(out); });
    after(async () => { await srv.close(); });
    test('one finding per ID', () => assert.deepEqual([...out.map((x) => x.id)].sort(), [...IDS].sort()));
    test('robots.txt: exists, does not block everyone, but blocks GPTBot', () => {
      assert.equal(f['seo-robots-txt'].status, 'pass');
      assert.equal(f['ai-robots-blocks-all'].status, 'pass');
      assert.equal(f['ai-robots-blocks-bots'].status, 'warn');
      assert.match(f['ai-robots-blocks-bots'].evidence, /GPTBot/);
    });
    test('no sitemap and no llms.txt (soft-404 body must not count)', () => {
      assert.equal(f['seo-sitemap'].status, 'warn');
      assert.equal(f['ai-llms-txt'].status, 'warn');
    });
    test('soft 404 is detected', () => assert.equal(f['ux-404-page'].status, 'fail'));
    test('local hostname is not a default hosting hostname', () => assert.equal(f['ux-default-hostname'].status, 'pass'));
    test('no stack trace in the soft-404 body', () => assert.equal(f['exp-error-leak'].status, 'pass'));
    test('no evidence contains response bodies of probes-like secrets', () => {
      for (const x of out) assert.ok(!/SECRET_KEY|DB_PASSWORD/.test(x.evidence), x.id);
    });
  });

  describe('good fixture', () => {
    let srv, f, out;
    before(async () => { srv = await start({ mode: 'good' }); out = await run(await buildCtx(srv.url + '/')); f = by(out); });
    after(async () => { await srv.close(); });
    test('everything site-level passes', () => {
      for (const id of ['seo-robots-txt', 'ai-robots-blocks-all', 'ai-robots-blocks-bots', 'seo-sitemap', 'ai-llms-txt', 'ux-404-page', 'ux-favicon', 'ux-default-hostname', 'exp-security-txt', 'exp-security-txt-fields', 'exp-error-leak']) {
        assert.equal(f[id].status, 'pass', `${id}: ${f[id].evidence}`);
      }
    });
    test('crawled pages have unique titles', () => assert.ok(['pass', 'info'].includes(f['seo-duplicate-titles'].status)));
  });

  describe('spa fixture', () => {
    test('catch-all HTML at /robots.txt is a failure, not a pass', async () => {
      const srv = await start({ mode: 'spa' });
      try {
        const f = by(await run(await buildCtx(srv.url + '/')));
        assert.equal(f['seo-robots-txt'].status, 'fail');
        assert.notEqual(f['ai-llms-txt'].status, 'pass');
        assert.equal(f['ux-404-page'].status, 'fail');
      } finally { await srv.close(); }
    });
  });
});
