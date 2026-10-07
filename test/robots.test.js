// robots.txt verdicts under RFC 9309 matching: longest pattern wins, Allow wins a tie, `*` and trailing `$`,
// product tokens matched exactly and case-insensitively, same-name groups merged, `*` as the fallback group.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { run, parseRobots } from '../lib/checks/site.js';
import { fakeCtx } from './fixture-server.js';

const URL0 = 'https://example.test/';
const by = (fs) => Object.fromEntries(fs.map((f) => [f.id, f]));
const res = (status, body, u) => ({ status, headers: { 'content-type': 'text/plain' }, body, finalUrl: u, timingMs: 1, redirects: [], truncated: false });
const robots = async (body) => {
  const fetch = async (u) => (new URL(u).pathname === '/robots.txt' ? res(200, body, u) : res(404, '', u));
  return by(await run(fakeCtx({ url: URL0, body: '<!doctype html><html lang="en"><head><title>T</title></head><body>hi</body></html>', fetch })));
};
// [robots.txt, blocks-all status, blocks-bots status, blocks-bots evidence regex?]
const check = async (body, all, bots, ev) => {
  const f = await robots(body);
  assert.equal(f['ai-robots-blocks-all'].status, all, `blocks-all ${JSON.stringify(body)}: ${f['ai-robots-blocks-all'].evidence}`);
  assert.equal(f['ai-robots-blocks-bots'].status, bots, `blocks-bots ${JSON.stringify(body)}: ${f['ai-robots-blocks-bots'].evidence}`);
  if (ev) assert.match(f['ai-robots-blocks-bots'].evidence, ev);
  return f;
};
const ALL10 = 'GPTBot, ChatGPT-User, OAI-SearchBot, ClaudeBot, Claude-Web, anthropic-ai, PerplexityBot, Google-Extended, CCBot, Bytespider';

describe('robots.txt RFC 9309 matching', () => {
  test('excalidraw: Allow /$ and Allow / beat Disallow / in the wildcard group; empty Disallow matches nothing', async () => {
    const body = 'User-agent: Twitterbot\nDisallow:\n\nUser-agent: facebookexternalhit\nDisallow:\n\nUser-agent: *\nAllow: /$\nAllow: /\nAllow: /sitemap.xml\nDisallow: /\n\nSitemap: https://example.test/sitemap.xml\n';
    const f = await check(body, 'pass', 'pass', /^no AI crawler blocked$/);
    assert.equal(f['ai-robots-blocks-all'].evidence, 'not blocked');
  });
  test('a pure tie: Allow wins regardless of line order', async () => {
    await check('User-agent: *\nDisallow: /\nAllow: /\n', 'pass', 'pass');
    await check('User-agent: *\nAllow: /\nDisallow: /\n', 'pass', 'pass');
  });
  test('wildcard Disallow: / fails blocks-all and blocks every AI bot via User-agent: *', async () => {
    const f = await check('User-agent: *\nDisallow: /\n', 'fail', 'warn', new RegExp(`^disallowed: ${ALL10} \\(10 via User-agent: \\*\\)$`));
    assert.equal(f['ai-robots-blocks-all'].evidence, 'User-agent: * disallows the whole site');
  });
  test('the longer pattern wins: Disallow /* beats Allow /, Allow /* beats Disallow /', async () => {
    await check('User-agent: *\nAllow: /\nDisallow: /*\n', 'fail', 'warn');
    await check('User-agent: *\nDisallow: /\nAllow: /*\n', 'pass', 'pass');
  });
  test('home page only (Allow /$ + Disallow /) is not a whole-site block; Disallow /$ honours the anchor', async () => {
    await check('User-agent: *\nAllow: /$\nDisallow: /\n', 'pass', 'pass');
    await check('User-agent: *\nDisallow: /$\n', 'pass', 'pass');
  });
  test('empty Disallow matches nothing; Disallow: * matches everything', async () => {
    await check('User-agent: *\nDisallow:\n', 'pass', 'pass');
    await check('User-agent: *\nDisallow: *\n', 'fail', 'warn', /10 via User-agent: \*/);
  });
  test('a bot with its own group obeys only that group', async () => {
    const f = await check('User-agent: *\nDisallow: /\n\nUser-agent: GPTBot\nAllow: /\n', 'fail', 'warn', /\(9 via User-agent: \*\)$/);
    assert.doesNotMatch(f['ai-robots-blocks-bots'].evidence, /GPTBot/);
  });
  test('an own-group block has no via suffix', async () => {
    const f = await check('User-agent: GPTBot\nDisallow: /\n', 'pass', 'warn', /^disallowed: GPTBot$/);
    assert.doesNotMatch(f['ai-robots-blocks-bots'].evidence, /via/);
  });
  test('keys and agents are case-insensitive; shared groups; same-name groups merge', async () => {
    await check('user-agent: gptbot\nUSER-AGENT: ClaudeBot\nDISALLOW: /\n\nUser-agent: CCBot\nAllow: /x\n\nUser-agent: ccbot\nDisallow: /\n', 'pass', 'warn', /^disallowed: GPTBot, ClaudeBot, CCBot$/);
  });
  test('BOM, CRLF and trailing comments', async () => {
    const f = await check('﻿User-agent: * # all\r\nDisallow: / # nope\r\n', 'fail', 'warn');
    assert.equal(f['seo-robots-txt'].status, 'pass');
    // a BOM file whose only directive is on line 1 is still valid
    assert.equal((await robots('﻿Sitemap: https://example.test/s.xml'))['seo-robots-txt'].status, 'pass');
  });
  test('lone CR line endings', async () => {
    await check('User-agent: *\rDisallow: /\r', 'fail', 'warn');
  });
  test('a Sitemap line does not end a User-agent run (RFC 9309 s2.2.4)', async () => {
    await check('User-agent: GPTBot\nSitemap: https://example.test/s.xml\nUser-agent: ClaudeBot\nDisallow: /\n', 'pass', 'warn', /^disallowed: GPTBot, ClaudeBot$/);
  });
  test('the product token is the leading [a-z_-] run of the value', async () => {
    await check('User-agent: GPTBot/1.2\nDisallow: /\n', 'pass', 'warn', /^disallowed: GPTBot$/);
    assert.deepEqual(parseRobots('User-agent: GPTBot/1.2\nUser-agent: *foo\nUser-agent: *\n').groups[0].agents, ['gptbot', '', '*']);
  });
  test('no prefix or substring matching of product tokens', async () => {
    await check('User-agent: GPT\nDisallow: /\nUser-agent: GPTBot-Next\nDisallow: /\n', 'pass', 'pass');
  });
  test('rules outside a group are ignored', async () => {
    await check('Disallow: /\nUser-agent: *\nAllow: /\n', 'pass', 'pass');
    await check('Disallow: /private\n', 'pass', 'pass');
  });
  test('a mid-path $ pattern and a narrow Allow', async () => {
    await check('User-agent: *\nDisallow: /*.html$\n', 'pass', 'pass');
    await check('User-agent: *\nDisallow: /\nAllow: /x\n', 'fail', 'warn');
  });
  test('parseRobots keeps Allow and Disallow per group', () => {
    assert.deepEqual(parseRobots('User-agent: a\nAllow: /x\nDisallow: /y\n').groups, [{ agents: ['a'], allow: ['/x'], disallow: ['/y'] }]);
  });
  test('hostile wildcard patterns stay fast', async () => {
    for (const body of [`User-agent: *\nDisallow: ${'*'.repeat(20000)}q\n`, `User-agent: *\n${'Disallow: /*a*a*a*a*a*a*a*a*a*b\n'.repeat(8000)}`]) {
      const t0 = performance.now();
      await robots(body);
      assert.ok(performance.now() - t0 < 3000, `${Math.round(performance.now() - t0)} ms`);
    }
  });
});

describe('robots.txt: review regressions', () => {
  test('an Allow that is not the home page is an exception, not an unblock (no probe-path collision)', async () => {
    for (const allow of ['/pr', '/p', '/probe', '/public/']) {
      const f = await check(`User-agent: *\nDisallow: /\nAllow: ${allow}\n`, 'fail', 'warn', /10 via User-agent: \*/);
      assert.equal(f['ai-robots-blocks-all'].evidence, 'User-agent: * disallows the whole site except 1 Allow path(s)');
    }
  });
  test('narrow Disallows never add up to a whole-site block', async () => {
    await check('User-agent: *\nDisallow: /$\nDisallow: /p\n', 'pass', 'pass');
    await check('User-agent: *\nDisallow: /blog/\nDisallow: /*.pdf$\n', 'pass', 'pass');
  });
  test('catch-all patterns: /*$ and */ cover every path; /$ and */$ do not', async () => {
    await check('User-agent: *\nDisallow: /*$\n', 'fail', 'warn');
    await check('User-agent: *\nDisallow: */\n', 'fail', 'warn');
    await check('User-agent: *\nDisallow: /$\n', 'pass', 'pass');
    await check('User-agent: *\nDisallow: */$\n', 'pass', 'pass');
  });
  test('a truncated robots.txt drops its partial last line; it is read with a 500 KB cap', async () => {
    const full = `User-agent: *\n${'Disallow: /zz\n'.repeat(100)}Disallow: /admin\n`;
    const cut = full.slice(0, full.lastIndexOf('/admin') + 1); // ends in "Disallow: /"
    let cap;
    const fetch = async (u, o = {}) => {
      if (new URL(u).pathname !== '/robots.txt') return res(404, '', u);
      cap = o.maxBytes;
      return { ...res(200, cut, u), truncated: true };
    };
    const f = by(await run(fakeCtx({ url: URL0, body: '<!doctype html><title>T</title>', fetch })));
    assert.equal(f['ai-robots-blocks-all'].status, 'pass', f['ai-robots-blocks-all'].evidence);
    assert.equal(f['ai-robots-blocks-bots'].status, 'pass');
    assert.equal(cap, 512000);
  });
});
