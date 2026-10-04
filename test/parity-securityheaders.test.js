// Parity with SecurityHeaders.com: the real headers of securityheaders.com (grade A+ there) run through
// headers + cookies + csp. Expectations = docs/specs/PARITY-SPEC.md section 4 (statuses) and 5/6 (score, rawHeaders).
process.env.HEADERSCAN_ALLOW_PRIVATE = '1';
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { run as runHeaders, IDS as HEADER_IDS } from '../lib/checks/headers.js';
import { run as runCookies, IDS as COOKIE_IDS } from '../lib/checks/cookies.js';
import { run as runCsp, IDS as CSP_IDS } from '../lib/checks/csp.js';
import { score } from '../lib/score.js';
import { buildRawHeaders } from '../lib/scan.js';
import { fakeCtx } from './fixture-server.js';

const FIX = JSON.parse(readFileSync(new URL('./fixtures/securityheaders-com.json', import.meta.url), 'utf8')).headers;
const URL_ = 'https://securityheaders.com/';
const COOKIE_VALUE = '3ca967900934bcbf8d24e9d95ea5a267';
const PAGE = '<!doctype html><html lang="en"><head><title>Fixture</title></head><body><h1>Fixture</h1></body></html>';

// Same shape the orchestrator builds: set-cookie is an array, every other header a string.
const fixtureCtx = () => fakeCtx({
  url: URL_,
  headers: { ...FIX, 'set-cookie': [FIX['set-cookie']] },
  body: PAGE,
  fetch: async (u) => ({ status: 200, headers: { ...FIX }, body: '', finalUrl: String(u), timingMs: 1, redirects: [], truncated: false }),
});

// Section 4: every id not listed is `pass`.
const EXPECT = {
  fail: ['cookie-secure'],
  warn: ['hdr-powered-by', 'hdr-cache-control-html', 'cookie-httponly', 'cookie-samesite', 'cookie-cache-control', 'csp-object-src', 'csp-base-uri',
    'csp-frame-ancestors', 'csp-style-unsafe-inline', 'hdr-xss-protection', 'cors-wildcard-public'],
  info: ['hdr-coop', 'hdr-coep', 'hdr-corp', 'cookie-prefix', 'csp-upgrade-insecure', 'hdr-legacy-headers', 'hdr-reporting'],
};
const expected = (id) => Object.keys(EXPECT).find((st) => EXPECT[st].includes(id)) || 'pass';

describe('securityheaders.com fixture', () => {
  let all, ctx, by;
  const load = async () => {
    if (all) return;
    ctx = fixtureCtx();
    all = [...await runHeaders(ctx), ...await runCookies(ctx), ...await runCsp(ctx)];
    by = Object.fromEntries(all.map((f) => [f.id, f]));
  };

  test('46 findings, one per id of the three modules', async () => {
    await load();
    assert.equal(all.length, HEADER_IDS.length + COOKIE_IDS.length + CSP_IDS.length);
    assert.equal(all.length, 46);
    assert.equal(new Set(all.map((f) => f.id)).size, 46);
  });

  test('status of EVERY finding matches PARITY-SPEC section 4', async () => {
    await load();
    for (const f of all) assert.equal(f.status, expected(f.id), `${f.id}: ${f.evidence}`);
  });

  test('every id named in the expectation table exists (no typos)', async () => {
    await load();
    for (const id of Object.values(EXPECT).flat()) assert.ok(by[id], id);
  });

  test('COOP/COEP report-only are recognised, CORP is plainly absent', async () => {
    await load();
    assert.match(by['hdr-coop'].evidence, /report-only, not enforced/);
    assert.match(by['hdr-coep'].evidence, /report-only, not enforced/);
    assert.match(by['hdr-corp'].evidence, /header absent/);
  });

  test('reporting is info, names the channels and only the endpoint host', async () => {
    await load();
    const ev = by['hdr-reporting'].evidence;
    assert.equal(by['hdr-reporting'].status, 'info');
    for (const c of ['Report-To', 'NEL', 'CSP report-uri', 'CSP report-to']) assert.ok(ev.includes(c), `${c} in ${ev}`);
    assert.ok(ev.includes('scotthelme.report-uri.com'), ev);
    assert.ok(!ev.includes('/r/d/csp/enforce') && !ev.includes('/a/d/g'), 'no endpoint paths');
  });

  test('new checks name what they saw on the fixture', async () => {
    await load();
    assert.match(by['hdr-xss-protection'].evidence, /^X-XSS-Protection: 1$/);
    assert.ok(!by['hdr-xss-protection'].evidence.includes('report='), 'report URL never echoed');
    assert.match(by['hdr-legacy-headers'].evidence, /expect-ct/);
    assert.ok(!by['hdr-legacy-headers'].evidence.includes('max-age'), 'legacy header values never echoed');
    assert.match(by['csp-style-unsafe-inline'].evidence, /style-src/);
  });

  test('csp-script-bypass-hosts: recaptcha paths, googletagmanager and a style-src cdnjs are not hits', async () => {
    await load();
    assert.equal(by['csp-script-bypass-hosts'].status, 'pass', by['csp-script-bypass-hosts'].evidence);
  });

  test('no finding leaks the cookie value', async () => {
    await load();
    assert.ok(!JSON.stringify(all).includes(COOKIE_VALUE));
    assert.match(by['cookie-secure'].evidence, /anti_forgery_cookie/); // names are fine
  });

  test('score: security 84 / C (capped by the cookie-secure fail), headers 88, cookies unchanged', async () => {
    await load();
    const s = score(all);
    assert.deepEqual(s.security, { score: 84, grade: 'C', cappedBy: ['cookie-secure'] });
    assert.deepEqual(s.categories.headers, { score: 88, pass: 21, warn: 8, fail: 0, info: 6, skipped: 0 });
    assert.deepEqual(s.categories.cookies, { score: 58, pass: 3, warn: 3, fail: 1, info: 1, skipped: 0 });
  });

  test('info findings (reporting, report-only COOP/COEP, legacy list) are never counted', async () => {
    await load();
    assert.deepEqual(score(all.filter((f) => f.status !== 'info')).security, score(all).security);
  });

  test('rawHeaders of the fixture: 25 entries in arrival order, cookie redacted, CSP cut', async () => {
    await load();
    const raw = buildRawHeaders(ctx.page.headers);
    assert.equal(raw.length, 25);
    assert.equal(raw[0].name, 'content-type');
    assert.deepEqual(raw.map((r) => r.name), Object.keys(ctx.page.headers));
    for (const r of raw) {
      assert.deepEqual(Object.keys(r), ['name', 'value']);
      assert.equal(r.name, r.name.toLowerCase());
      assert.equal(typeof r.value, 'string');
    }
    const cookie = raw.find((r) => r.name === 'set-cookie');
    assert.equal(cookie.value, 'anti_forgery_cookie=<redacted>; expires=Wed, 30 Sep 2026 13:12:15 GMT; Max-Age=7200; path=/');
    const json = JSON.stringify(raw);
    assert.ok(!json.includes(COOKIE_VALUE));
    assert.ok(json.includes('Max-Age=7200'));
    const csp = raw.find((r) => r.name === 'content-security-policy');
    assert.equal(FIX['content-security-policy'].length, 713);
    assert.equal(csp.value.length, 512);
    assert.ok(csp.value.endsWith('...'));
    assert.equal(raw.find((r) => r.name === 'strict-transport-security').value, FIX['strict-transport-security']);
    assert.equal(raw.find((r) => r.name === 'x-xss-protection').value, FIX['x-xss-protection']);
  });
});
