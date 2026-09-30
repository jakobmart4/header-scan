// Regression tests for the second review round (docs/PARITY-SPEC.md section 10): each fix has a pass and a non-pass case.
process.env.HEADERSCAN_ALLOW_PRIVATE = '1';
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { run as runCsp, bypassHits } from '../lib/checks/csp.js';
import { run as runHeaders } from '../lib/checks/headers.js';
import { run as runCookies } from '../lib/checks/cookies.js';
import { run as runDns } from '../lib/checks/dns.js';
import { run as runHtml } from '../lib/checks/html.js';
import { run as runTls } from '../lib/checks/tls.js';
import { buildRawHeaders } from '../lib/scan.js';
import { fakeCtx, stubResolve } from './fixture-server.js';

const byId = (fs) => Object.fromEntries(fs.map((f) => [f.id, f]));
const res = (status, headers = {}, body = '') => async (u) => ({ status, headers, body, finalUrl: String(u), timingMs: 1, redirects: [], truncated: false });
const C = async (policy, o = {}) => byId(await runCsp(fakeCtx({ headers: policy == null ? {} : { 'content-security-policy': policy }, ...o })));
const H = async (headers = {}, o = {}) => byId(await runHeaders(fakeCtx({ headers, fetch: res(200), ...o })));
const raw = (headers, name = 'set-cookie') => buildRawHeaders(headers).filter((r) => r.name === name).map((r) => r.value);

describe('bypass hosts: concrete Google API hosts', () => {
  test('maps/translate/mts0/mts1.googleapis.com are host-level hits', async () => {
    for (const h of ['maps.googleapis.com', 'translate.googleapis.com', 'mts0.googleapis.com', 'https://mts1.googleapis.com']) {
      assert.equal(bypassHits([h])[0]?.level, 'host', h);
      assert.equal((await C(`script-src ${h}`))['csp-script-bypass-hosts'].status, 'warn', h);
    }
  });
  test('other googleapis hosts (fonts) and a path-scoped Maps loader are not host-level', async () => {
    assert.deepEqual(bypassHits(['fonts.googleapis.com']), []);
    assert.equal(bypassHits(['maps.googleapis.com/maps/api/js'])[0].level, 'path');
  });
});

describe('bypassHits: path case and bare-TLD wildcards', () => {
  test('path matching is case-sensitive, host is not', () => {
    assert.deepEqual(bypassHits(['https://www.google.com/RECAPTCHA/']), []);
    assert.equal(bypassHits(['WWW.GOOGLE.COM/recaptcha/'])[0].level, 'host');
  });
  test('bare-TLD wildcards are csp-wildcard material, not bypass hosts', async () => {
    for (const s of ['*.net', '*.com', 'https://*.net:443']) assert.deepEqual(bypassHits([s]), [], s);
    assert.equal(bypassHits(['*.cloudfront.net'])[0].level, 'host'); // a real wildcard host still hits
    const c = await C('script-src *.net');
    assert.equal(c['csp-wildcard'].status, 'fail');
    assert.equal(c['csp-script-bypass-hosts'].status, 'pass');
    assert.equal((await C("script-src 'self' *.example.com"))['csp-wildcard'].status, 'pass');
  });
  test('path-scoped hits do not claim the host serves AngularJS', async () => {
    const f = (await C('script-src cdnjs.cloudflare.com/ajax/libs/jquery/'))['csp-script-bypass-hosts'];
    assert.equal(f.status, 'info');
    assert.match(f.evidence, /open-redirect risk only/);
    assert.ok(!/AngularJS/.test(f.evidence), f.evidence);
    assert.match((await C('script-src cdnjs.cloudflare.com'))['csp-script-bypass-hosts'].evidence, /AngularJS/); // whole host keeps the reason
  });
});

describe('multiple CSP policies (comma-joined duplicate headers)', () => {
  test('a problem counts only if every policy has it', async () => {
    const lax = "script-src 'self' 'unsafe-inline'";
    let c = await C(`${lax}, script-src 'nonce-abc'`);
    assert.equal(c['csp-unsafe-inline'].status, 'pass'); // the second policy forbids inline script
    assert.match(c['csp-present'].evidence, /2 policies/);
    c = await C(`${lax}, ${lax}`);
    assert.equal(c['csp-unsafe-inline'].status, 'fail');
    assert.equal((await C(`script-src cdnjs.cloudflare.com, script-src 'self'`))['csp-script-bypass-hosts'].status, 'pass');
    assert.equal((await C('script-src cdnjs.cloudflare.com, script-src cdn.jsdelivr.net'))['csp-script-bypass-hosts'].status, 'warn');
  });
  test('a policy without the relevant directive does not vouch for another (frame-ancestors-only add-on)', async () => {
    const c = await C("script-src 'self' 'unsafe-inline' cdnjs.cloudflare.com; object-src 'none', frame-ancestors 'none'");
    assert.equal(c['csp-unsafe-inline'].status, 'fail');
    assert.equal(c['csp-script-bypass-hosts'].status, 'warn');
    assert.equal(c['csp-frame-ancestors'].status, 'pass'); // presence in any policy counts
    assert.equal(c['csp-object-src'].status, 'pass');
  });
  test('an empty leading element is skipped; an all-empty header is "no CSP"', async () => {
    const c = await C(', script-src cdnjs.cloudflare.com');
    assert.equal(c['csp-present'].status, 'pass');
    assert.equal(c['csp-script-bypass-hosts'].status, 'warn'); // evaluated, not skipped
    const none = await C(' , ');
    assert.equal(none['csp-present'].status, 'fail');
    assert.equal(none['csp-unsafe-inline'].status, 'skipped');
  });
  test('single policy keeps its plain evidence', async () => {
    assert.equal((await C("default-src 'self'"))['csp-present'].evidence, 'enforced header present');
  });
});

describe('csp-style-unsafe-inline: style attributes fall back to style-src, not style-src-elem', () => {
  test('locked style-src-elem with open style-src is info, not pass', async () => {
    const f = (await C("style-src 'unsafe-inline'; style-src-elem 'self'"))['csp-style-unsafe-inline'];
    assert.equal(f.status, 'info');
    assert.match(f.evidence, /style attributes/);
  });
  test('pass when style-src-attr closes the gap or style-src is clean', async () => {
    assert.equal((await C("style-src 'unsafe-inline'; style-src-elem 'self'; style-src-attr 'none'"))['csp-style-unsafe-inline'].status, 'pass');
    assert.equal((await C("style-src 'self'; style-src-elem 'self'"))['csp-style-unsafe-inline'].status, 'pass');
  });
});

describe('hdr-reporting: hosts only, never URL userinfo', () => {
  test('userinfo (key, user:pass) is dropped, the real host is kept', async () => {
    const f = (await H({
      'report-to': '{"group":"d","endpoints":[{"url":"https://tok:pw@r.example/a"}]}',
      'content-security-policy': "default-src 'self'; report-uri https://PUBLICKEY123@o1.ingest.sentry.io/api/1/security/?sentry_key=SECRETK",
    }))['hdr-reporting'];
    assert.match(f.evidence, /r\.example/);
    assert.match(f.evidence, /o1\.ingest\.sentry\.io/);
    assert.ok(!/tok|pw|publickey|SECRETK/i.test(f.evidence.replace('Report-To', '')), f.evidence);
  });
  test('IDN hosts come out as punycode, bracketed IPv6 is kept', async () => {
    const f = (await H({ 'report-to': '{"a":"https://münchen.example/x","b":"https://[2001:db8::1]/y"}' }))['hdr-reporting'];
    assert.match(f.evidence, /xn--mnchen-3ya\.example/);
    assert.match(f.evidence, /\[2001:db8::1\]/);
  });
});

describe('nameless cookies never leak their value', () => {
  test('rawHeaders: empty name, value redacted', () => {
    assert.deepEqual(raw({ 'set-cookie': ['SECRETVALUE123; Secure; HttpOnly'] }), ['=<redacted>; Secure; HttpOnly']);
    assert.deepEqual(raw({ 'set-cookie': ['n=SECRETVALUE123; Secure'] }), ['n=<redacted>; Secure']); // named cookies unchanged
  });
  test('cookie findings list it as (unnamed), not by value', async () => {
    const out = await runCookies(fakeCtx({ headers: { 'set-cookie': ['SECRETVALUE123; HttpOnly'] } }));
    const s = byId(out)['cookie-secure'];
    assert.equal(s.status, 'fail');
    assert.match(s.evidence, /\(unnamed\)/);
    assert.ok(!JSON.stringify(out).includes('SECRETVALUE123'));
  });
});

describe('rawHeaders cookie attributes: only shapes that cannot carry identifiers', () => {
  test('Path other than "/" and every Domain are redacted, flags and enumerations survive', () => {
    assert.deepEqual(raw({ 'set-cookie': ['a=x; Path=/reset/SECRETTOKEN; Domain=SECRET.example; Secure; SameSite=Lax; Max-Age=60'] }),
      ['a=<redacted>; Path=<redacted>; Domain=<redacted>; Secure; SameSite=Lax; Max-Age=60']);
    assert.deepEqual(raw({ 'set-cookie': ['a=x; Path=/'] }), ['a=<redacted>; Path=/']);
  });
  test('malformed values of the kept attributes are redacted too', () => {
    const v = raw({ 'set-cookie': ['a=x; SameSite=LEAK1; Max-Age=LEAK2; Expires=LEAK3; Priority=LEAK4; Secure=LEAK5'] })[0];
    assert.ok(!/LEAK/.test(v), v);
    assert.equal(v, 'a=<redacted>; SameSite=<redacted>; Max-Age=<redacted>; Expires=<redacted>; Priority=<redacted>; Secure');
  });
  test('a well-formed Expires date is kept', () => {
    assert.equal(raw({ 'set-cookie': ['a=x; Expires=Wed, 30 Sep 2026 13:12:15 GMT'] })[0], 'a=<redacted>; Expires=Wed, 30 Sep 2026 13:12:15 GMT');
  });
});

describe('rawHeaders: a cookie flood cannot hide the other headers', () => {
  const flood = { 'content-type': 'text/html', 'set-cookie': Array.from({ length: 100 }, (_, i) => `c${i}=1`), 'strict-transport-security': 'max-age=1', 'content-security-policy': "default-src 'self'" };
  test('cookie lines are capped separately and a marker row says so', () => {
    const r = buildRawHeaders(flood);
    const names = r.map((x) => x.name);
    assert.ok(names.includes('strict-transport-security') && names.includes('content-security-policy'));
    assert.equal(r.filter((x) => x.name === 'set-cookie').length, 20);
    assert.deepEqual(r.at(-1), { name: '(truncated)', value: '80 more header/cookie line(s) not shown' });
    assert.ok(r.length <= 80);
  });
  test('no overflow, no marker', () => {
    assert.ok(!buildRawHeaders({ a: '1', 'set-cookie': ['x=1', 'y=2'] }).some((x) => x.name === '(truncated)'));
  });
});

describe('CORS: "*" + credentials is a browser-blocked misconfiguration, a reflected origin is exploitable', () => {
  const ACAO = 'access-control-allow-origin', ACAC = 'access-control-allow-credentials';
  test('* + credentials warns, evidence says browsers reject it', async () => {
    const f = await H({}, { fetch: res(200, { [ACAO]: '*', [ACAC]: 'true' }) });
    assert.equal(f['cors-wildcard-credentials'].status, 'warn');
    assert.match(f['cors-wildcard-credentials'].evidence, /browsers reject/);
    assert.match(f['cors-wildcard-public'].evidence, /Allow-Credentials/);
  });
  test('reflected origin + credentials still fails; * without credentials passes', async () => {
    const reflect = async (u, o = {}) => ({ status: 200, headers: { [ACAO]: o.headers?.Origin ?? '', [ACAC]: 'true' }, body: '', finalUrl: u, timingMs: 1, redirects: [], truncated: false });
    assert.equal((await H({}, { fetch: reflect }))['cors-wildcard-credentials'].status, 'fail');
    assert.equal((await H({}, { fetch: res(200, { [ACAO]: '*' }) }))['cors-wildcard-credentials'].status, 'pass');
  });
});

describe('hdr-referrer-policy: origin is valid but weak', () => {
  test('origin warns as a value, not as unrecognized', async () => {
    const f = (await H({ 'referrer-policy': 'origin' }))['hdr-referrer-policy'];
    assert.equal(f.status, 'warn');
    assert.equal(f.evidence, 'value: origin');
  });
  test('a token outside the spec list stays "unrecognized", a strong value passes', async () => {
    assert.match((await H({ 'referrer-policy': 'bogus' }))['hdr-referrer-policy'].evidence, /unrecognized value: bogus/);
    assert.equal((await H({ 'referrer-policy': 'strict-origin' }))['hdr-referrer-policy'].status, 'pass');
  });
});

describe('mail-mx: null MX', () => {
  const dns = (mx) => runDns(fakeCtx({ url: 'https://example.test/', resolve: stubResolve({ mx: async () => mx }) }));
  test("Node's null MX (exchange '') and '.' are recognised, and still count as no mail for SPF severity", async () => {
    for (const exchange of ['', '.']) {
      const f = byId(await dns([{ exchange, priority: 0 }]));
      assert.equal(f['mail-mx'].status, 'pass', exchange);
      assert.match(f['mail-mx'].evidence, /null MX/);
      assert.equal(f['mail-spf-present'].status, 'warn'); // hasMx stays false: warn, not fail
    }
  });
  test('no MX at all is still info; a real MX passes and makes missing SPF a fail', async () => {
    const none = byId(await dns([]));
    assert.equal(none['mail-mx'].status, 'info');
    assert.match(none['mail-mx'].evidence, /no MX/);
    const real = byId(await dns([{ exchange: 'mx.example.test', priority: 10 }]));
    assert.equal(real['mail-mx'].status, 'pass');
    assert.equal(real['mail-spf-present'].status, 'fail');
  });
});

describe('dns-ns-count: climbs to the parent like the other DNS checks', () => {
  const ns = (map) => async (n) => map[n] || [];
  test('a www host finds the NS of the org domain', async () => {
    const f = byId(await runDns(fakeCtx({ url: 'https://www.example.test/', resolve: stubResolve({ ns: ns({ 'example.test': ['a.ns', 'b.ns'] }) }) })));
    assert.equal(f['dns-ns-count'].status, 'pass');
    assert.match(f['dns-ns-count'].evidence, /2 nameserver\(s\) \(at example\.test\)/);
  });
  test('one NS warns, none anywhere is skipped', async () => {
    assert.equal(byId(await runDns(fakeCtx({ url: 'https://www.example.test/', resolve: stubResolve({ ns: ns({ 'example.test': ['a.ns'] }) }) })))['dns-ns-count'].status, 'warn');
    assert.equal(byId(await runDns(fakeCtx({ url: 'https://www.example.test/', resolve: stubResolve() })))['dns-ns-count'].status, 'skipped');
  });
});

describe('seo-viewport: present-but-wrong is not "missing"', () => {
  const page = (head) => runHtml(fakeCtx({ body: `<html lang="en"><head>${head}</head><body></body></html>`, fetch: res(200) }));
  test('tag without width=device-width warns and says so', async () => {
    const f = byId(await page('<meta name="viewport" content="initial-scale=1,user-scalable=yes">'))['seo-viewport'];
    assert.equal(f.status, 'warn');
    assert.match(f.evidence, /lacks width=device-width/);
  });
  test('absent tag fails as missing, a correct tag passes', async () => {
    const f = byId(await page(''))['seo-viewport'];
    assert.equal(f.status, 'fail');
    assert.match(f.evidence, /missing/);
    assert.equal(byId(await page('<meta name="viewport" content="width=device-width, initial-scale=1">'))['seo-viewport'].status, 'pass');
  });
});

describe('tls-http-redirect: a port-80 answer that is not a redirect is not "no listener"', () => {
  const at = (status, headers = {}) => fakeCtx({ url: 'https://example.test/', fetch: res(status, headers) });
  test('403 and 500 are info with the status in the evidence', async () => {
    for (const status of [403, 404, 500]) {
      const f = byId(await runTls(at(status)))['tls-http-redirect'];
      assert.equal(f.status, 'info', String(status));
      assert.equal(f.evidence, `HTTP responds ${status}, no redirect, no content served`);
    }
    assert.equal(byId(await runTls(at(403)))['tls-redirect-permanent'].status, 'skipped');
  });
  test('connection error stays "no HTTP listener"; 200 still fails; https redirect still passes', async () => {
    const dead = fakeCtx({ url: 'https://example.test/', fetch: async () => { throw new Error('ECONNREFUSED'); } });
    assert.match(byId(await runTls(dead))['tls-http-redirect'].evidence, /no HTTP listener/);
    assert.equal(byId(await runTls(at(200)))['tls-http-redirect'].status, 'fail');
    assert.equal(byId(await runTls(at(301, { location: 'https://example.test/' })))['tls-http-redirect'].status, 'pass');
  });
});
