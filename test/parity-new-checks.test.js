// New/changed checks of the SecurityHeaders.com parity round (docs/PARITY-SPEC.md): every new id has a pass and a non-pass case.
process.env.HEADERSCAN_ALLOW_PRIVATE = '1';
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { run as runHeaders, IDS as HEADER_IDS } from '../lib/checks/headers.js';
import { run as runCsp, IDS as CSP_IDS, bypassHits } from '../lib/checks/csp.js';
import { BYPASS_HOSTS } from '../lib/data/csp-bypass-hosts.js';
import { buildRawHeaders, scan } from '../lib/scan.js';
import { fakeCtx, start, stubResolve } from './fixture-server.js';

const res = (headers) => async (u) => ({ status: 200, headers, body: '', finalUrl: String(u), timingMs: 1, redirects: [], truncated: false });
const byId = (fs) => Object.fromEntries(fs.map((f) => [f.id, f]));
const H = async (headers = {}, o = {}) => byId(await runHeaders(fakeCtx({ headers, fetch: res({}), ...o })));
const C = async (policy, o = {}) => byId(await runCsp(fakeCtx({ headers: policy == null ? {} : { 'content-security-policy': policy }, ...o })));

// rows: [label, headers, expected status, evidence regex?, ctx overrides?]
const headerTable = (name, id, rows) => test(name, async () => {
  for (const [label, headers, status, ev, o] of rows) {
    const f = (await H(headers, o))[id];
    assert.equal(f.status, status, `${label}: ${f.evidence}`);
    if (ev) assert.match(f.evidence, ev, label);
  }
});
// rows: [policy, expected status, evidence regex?]
const cspTable = (name, id, rows) => test(name, async () => {
  for (const [policy, status, ev] of rows) {
    const f = (await C(policy))[id];
    assert.equal(f.status, status, `${policy}: ${f.evidence}`);
    if (ev) assert.match(f.evidence, ev, String(policy));
  }
});

const OPP = 'cross-origin-opener-policy', EMB = 'cross-origin-embedder-policy', RES = 'cross-origin-resource-policy';
const ACAO = 'access-control-allow-origin';
const NEW_SEV = { 'hdr-xss-protection': 2, 'hdr-legacy-headers': 1, 'cors-wildcard-public': 2, 'hdr-reporting': 1, 'csp-style-unsafe-inline': 2, 'csp-script-bypass-hosts': 3 };

describe('IDs, severity, skipped branch', () => {
  test('new ids are appended after the old ones', () => {
    assert.deepEqual(HEADER_IDS.slice(-4), ['hdr-xss-protection', 'hdr-legacy-headers', 'cors-wildcard-public', 'hdr-reporting']);
    assert.equal(HEADER_IDS.length, 22);
    const i = CSP_IDS.indexOf('csp-upgrade-insecure');
    assert.deepEqual(CSP_IDS.slice(i + 1, i + 3), ['csp-style-unsafe-inline', 'csp-script-bypass-hosts']);
    assert.equal(CSP_IDS.length, 16);
  });
  test('severity, category headers, no checklist field, whatever the status', async () => {
    const all = [...Object.values(await H({})), ...Object.values(await H({ 'x-xss-protection': '1', [ACAO]: '*' })),
      ...Object.values(await C("style-src 'unsafe-inline'; script-src cdnjs.cloudflare.com")), ...Object.values(await C(null))];
    for (const [id, sev] of Object.entries(NEW_SEV)) {
      const fs = all.filter((f) => f.id === id);
      assert.ok(fs.length >= 2, id);
      for (const f of fs) {
        assert.equal(f.severity, sev, id);
        assert.equal(f.category, 'headers', id);
        assert.ok(!('checklist' in f), id);
      }
    }
  });
  test('failed page fetch: every id skipped, none thrown', async () => {
    const h = byId(await runHeaders(fakeCtx({ status: 0 })));
    const c = byId(await runCsp(fakeCtx({ status: 0 })));
    for (const id of ['hdr-xss-protection', 'hdr-legacy-headers', 'cors-wildcard-public', 'hdr-reporting']) assert.equal(h[id].status, 'skipped', id);
    for (const id of ['csp-style-unsafe-inline', 'csp-script-bypass-hosts']) assert.equal(c[id].status, 'skipped', id);
    assert.equal(Object.keys(h).length, HEADER_IDS.length);
    assert.equal(Object.keys(c).length, CSP_IDS.length);
  });
});

describe('COOP / COEP / CORP', () => {
  const ro = (h) => `${h}-report-only`;
  headerTable('hdr-coop', 'hdr-coop', [
    ['same-origin', { [OPP]: 'same-origin' }, 'pass'],
    ['same-origin-allow-popups', { [OPP]: 'same-origin-allow-popups' }, 'pass'],
    ['noopener-allow-popups', { [OPP]: 'noopener-allow-popups' }, 'pass'],
    ['case and parameters', { [OPP]: 'Same-Origin; report-to="d"' }, 'pass'],
    ['report-only only', { [ro(OPP)]: 'same-origin; report-to="d"' }, 'info', /report-only, not enforced: same-origin; report-to="d"/],
    ['enforced wins over report-only', { [OPP]: 'same-origin', [ro(OPP)]: 'same-origin' }, 'pass'],
    ['unsafe-none + report-only', { [OPP]: 'unsafe-none', [ro(OPP)]: 'same-origin' }, 'info', /report-only, not enforced/],
    ['unrecognised + report-only', { [OPP]: 'bogus', [ro(OPP)]: 'same-origin' }, 'info', /report-only, not enforced/],
    ['unsafe-none', { [OPP]: 'unsafe-none' }, 'info', /cross-origin-opener-policy: unsafe-none \(not an enforcing value\)/],
    ['absent', {}, 'info', /header absent \(optional hardening\)/],
  ]);
  headerTable('hdr-coep', 'hdr-coep', [
    ['require-corp', { [EMB]: 'require-corp' }, 'pass'],
    ['credentialless', { [EMB]: 'credentialless' }, 'pass'],
    ['report-only only', { [ro(EMB)]: 'require-corp; report-to="d"' }, 'info', /report-only, not enforced: require-corp; report-to="d"/],
    ['enforced wins over report-only', { [EMB]: 'require-corp', [ro(EMB)]: 'credentialless' }, 'pass'],
    ['unsafe-none + report-only', { [EMB]: 'unsafe-none', [ro(EMB)]: 'require-corp' }, 'info', /report-only, not enforced/],
    ['unsafe-none', { [EMB]: 'unsafe-none' }, 'info', /not an enforcing value/],
    ['absent', {}, 'info', /header absent/],
  ]);
  headerTable('hdr-corp', 'hdr-corp', [
    ['same-site', { [RES]: 'same-site' }, 'pass'],
    ['same-origin', { [RES]: 'same-origin' }, 'pass'],
    ['cross-origin', { [RES]: 'cross-origin' }, 'pass'],
    ['bogus', { [RES]: 'bogus' }, 'info', /cross-origin-resource-policy: bogus \(not an enforcing value\)/],
    ['absent', {}, 'info', /header absent \(optional hardening\)/],
    ['no report-only variant is invented', { [ro(RES)]: 'same-site' }, 'info', /header absent/],
  ]);
  test('info fix texts name the enforcing value, pass has no fix', async () => {
    const f = await H({});
    assert.match(f['hdr-coop'].fix, /Cross-Origin-Opener-Policy: same-origin/);
    assert.match(f['hdr-coep'].fix, /Cross-Origin-Embedder-Policy: require-corp/);
    assert.match(f['hdr-corp'].fix, /Cross-Origin-Resource-Policy: same-site/);
    const g = await H({ [OPP]: 'same-origin', [EMB]: 'require-corp', [RES]: 'same-site' });
    for (const id of ['hdr-coop', 'hdr-coep', 'hdr-corp']) assert.equal(g[id].fix, '', id);
  });
  test('never warn or fail, severity stays 1', async () => {
    for (const headers of [{}, { [OPP]: 'x' }, { [ro(OPP)]: 'x' }, { [RES]: 'x' }]) {
      const f = await H(headers);
      for (const id of ['hdr-coop', 'hdr-coep', 'hdr-corp']) { assert.ok(['pass', 'info'].includes(f[id].status), id); assert.equal(f[id].severity, 1); }
    }
  });
});

describe('hdr-xss-protection', () => {
  headerTable('absent and 0 pass, anything else warns', 'hdr-xss-protection', [
    ['absent', {}, 'pass'],
    ['0', { 'x-xss-protection': '0' }, 'pass'],
    ['0; mode=block', { 'x-xss-protection': '0; mode=block' }, 'pass'],
    ['1', { 'x-xss-protection': '1' }, 'warn', /^X-XSS-Protection: 1$/],
    ['1; mode=block', { 'x-xss-protection': '1; mode=block' }, 'warn', /^X-XSS-Protection: 1$/],
    ['unknown value', { 'x-xss-protection': 'on' }, 'warn', /^X-XSS-Protection: on$/],
  ]);
  test('a report= URL is never echoed', async () => {
    const f = (await H({ 'x-xss-protection': '1; mode=block; report=https://x.test/r?token=abc' }))['hdr-xss-protection'];
    assert.equal(f.status, 'warn');
    assert.ok(!/report=|token|x\.test/.test(f.evidence), f.evidence);
    assert.match(f.fix, /X-XSS-Protection: 0/);
  });
});

describe('hdr-legacy-headers', () => {
  headerTable('lists obsolete headers (I), warns on X-Permitted-Cross-Domain-Policies: all', 'hdr-legacy-headers', [
    ['none present', {}, 'pass'],
    ['expect-ct', { 'expect-ct': 'max-age=0' }, 'info', /expect-ct/],
    ['several', { 'feature-policy': "camera 'none'", 'x-download-options': 'noopen', p3p: 'CP="x"' }, 'info', /feature-policy/],
    ['public-key-pins-report-only', { 'public-key-pins-report-only': 'pin-sha256="x"; max-age=5' }, 'info', /public-key-pins-report-only/],
    ['policy all', { 'x-permitted-cross-domain-policies': 'all' }, 'warn'],
    ['policy all + legacy names', { 'x-permitted-cross-domain-policies': 'all', 'expect-ct': 'max-age=0' }, 'warn', /expect-ct/],
    ['policy none', { 'x-permitted-cross-domain-policies': 'none' }, 'pass'],
    ['policy master-only', { 'x-permitted-cross-domain-policies': 'master-only' }, 'pass'],
    ['policy none + legacy', { 'x-permitted-cross-domain-policies': 'none', 'expect-ct': 'max-age=0' }, 'info', /expect-ct/],
  ]);
  test('names are listed, values never echoed', async () => {
    const f = (await H({ 'expect-ct': 'max-age=86400, report-uri="https://r.test/x"', 'public-key-pins-report-only': 'pin-sha256="SECRETPIN"', 'feature-policy': "camera 'none'", 'x-download-options': 'noopen', p3p: 'CP="ALL"' }))['hdr-legacy-headers'];
    for (const n of ['expect-ct', 'public-key-pins-report-only', 'feature-policy', 'x-download-options', 'p3p']) assert.ok(f.evidence.includes(n), `${n} in ${f.evidence}`);
    assert.ok(!/max-age|SECRETPIN|r\.test|noopen|camera|ALL/.test(f.evidence), f.evidence);
  });
});

describe('cors-wildcard-public', () => {
  const reflect = async (u, o = {}) => {
    const origin = (o.headers || {}).Origin;
    return { status: 200, headers: origin ? { [ACAO]: origin } : {}, body: '', finalUrl: String(u), timingMs: 1, redirects: [], truncated: false };
  };
  const boom = async () => { throw Object.assign(new Error('x'), { code: 'NETWORK' }); };
  headerTable('public wildcard is info, personalised wildcard warns', 'cors-wildcard-public', [
    ['no ACAO', {}, 'pass', /no ACAO/],
    ['specific origin', { [ACAO]: 'https://a.example' }, 'pass', /ACAO: https:\/\/a\.example/],
    ['* without any personalisation', { [ACAO]: '*' }, 'info'],
    ['* + public cache-control', { [ACAO]: '*', 'cache-control': 'public, max-age=60' }, 'info'],
    ['* + Vary: Origin only', { [ACAO]: '*', vary: 'Origin' }, 'info'],
    ['* + Set-Cookie', { [ACAO]: '*', 'set-cookie': ['a=1; Secure'] }, 'warn'],
    ['* + Vary: Cookie', { [ACAO]: '*', vary: 'Accept-Encoding, Cookie' }, 'warn'],
    ['* + Vary: Authorization', { [ACAO]: '*', vary: 'Authorization' }, 'warn'],
    ['* + Cache-Control: private', { [ACAO]: '*', 'cache-control': 'max-age=0, private' }, 'warn'],
    ['probe answers * (page header silent)', {}, 'info', null, { fetch: res({ [ACAO]: '*' }) }],
    ['probe answers * + cookie', { 'set-cookie': ['a=1'] }, 'warn', null, { fetch: res({ [ACAO]: '*' }) }],
    ['probe fails, page header *', { [ACAO]: '*' }, 'info', null, { fetch: boom }],
    ['probe fails, page header silent', {}, 'pass', null, { fetch: boom }],
    ['reflected origin belongs to cors-reflected-origin', {}, 'pass', null, { fetch: reflect }],
  ]);
  test('overlap with cors-wildcard-credentials: both report, and the public finding mentions the credentials header', async () => {
    const f = await H({}, { fetch: res({ [ACAO]: '*', 'access-control-allow-credentials': 'true' }) });
    assert.equal(f['cors-wildcard-credentials'].status, 'warn');
    assert.equal(f['cors-wildcard-public'].status, 'info');
    assert.match(f['cors-wildcard-public'].evidence, /Allow-Credentials/);
  });
});

describe('hdr-reporting', () => {
  test('nothing configured: info with the optional hint', async () => {
    const f = (await H({}))['hdr-reporting'];
    assert.equal(f.status, 'info');
    assert.match(f.evidence, /no reporting configured/);
    assert.ok(f.fix.length > 0);
  });
  test('channels and endpoint hosts are named, paths and queries never', async () => {
    const f = (await H({
      'report-to': '{"group":"d","endpoints":[{"url":"https://collector.example/a/b?token=SECRET1"}]}',
      'reporting-endpoints': 'default="https://r.example/path?x=SECRET2"',
      nel: '{"report_to":"d","max_age":1}',
      'content-security-policy': "default-src 'self'; report-uri https://csp.example/r/x?key=SECRET3; report-to default",
    }))['hdr-reporting'];
    assert.equal(f.status, 'info');
    for (const c of ['Report-To', 'Reporting-Endpoints', 'NEL', 'CSP report-uri', 'CSP report-to']) assert.ok(f.evidence.includes(c), `${c} in ${f.evidence}`);
    for (const host of ['collector.example', 'r.example', 'csp.example']) assert.ok(f.evidence.includes(host), `${host} in ${f.evidence}`);
    assert.ok(!/SECRET|\/a\/b|\/path|\/r\/x|token=|key=/.test(f.evidence), f.evidence);
    assert.equal(f.fix, '');
  });
  test('report-only CSP counts, meta CSP does not, a plain header is not a channel', async () => {
    const ro = (await H({ 'content-security-policy-report-only': "default-src 'self'; report-uri https://ro.example/x" }))['hdr-reporting'];
    assert.match(ro.evidence, /CSP report-uri/);
    assert.ok(ro.evidence.includes('ro.example'));
    const meta = (await H({}, { body: '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'; report-uri https://m.example/x">' }))['hdr-reporting'];
    assert.match(meta.evidence, /no reporting configured/);
    assert.match((await H({ nel: '{}' }))['hdr-reporting'].evidence, /NEL/);
    assert.match((await H({ 'content-security-policy': "default-src 'self'" }))['hdr-reporting'].evidence, /no reporting configured/);
  });
  test('at most 3 endpoint hosts, deduplicated', async () => {
    const f = (await H({ 'report-to': '{"e":["https://a.example/1","https://a.example/2","https://b.example/","https://c.example/","https://d.example/"]}' }))['hdr-reporting'];
    assert.ok(f.evidence.includes('a.example') && f.evidence.includes('b.example') && f.evidence.includes('c.example'), f.evidence);
    assert.ok(!f.evidence.includes('d.example'), f.evidence);
  });
});

describe('hdr-permissions-policy: Feature-Policy hint', () => {
  test('warn evidence mentions the deprecated header only when it is the only one', async () => {
    const legacy = (await H({ 'feature-policy': "camera 'none'" }))['hdr-permissions-policy'];
    assert.equal(legacy.status, 'warn');
    assert.match(legacy.evidence, /Feature-Policy is deprecated/);
    const none = (await H({}))['hdr-permissions-policy'];
    assert.equal(none.status, 'warn');
    assert.ok(!/Feature-Policy/.test(none.evidence));
    const both = (await H({ 'feature-policy': "camera 'none'", 'permissions-policy': 'camera=()' }))['hdr-permissions-policy'];
    assert.equal(both.status, 'pass');
    assert.ok(!/Feature-Policy/.test(both.evidence));
  });
});

describe('csp-style-unsafe-inline', () => {
  cspTable('style directive chain style-src-elem > style-src > default-src', 'csp-style-unsafe-inline', [
    ["style-src 'self'", 'pass'],
    ["style-src 'unsafe-inline'", 'warn', /^style-src allows 'unsafe-inline' without nonce\/hash/],
    ["STYLE-SRC 'UNSAFE-INLINE'", 'warn', /^style-src allows/],
    ["style-src 'unsafe-inline' 'nonce-abc'", 'pass'],
    ["style-src 'unsafe-inline' 'sha256-abc='", 'pass'],
    ["style-src 'unsafe-inline' 'strict-dynamic'", 'warn'], // strict-dynamic never neutralises styles
    ["default-src 'unsafe-inline'", 'warn', /^default-src allows/],
    ["default-src 'unsafe-inline'; style-src 'self'", 'pass'],
    ["default-src 'unsafe-inline'; style-src", 'pass'], // present but empty counts
    ["style-src 'unsafe-inline'; style-src-elem 'self'", 'info', /style-src-elem restricts <style> elements, but style-src still allows inline style attributes/], // style-src-attr falls back to style-src
    ["style-src 'unsafe-inline'; style-src-elem 'self'; style-src-attr 'none'", 'pass'],
    ["style-src 'unsafe-inline'; style-src-elem 'self'; style-src-attr 'unsafe-inline'", 'pass'], // explicit attr rule: approved, attributes cannot run script
    ["style-src 'self'; style-src-elem 'unsafe-inline'", 'warn', /^style-src-elem allows/],
    ["style-src 'self'; style-src-attr 'unsafe-inline'", 'pass'], // attributes cannot run script, not evaluated
    ["script-src 'self'", 'pass'], // no style directive at all: csp-default-src's job
    ["default-src 'self'; script-src 'unsafe-inline'", 'pass'], // script unsafe-inline is csp-unsafe-inline's job
    [null, 'skipped', /no CSP/],
  ]);
  test('a <meta> CSP is evaluated when there is no header', async () => {
    const f = (await C(null, { body: '<meta http-equiv="Content-Security-Policy" content="style-src \'unsafe-inline\'">' }))['csp-style-unsafe-inline'];
    assert.equal(f.status, 'warn');
    assert.match(f.fix, /nonce or hash/);
  });
});

describe('csp-script-bypass-hosts (run)', () => {
  cspTable('script directive chain script-src-elem > script-src > default-src', 'csp-script-bypass-hosts', [
    ['script-src cdnjs.cloudflare.com', 'warn', /cdnjs\.cloudflare\.com \(/],
    ["script-src 'self' https://cdnjs.cloudflare.com", 'warn'],
    ['default-src *.cloudfront.net', 'warn'],
    ['script-src-elem ajax.googleapis.com', 'warn'],
    ['script-src www.google.com', 'warn'], // the whole host serves the gadget
    ['script-src cdn.jsdelivr.net/npm/x@1/a.js', 'info'], // path-scoped: only open redirects bypass it
    ['script-src cdn.jsdelivr.net/npm/x@1/a.js cdnjs.cloudflare.com', 'warn'], // a host-level hit beats a path-level one
    ["script-src 'self'", 'pass'],
    ["script-src 'nonce-x' 'strict-dynamic' cdnjs.cloudflare.com", 'pass', /ignored \(strict-dynamic\)/],
    ["script-src 'strict-dynamic' cdnjs.cloudflare.com", 'pass', /ignored \(strict-dynamic\)/],
    ["script-src 'self'; style-src cdnjs.cloudflare.com; font-src cdnjs.cloudflare.com", 'pass'],
    ["default-src cdnjs.cloudflare.com; script-src 'self'", 'pass'],
    ["script-src-elem 'self'; script-src cdnjs.cloudflare.com", 'pass'],
    ["img-src cdnjs.cloudflare.com", 'pass'], // no script chain at all
    ['script-src js.stripe.com www.google.com/recaptcha/api.js www.gstatic.com/recaptcha/releases/ *.googletagmanager.com', 'pass'],
    ['script-src *', 'pass'], // csp-wildcard's job
    ['script-src https:', 'pass'],
    [null, 'skipped', /no CSP/],
  ]);
  test('ref = ref of the first hit, evidence names source and reason', async () => {
    const f = (await C('script-src unpkg.com cdnjs.cloudflare.com'))['csp-script-bypass-hosts'];
    assert.equal(f.status, 'warn');
    assert.equal(f.ref, 'https://github.com/renniepak/CSPBypass');
    assert.ok(f.evidence.startsWith('unpkg.com ('), f.evidence);
    assert.ok(f.evidence.includes('cdnjs.cloudflare.com ('), f.evidence);
    const g = (await C('script-src cdnjs.cloudflare.com'))['csp-script-bypass-hosts'];
    assert.equal(g.ref, 'https://github.com/google/csp-evaluator/tree/master/allowlist_bypasses');
  });
  test('evidence lists the first 5 hits and counts the rest', async () => {
    const f = (await C('script-src www.blogger.com apis.google.com api.github.com *.blogspot.com *.herokuapp.com *.appspot.com *.cloudfront.net'))['csp-script-bypass-hosts'];
    assert.equal(f.status, 'warn');
    assert.match(f.evidence, /\+2 more/);
    assert.ok(f.evidence.includes('*.herokuapp.com (') && !f.evidence.includes('*.appspot.com ('), f.evidence);
  });
});

describe('bypassHits()', () => {
  const one = (s) => bypassHits([s])[0];
  test('PARITY-SPEC 3.1 expectations', () => {
    assert.deepEqual(bypassHits(['www.google.com/recaptcha/api.js']), []);
    assert.deepEqual(bypassHits(['www.gstatic.com/recaptcha/releases/']), []);
    assert.equal(one('www.google.com').level, 'host');
    assert.equal(one('www.google.com').pattern, 'www.google.com/tools/feedback/escalation-options'); // first entry in list order
    assert.equal(one('www.google.com/recaptcha/').level, 'host');
    assert.equal(one('www.google.com/recaptcha/').pattern, 'www.google.com/recaptcha/about/js/main.min.js');
    assert.equal(one('cdn.jsdelivr.net/npm/x@1/a.js').level, 'path');
    assert.equal(one('*.cloudfront.net').level, 'host');
    assert.deepEqual(bypassHits(['d111.cloudfront.net']), []);
    assert.equal(one('*.googleapis.com').level, 'host');
    assert.equal(one('*.googleapis.com').pattern, 'ajax.googleapis.com');
  });
  test('hit shape mirrors the data entry', () => {
    const h = one('cdnjs.cloudflare.com');
    assert.deepEqual(Object.keys(h).sort(), ['level', 'pattern', 'reason', 'ref', 'source']);
    assert.equal(h.source, 'cdnjs.cloudflare.com');
    const e = BYPASS_HOSTS.find((x) => x.pattern === h.pattern);
    assert.equal(h.reason, e.reason);
    assert.equal(h.ref, e.ref);
  });
  test('keywords, nonces, hashes, bare schemes, * and dot-less tokens are skipped; order is source order', () => {
    assert.deepEqual(bypassHits(["'self'", "'nonce-abc'", "'sha256-abc='", "'strict-dynamic'", "'unsafe-inline'", 'https:', 'data:', 'blob:', '*', 'localhost']), []);
    assert.deepEqual(bypassHits(["'self'", 'unpkg.com', 'js.stripe.com', 'cdnjs.cloudflare.com']).map((h) => h.source), ['unpkg.com', 'cdnjs.cloudflare.com']);
    assert.deepEqual(bypassHits([]), []);
  });
  test('sources are normalised: scheme, case, port, trailing slash', () => {
    for (const s of ['https://cdnjs.cloudflare.com', 'http://cdnjs.cloudflare.com/', 'https://cdnjs.cloudflare.com:443/', 'cdnjs.cloudflare.com:*', 'CDNJS.Cloudflare.COM', 'cdnjs.cloudflare.com/']) {
      assert.equal(one(s)?.level, 'host', s);
      assert.equal(one(s).pattern, 'cdnjs.cloudflare.com', s);
    }
    assert.equal(one('cdnjs.cloudflare.com/ajax/libs/?x=1#h').level, 'path');
  });
  test('host matching: exact vs wildcard on either side', () => {
    assert.deepEqual(bypassHits(['foo.cdnjs.cloudflare.com']), []); // exact source never matches a sub-host of an exact entry
    assert.equal(one('*.cloudflare.com').pattern, 'cdnjs.cloudflare.com'); // wildcard source covers an exact entry
    assert.equal(one('*.blogspot.com').level, 'host'); // wildcard vs wildcard
    assert.deepEqual(bypassHits(['*.s3.amazonaws.com']), []); // narrower wildcard than the entry
    for (const s of ['mysite.github.io', 'foo.appspot.com', 'x.herokuapp.com', 'example.blob.core.windows.net']) assert.deepEqual(bypassHits([s]), [], s); // a concrete tenant is its own site
  });
  test('gadget-path entries need a source path that covers the gadget', () => {
    for (const s of ['www.google.com/recaptcha/about/js/main.min.js', 'www.google.com/recaptcha/about/', 'www.google.com/recaptcha/about/js/main.min.js?x=1']) assert.equal(one(s)?.level, 'host', s);
    assert.deepEqual(bypassHits(['www.google.com/recaptcha']), []); // no trailing slash and not equal
    assert.equal(one('www.gstatic.com/fsn/angular_js-bundle1.js').level, 'host');
  });
});

describe('lib/data/csp-bypass-hosts.js', () => {
  const E = 'https://github.com/google/csp-evaluator/tree/master/allowlist_bypasses';
  const Cb = 'https://github.com/renniepak/CSPBypass';
  const Hk = 'https://github.com/HackTricks-wiki/hacktricks/blob/master/src/pentesting-web/content-security-policy-csp-bypass/README.md';
  const SEED = [
    ['cdnjs.cloudflare.com', E], ['cdn.jsdelivr.net', E], ['unpkg.com', Cb], ['ajax.googleapis.com', E], ['code.angularjs.org', Cb], ['cdn.shopify.com', E],
    ['www.gstatic.com/fsn/angular_js-bundle1.js', E], ['www.google.com/tools/feedback/escalation-options', E], ['www.google.com/recaptcha/about/js/main.min.js', Hk],
    ['accounts.google.com/o/oauth2/revoke', E], ['apis.google.com', Cb], ['*.googleapis.com', E], ['maps.googleapis.com', E], ['translate.googleapis.com', E], ['mts0.googleapis.com', E], ['mts1.googleapis.com', E], ['*.blogspot.com', E], ['www.blogger.com', E], ['api.github.com', Cb],
    ['*.github.io', E], ['*.cloudfront.net', E], ['*.amazonaws.com', E], ['*.appspot.com', E], ['*.herokuapp.com', E], ['*.azurewebsites.net', Hk],
    ['*.azurestaticapps.net', Hk], ['*.firebaseapp.com', Hk], ['*.blob.core.windows.net', E],
  ];
  test('exactly the 28 seed entries of PARITY-SPEC section 3, in list order', () => {
    assert.equal(BYPASS_HOSTS.length, 28);
    assert.deepEqual(BYPASS_HOSTS.map((e) => [e.pattern, e.ref]), SEED);
  });
  test('entry shape: lowercase pattern, reason <= 80 chars, https ref, no duplicates', () => {
    for (const e of BYPASS_HOSTS) {
      assert.ok(e.pattern && e.pattern === e.pattern.toLowerCase(), e.pattern);
      assert.ok(e.reason && e.reason.length <= 80, e.pattern);
      assert.ok(e.ref.startsWith('https://'), e.pattern);
    }
    assert.equal(new Set(BYPASS_HOSTS.map((e) => e.pattern)).size, BYPASS_HOSTS.length);
  });
  test('eval-gated hosts are deliberately absent', () => {
    for (const e of BYPASS_HOSTS) assert.ok(!/googletagmanager|google-analytics/.test(e.pattern), e.pattern);
  });
});

describe('buildRawHeaders()', () => {
  const val = (headers, name) => buildRawHeaders(headers).find((r) => r.name === name)?.value;
  test('empty, undefined and null input give []', () => {
    assert.deepEqual(buildRawHeaders({}), []);
    assert.deepEqual(buildRawHeaders(undefined), []);
    assert.deepEqual(buildRawHeaders(null), []);
  });
  test('plain headers: exactly {name, value}, names lowercased, arrays joined, numbers stringified', () => {
    const raw = buildRawHeaders({ 'Content-Type': 'text/html', 'x-multi': ['a', 'b'], 'x-n': 5 });
    assert.deepEqual(raw, [{ name: 'content-type', value: 'text/html' }, { name: 'x-multi', value: 'a, b' }, { name: 'x-n', value: '5' }]);
  });
  test('cookie values are redacted, only whitelisted attributes survive (original casing kept)', () => {
    const line = 'sid=SECRETVALUE; Path=/; HttpOnly; Secure; SameSite=Lax; Domain=.x.test; Max-Age=5; Expires=Wed, 30 Sep 2026 13:12:15 GMT; Partitioned; Priority=High; Comment=leak; Version=1';
    assert.equal(val({ 'set-cookie': [line] }, 'set-cookie'),
      'sid=<redacted>; Path=/; HttpOnly; Secure; SameSite=Lax; Domain=<redacted>; Max-Age=5; Expires=Wed, 30 Sep 2026 13:12:15 GMT; Partitioned; Priority=High');
  });
  test('cookie values containing = or junk never appear, not even partially', () => {
    for (const line of ['token=a=b=c==; Secure', 'jwt=eyJ.a.b; path=/', 'x= spaced value ; Secure', 'empty=; Secure']) {
      const v = val({ 'set-cookie': [line] }, 'set-cookie');
      assert.ok(!/a=b|eyJ|spaced|value/.test(v), `${line} -> ${v}`);
      assert.match(v, /^[a-z]+=<redacted>/);
    }
    assert.equal(val({ 'set-cookie': ['justvalue; Secure'] }, 'set-cookie'), '=<redacted>; Secure'); // no "=": nameless cookie, the pair is the VALUE
  });
  test('one entry per cookie line, string or array, set-cookie2 too, order kept', () => {
    const raw = buildRawHeaders({ a: '1', 'set-cookie': ['x=1; Secure', 'y=2; HttpOnly', 'z=3'], b: '2', 'set-cookie2': 'w=4; Path=/' });
    assert.deepEqual(raw, [
      { name: 'a', value: '1' },
      { name: 'set-cookie', value: 'x=<redacted>; Secure' }, { name: 'set-cookie', value: 'y=<redacted>; HttpOnly' }, { name: 'set-cookie', value: 'z=<redacted>' },
      { name: 'b', value: '2' }, { name: 'set-cookie2', value: 'w=<redacted>; Path=/' },
    ]);
    assert.deepEqual(buildRawHeaders({ 'set-cookie': 'only=1; Secure' }), [{ name: 'set-cookie', value: 'only=<redacted>; Secure' }]);
    assert.deepEqual(buildRawHeaders({ 'set-cookie': [] }), []);
  });
  test('prototype-looking header names are plain data', () => {
    const raw = buildRawHeaders(JSON.parse('{"__proto__":"a","constructor":"b","hasownproperty":"c","x":"d"}'));
    assert.deepEqual(raw.map((r) => [r.name, r.value]), [['__proto__', 'a'], ['constructor', 'b'], ['hasownproperty', 'c'], ['x', 'd']]);
    assert.equal({}.a, undefined);
    assert.equal(Object.getPrototypeOf(raw), Array.prototype);
  });
  test('at most 80 entries (each cookie line counts as one)', () => {
    const many = Object.fromEntries(Array.from({ length: 10000 }, (_, i) => [`h${i}`, 'v']));
    const raw = buildRawHeaders(many);
    assert.equal(raw.length, 80);
    assert.equal(raw[0].name, 'h0');
    assert.equal(raw[78].name, 'h78');
    assert.deepEqual(raw[79], { name: '(truncated)', value: '9921 more header/cookie line(s) not shown' }); // the marker takes the last slot
    const mixed = { ...Object.fromEntries(Array.from({ length: 79 }, (_, i) => [`h${i}`, 'v'])), 'set-cookie': ['a=1', 'b=2', 'c=3'] };
    assert.equal(buildRawHeaders(mixed).length, 80);
  });
  test('values are cut to 512 chars, names to 128', () => {
    assert.equal(val({ big: 'x'.repeat(1024 * 1024) }, 'big').length, 512);
    assert.ok(val({ big: 'x'.repeat(1024 * 1024) }, 'big').endsWith('...'));
    assert.equal(val({ ok: 'y'.repeat(512) }, 'ok'), 'y'.repeat(512));
    assert.equal(val({ cut: 'z'.repeat(513) }, 'cut'), 'z'.repeat(509) + '...');
    assert.equal(val({ 'set-cookie': ['a=1' + '; Secure'.repeat(500)] }, 'set-cookie').length, 512);
    assert.equal(buildRawHeaders({ ['n'.repeat(500)]: 'v' })[0].name.length, 128);
  });
  test('token-like header names are masked, others (also www-authenticate) are not', () => {
    for (const n of ['x-csrf-token', 'X-XSRF-TOKEN', 'x-api-key', 'x-apikey', 'x-secret', 'x-jwt', 'x-password', 'x-session-id', 'authorization', 'proxy-authorization', 'x-auth-token']) {
      assert.equal(val({ [n]: 'LEAK' }, n.toLowerCase()), '<redacted>', n);
    }
    assert.equal(val({ 'x-csrf-token': ['a', 'b'] }, 'x-csrf-token'), '<redacted>');
    assert.equal(val({ 'www-authenticate': 'Basic realm="x"' }, 'www-authenticate'), 'Basic realm="x"');
    assert.equal(val({ server: 'nginx' }, 'server'), 'nginx');
    assert.equal(val({ 'x-request-id': 'abc' }, 'x-request-id'), 'abc');
  });
});

describe('scan() result.rawHeaders', () => {
  let bad, r;
  before(async () => {
    bad = await start({ mode: 'bad' });
    r = await scan({ url: bad.url + '/', resolve: stubResolve(), allowPrivate: true });
  });
  after(async () => { await bad.close(); });

  test('exists, sits right after `deep`, cookie value redacted', () => {
    assert.ok(Array.isArray(r.rawHeaders) && r.rawHeaders.length > 0);
    const keys = Object.keys(r);
    assert.equal(keys.indexOf('rawHeaders'), keys.indexOf('deep') + 1);
    assert.equal(r.rawHeaders.find((h) => h.name === 'set-cookie').value, 'sessionid=<redacted>; Path=/');
    assert.equal(r.rawHeaders.find((h) => h.name === 'server').value, 'nginx/1.18.0');
    const json = JSON.stringify(r);
    assert.ok(!json.includes('sessionid=abc'));
    assert.deepEqual(r.errors, []);
  });
  test('page fetch failed: rawHeaders is []', async () => {
    const dead = await start({ mode: 'bad' });
    const url = dead.url;
    await dead.close();
    const res2 = await scan({ url: url + '/', resolve: stubResolve(), allowPrivate: true });
    assert.deepEqual(res2.rawHeaders, []);
  });
});
