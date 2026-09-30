import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { IDS, run } from '../lib/checks/dns.js';
import { fakeCtx, stubResolve } from './fixture-server.js';

const HOST = 'example.test';
const by = (fs) => Object.fromEntries(fs.map((f) => [f.id, f.status]));
// records: { 'name': ['txt', ...] }; extra: overrides for a/aaaa/ns/mx/caa/dnssec
const ctxWith = (records = {}, extra = {}) => fakeCtx({ url: `https://${HOST}/`, resolve: stubResolve({ txt: async (n) => records[n] || [], ...extra }) });
const MX = { mx: async () => [{ exchange: 'mx.example.test', priority: 10 }] };

describe('dns.js', () => {
  test('exactly the owned IDs, once each', async () => {
    const out = await run(ctxWith());
    assert.deepEqual([...out.map((f) => f.id)].sort(), [...IDS].sort());
    assert.equal(new Set(IDS).size, 15);
  });
  test('healthy domain', async () => {
    const s = by(await run(ctxWith(
      { [HOST]: ['v=spf1 include:_spf.example.test -all'], '_spf.example.test': ['v=spf1 ip4:192.0.2.1 -all'], [`_dmarc.${HOST}`]: ['v=DMARC1; p=reject; rua=mailto:d@example.test'],
        [`_mta-sts.${HOST}`]: ['v=STSv1; id=1'], [`_smtp._tls.${HOST}`]: ['v=TLSRPTv1; rua=mailto:t@example.test'], [`default._domainkey.${HOST}`]: ['v=DKIM1; p=abc'] },
      { ...MX, aaaa: async () => ['2001:db8::1'], ns: async () => ['ns1.example.test', 'ns2.example.test'], caa: async () => [{ critical: 0, tag: 'issue', value: 'letsencrypt.org' }], dnssec: async () => ({ status: 'signed' }) })));
    for (const id of ['dns-caa', 'dns-dnssec', 'dns-ns-count', 'dns-ipv6', 'mail-mx', 'mail-spf-present', 'mail-spf-single', 'mail-spf-all', 'mail-spf-lookups', 'mail-dmarc-present', 'mail-dmarc-policy', 'mail-dmarc-rua', 'mail-mta-sts', 'mail-tls-rpt', 'mail-dkim']) assert.equal(s[id], 'pass', id);
  });
  test('empty domain without MX: advisory and warnings, dependent checks skipped', async () => {
    const s = by(await run(ctxWith()));
    assert.equal(s['dns-caa'], 'warn');
    assert.ok(['warn', 'skipped'].includes(s['dns-ns-count'])); // 0 NS = skipped (subdomain), 1 NS = warn
    assert.equal(by(await run(ctxWith({}, { ns: async () => ['ns1.example.test'] })))['dns-ns-count'], 'warn');
    assert.equal(s['dns-ipv6'], 'info');
    assert.equal(s['mail-mx'], 'info');
    assert.equal(s['mail-spf-present'], 'warn');
    assert.equal(s['mail-dmarc-present'], 'warn');
    for (const id of ['mail-spf-single', 'mail-spf-all', 'mail-spf-lookups', 'mail-dmarc-policy', 'mail-dmarc-rua']) assert.equal(s[id], 'skipped', id);
    assert.equal(s['dns-dnssec'], 'skipped'); // stub resolver has no dnssec()
  });
  test('MX present but no SPF/DMARC -> fail', async () => {
    const s = by(await run(ctxWith({}, MX)));
    assert.equal(s['mail-spf-present'], 'fail');
    assert.equal(s['mail-dmarc-present'], 'fail');
  });
  test('SPF all-mechanism grading', async () => {
    const spf = async (v) => by(await run(ctxWith({ [HOST]: [v] }, MX)))['mail-spf-all'];
    assert.equal(await spf('v=spf1 -all'), 'pass');
    assert.equal(await spf('v=spf1 ~all'), 'warn');
    assert.equal(await spf('v=spf1 +all'), 'fail');
    assert.equal(await spf('v=spf1 ?all'), 'fail');
    assert.equal(await spf('v=spf1 ip4:192.0.2.1'), 'fail');
  });
  test('two SPF records fail', async () => {
    assert.equal(by(await run(ctxWith({ [HOST]: ['v=spf1 -all', 'v=spf1 ~all'] }, MX)))['mail-spf-single'], 'fail');
  });
  test('SPF lookup count over 10 fails', async () => {
    const includes = Array.from({ length: 11 }, (_, i) => `include:i${i}.example.test`).join(' ');
    const rec = { [HOST]: [`v=spf1 ${includes} -all`] };
    for (let i = 0; i < 11; i++) rec[`i${i}.example.test`] = ['v=spf1 -all'];
    assert.equal(by(await run(ctxWith(rec, MX)))['mail-spf-lookups'], 'fail');
  });
  test('SPF include loop terminates', async () => {
    const s = by(await run(ctxWith({ [HOST]: ['v=spf1 include:a.example.test -all'], 'a.example.test': ['v=spf1 include:example.test -all'] }, MX)));
    assert.ok(['pass', 'warn', 'fail'].includes(s['mail-spf-lookups']));
  });
  test('DMARC policy grading', async () => {
    const d = async (v) => by(await run(ctxWith({ [`_dmarc.${HOST}`]: [v] }, MX)));
    assert.equal((await d('v=DMARC1; p=none; rua=mailto:a@b.test'))['mail-dmarc-policy'], 'fail');
    assert.equal((await d('v=DMARC1; p=quarantine; pct=50'))['mail-dmarc-policy'], 'warn');
    assert.equal((await d('v=DMARC1; p=quarantine'))['mail-dmarc-policy'], 'pass');
    assert.equal((await d('v=DMARC1; p=reject'))['mail-dmarc-rua'], 'warn');
  });
  test('DKIM selector unknown is informational, never a failure', async () => {
    assert.equal(by(await run(ctxWith()))['mail-dkim'], 'info');
  });
  test('DNSSEC unsigned warns', async () => {
    assert.equal(by(await run(ctxWith({}, { dnssec: async () => ({ status: 'unsigned' }) })))['dns-dnssec'], 'warn');
  });
  test('resolver errors never throw', async () => {
    const boom = async () => { throw Object.assign(new Error('SERVFAIL'), { code: 'ESERVFAIL' }); };
    const out = await run(fakeCtx({ url: `https://${HOST}/`, resolve: { a: boom, aaaa: boom, ns: boom, mx: boom, caa: boom, txt: boom } }));
    assert.equal(out.length, IDS.length);
  });
});
