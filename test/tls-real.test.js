process.env.HEADERSCAN_ALLOW_PRIVATE = '1';
// Real-TLS tests for lib/checks/tls.js: loopback node:tls servers with throwaway certificates minted at test time by the
// system `openssl` binary into os.tmpdir() (never committed, removed in after()). The whole file is skipped without openssl.
// Targets are IP literals (SAN IP:127.0.0.1) so no DNS is involved; the http->https redirect probe uses fakeCtx's offline fetch.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFile, execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import net from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import { promisify } from 'node:util';
import { run } from '../lib/checks/tls.js';
import { fakeCtx } from './fixture-server.js';

const HAVE_OPENSSL = spawnSync('openssl', ['version']).status === 0;
const openssl = (...args) => execFileSync('openssl', args, { stdio: 'pipe' });
const DATES = HAVE_OPENSSL && /-not_after/.test(spawnSync('openssl', ['req', '-help'], { encoding: 'utf8' }).stderr + spawnSync('openssl', ['x509', '-help'], { encoding: 'utf8' }).stderr);
const pick = (fs) => Object.fromEntries(fs.map((x) => [x.id, x]));
const LEGACY = { minVersion: 'TLSv1', ciphers: 'DEFAULT@SECLEVEL=0' }; // server side: accept TLS 1.0+ (OpenSSL 3 needs SECLEVEL=0)
const CHILD = (tlsUrl, fixtureUrl) => `
import { run } from ${JSON.stringify(tlsUrl)};
import { fakeCtx } from ${JSON.stringify(fixtureUrl)};
const out = {};
for (const [name, port] of Object.entries(JSON.parse(process.env.PORTS))) {
  out[name] = (await run({ ...fakeCtx({ url: 'https://127.0.0.1:' + port + '/' }), allowPrivate: true })).map((f) => [f.id, f.status, f.evidence]);
}
console.log(JSON.stringify(out));`;

describe('tls.js against real TLS servers', { skip: !HAVE_OPENSSL && 'openssl binary not found on PATH (needed to mint throwaway certs)' }, () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'hs-tls-'));
  const f = (n) => path.join(dir, n);
  const conf = f('o.cnf');
  const servers = [], sockets = new Set();
  let canLegacy = false;

  const serve = (cred, opts = {}, onConnection) => new Promise((resolve) => {
    const s = tls.createServer({ ...cred, ...opts }, (sock) => sock.on('error', () => {}));
    s.on('tlsClientError', () => {});
    s.on('connection', (raw) => { sockets.add(raw); raw.on('error', () => {}); onConnection?.(s, raw); });
    servers.push(s);
    s.listen(0, '127.0.0.1', () => resolve(s));
  });
  const scan = async (srv) => pick(await run({ ...fakeCtx({ url: `https://127.0.0.1:${srv.address().port}/` }), allowPrivate: true }));

  // ---- certificate factory (all leaves share one RSA key: keygen is the slow part) ----
  let key, cred;
  const cert = (name, { k = key, san = 'IP:127.0.0.1', days = 365, md = 'sha256', dates } = {}) => {
    openssl('req', '-config', conf, '-x509', '-key', k, '-subj', '/CN=t', '-addext', `subjectAltName=${san}`, `-${md}`,
      '-days', String(days), ...(dates ? ['-not_before', dates[0], '-not_after', dates[1]] : []), '-out', f(`${name}.pem`));
    return { key: readFileSync(k), cert: readFileSync(f(`${name}.pem`)) };
  };
  const caLeaf = (name, san, dates) => { // leaf signed by the throwaway CA
    openssl('req', '-config', conf, '-new', '-key', key, '-subj', '/CN=t', '-out', f(`${name}.csr`));
    writeFileSync(f(`${name}.ext`), `subjectAltName=${san}\n`);
    openssl('x509', '-req', '-in', f(`${name}.csr`), '-CA', f('ca.pem'), '-CAkey', f('ca.key'), '-CAcreateserial', '-extfile', f(`${name}.ext`),
      '-days', '365', ...(dates ? ['-not_before', dates[0], '-not_after', dates[1]] : []), '-out', f(`${name}.pem`));
    return { key: readFileSync(key), cert: readFileSync(f(`${name}.pem`)) };
  };

  before(() => {
    writeFileSync(conf, '[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=x\n'); // own config: independent of the system openssl.cnf
    key = f('k.pem');
    openssl('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', key);
    cred = cert('base');
  });
  after(async () => {
    for (const s of sockets) s.destroy();
    await Promise.all(servers.map((s) => new Promise((r) => s.close(() => r()))));
    rmSync(dir, { recursive: true, force: true });
  });

  // Can THIS node/OpenSSL do a TLS 1.0/1.1 handshake at all? If not, the check must say "skipped", never guess.
  before(async () => {
    const s = await serve(cred, LEGACY);
    canLegacy = await new Promise((r) => {
      const c = tls.connect({ host: '127.0.0.1', port: s.address().port, rejectUnauthorized: false, minVersion: 'TLSv1', maxVersion: 'TLSv1.1', ciphers: 'ALL:@SECLEVEL=0' });
      c.once('secureConnect', () => { c.destroy(); r(true); });
      c.once('error', () => r(false));
    });
  });
  const needLegacy = (t) => { if (!canLegacy) t.skip('this node/OpenSSL cannot speak TLS 1.0/1.1'); return !canLegacy; };

  test('tls-legacy-protocols: server accepting TLS 1.0/1.1 fails; TLS 1.2+ only passes', async (t) => {
    const legacy = await scan(await serve(cred, LEGACY));
    const modern = await scan(await serve(cred));
    assert.equal(modern['tls-legacy-protocols'].status, canLegacy ? 'pass' : 'skipped', modern['tls-legacy-protocols'].evidence);
    assert.equal(modern['tls-protocol'].status, 'pass');
    if (needLegacy(t)) return;
    assert.equal(legacy['tls-legacy-protocols'].status, 'fail', legacy['tls-legacy-protocols'].evidence);
    assert.match(legacy['tls-legacy-protocols'].evidence, /accepted TLS 1\.0\/1\.1/);
    assert.equal(legacy['tls-protocol'].status, 'pass'); // a legacy-capable server still negotiates 1.3 with a modern client
    assert.match(legacy['tls-protocol'].evidence, /TLSv1\.3/);
    assert.match(modern['tls-legacy-protocols'].evidence, /rejected/);
  });

  for (const v of ['TLSv1', 'TLSv1.1']) {
    test(`a server that ONLY speaks ${v} is reported as legacy, not as "HTTPS not reachable"`, async (t) => {
      if (needLegacy(t)) return;
      const r = await scan(await serve(cred, { ...LEGACY, minVersion: v, maxVersion: v }));
      assert.equal(r['tls-https'].status, 'pass', r['tls-https'].evidence);
      assert.equal(r['tls-protocol'].status, 'fail', r['tls-protocol'].evidence);
      assert.match(r['tls-protocol'].evidence, new RegExp(`negotiated ${v.replace('.', '\\.')}$`));
      assert.equal(r['tls-legacy-protocols'].status, 'fail', r['tls-legacy-protocols'].evidence);
    });
  }

  test('tls-legacy-protocols: a refused/vanished second connection is "skipped", not a false "rejected"', async (t) => {
    // The listener closes as soon as the first (main) handshake's TCP connection arrives; the legacy probe then hits ECONNREFUSED.
    const r = await scan(await serve(cred, {}, (srv) => srv.close()));
    assert.equal(r['tls-https'].status, 'pass');
    assert.equal(r['tls-legacy-protocols'].status, 'skipped', r['tls-legacy-protocols'].evidence);
  });

  test('tls-alpn-h2: h2 offered -> pass; http/1.1 only or no ALPN -> info', async () => {
    const h2 = await scan(await serve(cred, { ALPNProtocols: ['h2', 'http/1.1'] }));
    const h1 = await scan(await serve(cred, { ALPNProtocols: ['http/1.1'] }));
    const none = await scan(await serve(cred));
    assert.equal(h2['tls-alpn-h2'].status, 'pass');
    assert.equal(h2['tls-alpn-h2'].evidence, 'ALPN: h2');
    assert.equal(h1['tls-alpn-h2'].status, 'info');
    assert.equal(h1['tls-alpn-h2'].evidence, 'ALPN: http/1.1');
    assert.equal(none['tls-alpn-h2'].status, 'info');
    assert.equal(none['tls-alpn-h2'].evidence, 'ALPN: none');
  });

  test('self-signed certificate: chain fails, host/expiry/key/sigalg pass', async () => {
    const r = await scan(await serve(cred));
    assert.equal(r['tls-https'].status, 'pass');
    assert.equal(r['tls-cert-chain'].status, 'fail');
    assert.match(r['tls-cert-chain'].evidence, /not trusted: DEPTH_ZERO_SELF_SIGNED_CERT/);
    assert.equal(r['tls-cert-host'].status, 'pass');
    assert.equal(r['tls-cert-expiry'].status, 'pass');
    assert.equal(r['tls-cert-key'].status, 'pass');
    assert.equal(r['tls-cert-key'].evidence, 'RSA 2048 bits');
    assert.equal(r['tls-cert-sigalg'].status, 'pass');
    assert.equal(r['tls-cert-sigalg'].evidence, 'sha256WithRSA');
  });

  test('tls-cert-host: hostname not in the SAN list fails', async () => {
    const r = await scan(await serve(cert('san-other', { san: 'DNS:other.test' })));
    assert.equal(r['tls-cert-host'].status, 'fail');
    assert.match(r['tls-cert-host'].evidence, /127\.0\.0\.1 not covered/);
  });

  test('tls-cert-expiry: <7 days fails, <30 days warns, expired fails with "expired N days ago"', async (t) => {
    const at = async (name, days, dates) => (await scan(await serve(cert(name, { days, dates }))))['tls-cert-expiry'];
    assert.equal((await at('d3', 3)).status, 'fail');
    assert.match((await at('d3', 3)).evidence, /expires in 2 days/);
    assert.equal((await at('d20', 20)).status, 'warn');
    assert.equal((await at('d365', 365)).status, 'pass');
    if (!DATES) return t.diagnostic('openssl < 3.4 has no -not_after: expired-certificate case not run');
    const gone = await at('gone', 1, ['20200101000000Z', '20200102000000Z']);
    assert.equal(gone.status, 'fail');
    assert.match(gone.evidence, /^expired \d+ days ago$/);
  });

  test('tls-cert-key / tls-cert-sigalg: weak RSA key and SHA-1 signature fail, EC P-256 passes', async () => {
    const weak = f('weak.pem'), ec = f('ec.pem');
    openssl('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:1024', '-out', weak);
    openssl('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', ec);
    const w = await scan(await serve(cert('w1024', { k: weak }), { ciphers: 'DEFAULT@SECLEVEL=0' }));
    assert.equal(w['tls-https'].status, 'pass', w['tls-https'].evidence); // a weak key must be reported, not hide the whole scan
    assert.equal(w['tls-cert-key'].status, 'fail');
    assert.equal(w['tls-cert-key'].evidence, 'RSA 1024 bits');
    const sha1 = await scan(await serve(cert('sha1', { md: 'sha1' }), { ciphers: 'DEFAULT@SECLEVEL=0' }));
    assert.equal(sha1['tls-https'].status, 'pass', sha1['tls-https'].evidence);
    assert.equal(sha1['tls-cert-sigalg'].status, 'fail');
    assert.equal(sha1['tls-cert-sigalg'].evidence, 'sha1WithRSA');
    const e = await scan(await serve(cert('ec', { k: ec })));
    assert.equal(e['tls-cert-key'].status, 'pass');
    assert.equal(e['tls-cert-key'].evidence, 'EC 256 bits');
    assert.equal(e['tls-cert-sigalg'].evidence, 'ecdsa-with-SHA256');
  });

  test('a plain-TCP (non-TLS) listener: tls-https fails, TLS-only checks are skipped', async () => {
    const s = net.createServer((c) => { c.on('error', () => {}); c.end('HTTP/1.1 400 Bad Request\r\n\r\n'); });
    servers.push(s);
    await new Promise((r) => s.listen(0, '127.0.0.1', r));
    const r = await scan(s);
    assert.equal(r['tls-https'].status, 'fail');
    assert.match(r['tls-https'].evidence, /not reachable/);
    for (const id of ['tls-protocol', 'tls-legacy-protocols', 'tls-cert-chain', 'tls-alpn-h2']) assert.equal(r[id].status, 'skipped', id);
  });

  // Trust decisions need a CA the client trusts: NODE_EXTRA_CA_CERTS is read at process start, so the check runs in a child
  // process (async spawn: this process has to keep serving the TLS listeners).
  test('trusted chain: ok passes; expired and hostname-mismatch leaves are judged separately', async (t) => {
    openssl('req', '-config', conf, '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', f('ca.key'), '-subj', '/CN=Test CA',
      '-addext', 'basicConstraints=critical,CA:TRUE', '-days', '30', '-out', f('ca.pem'));
    const ports = {};
    const add = async (name, c) => { ports[name] = (await serve(c)).address().port; };
    await add('ok', caLeaf('ok', 'IP:127.0.0.1'));
    await add('mismatch', caLeaf('mismatch', 'DNS:other.test'));
    if (DATES) await add('expired', caLeaf('expired', 'IP:127.0.0.1', ['20200101000000Z', '20200102000000Z']));
    const script = f('child.mjs');
    writeFileSync(script, CHILD(new URL('../lib/checks/tls.js', import.meta.url).href, new URL('./fixture-server.js', import.meta.url).href));
    const { stdout } = await promisify(execFile)(process.execPath, [script], {
      env: { ...process.env, NODE_EXTRA_CA_CERTS: f('ca.pem'), PORTS: JSON.stringify(ports), HEADERSCAN_ALLOW_PRIVATE: '1' }, timeout: 60000,
    });
    const r = Object.fromEntries(Object.entries(JSON.parse(stdout)).map(([k, v]) => [k, Object.fromEntries(v.map(([id, status, evidence]) => [id, { status, evidence }]))]));
    assert.equal(r.ok['tls-cert-chain'].status, 'pass', r.ok['tls-cert-chain'].evidence);
    assert.equal(r.ok['tls-cert-host'].status, 'pass');
    // Hostname mismatch must not be blamed on the chain (Node reports ERR_TLS_CERT_ALTNAME_INVALID only after the chain verified).
    assert.equal(r.mismatch['tls-cert-host'].status, 'fail');
    assert.equal(r.mismatch['tls-cert-chain'].status, 'pass', r.mismatch['tls-cert-chain'].evidence);
    if (!DATES) return t.diagnostic('openssl < 3.4 has no -not_after: expired-leaf case not run');
    assert.equal(r.expired['tls-cert-expiry'].status, 'fail');
    assert.equal(r.expired['tls-cert-chain'].status, 'fail'); // documented behavior: Node stops at CERT_HAS_EXPIRED
    assert.match(r.expired['tls-cert-chain'].evidence, /CERT_HAS_EXPIRED/);
  });
});
