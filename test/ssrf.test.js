process.env.HEADERSCAN_ALLOW_PRIVATE = '1';
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { isBlockedIp, parseTarget, assertPublicHost, safeFetch } from '../lib/ssrf.js';

// Injected lookup usable both as promise-style and callback-style (dns.lookup all:true shape).
const mkLookup = (answers) => {
  const fn = (host, opts, cb) => {
    fn.calls++;
    const list = typeof answers === 'function' ? answers(fn.calls) : answers;
    const arr = list.map((address) => ({ address, family: address.includes(':') ? 6 : 4 }));
    if (typeof opts === 'function') cb = opts;
    if (typeof cb === 'function') return cb(null, arr);
    return Promise.resolve(arr);
  };
  fn.calls = 0;
  return fn;
};

describe('isBlockedIp', () => {
  const blocked = [
    '0.0.0.0', '0.1.2.3', '10.0.0.1', '10.255.255.255', '100.64.0.1', '100.127.255.255', '127.0.0.1', '127.255.255.254',
    '169.254.0.1', '169.254.169.254', '172.16.0.1', '172.31.255.255', '192.0.0.1', '192.0.2.5', '192.168.1.1',
    '198.18.0.1', '198.19.255.255', '198.51.100.7', '203.0.113.9', '224.0.0.1', '239.255.255.255', '240.0.0.1',
    '255.255.255.255', '::', '::1', 'fc00::1', 'fd12:3456::1', 'fe80::1', 'febf::1', 'ff02::1',
    '::ffff:127.0.0.1', '::ffff:10.0.0.1', '::ffff:169.254.169.254', '::ffff:7f00:1', '64:ff9b::7f00:1', '64:ff9b::a00:1',
    '2001:db8::1', '2002:7f00:1::', '2002:a9fe:a9fe::1', 'not-an-ip', '', '999.1.1.1',
  ];
  const open = ['8.8.8.8', '1.1.1.1', '93.184.216.34', '172.32.0.1', '100.63.255.255', '198.20.0.1', '2606:4700:4700::1111', '::ffff:8.8.8.8', '2002:0808:0808::1'];
  for (const ip of blocked) test(`blocks ${JSON.stringify(ip)}`, () => assert.equal(isBlockedIp(ip), true));
  for (const ip of open) test(`allows ${ip}`, () => assert.equal(isBlockedIp(ip), false));
});

describe('parseTarget', () => {
  const bad = (input, code, opts) => assert.throws(() => parseTarget(input, opts), (e) => e.code === code, input);
  test('accepts and normalizes a normal URL', () => {
    const t = parseTarget('https://Example.COM./path?q=1#frag', {});
    assert.equal(t.host, 'example.com');
    assert.equal(t.origin, 'https://example.com');
    assert.ok(!t.url.includes('#'));
  });
  test('rejects non-http schemes', () => {
    for (const u of ['ftp://example.com/', 'file:///etc/passwd', 'gopher://example.com/', 'javascript:alert(1)']) bad(u, 'BAD_URL');
  });
  test('rejects userinfo', () => bad('https://user:pw@example.com/', 'BAD_URL'));
  test('rejects over-long URLs', () => bad('https://example.com/' + 'a'.repeat(2100), 'BAD_URL'));
  test('rejects hosts without a dot', () => bad('http://intranet/', 'BAD_URL'));
  test('rejects localhost with trailing dot', () => assert.throws(() => parseTarget('http://localhost./'), (e) => ['BAD_URL', 'BLOCKED_TARGET'].includes(e.code)));
  test('rejects private IP literals in every notation', () => {
    for (const u of ['http://127.0.0.1/', 'http://2130706433/', 'http://0x7f000001/', 'http://0x7f.0.0.1/', 'http://0177.0.0.1/', 'http://127.1/',
      'http://[::1]/', 'http://[::ffff:127.0.0.1]/', 'http://169.254.169.254/latest/meta-data/', 'http://10.0.0.1/', 'http://192.168.0.1/']) {
      assert.throws(() => parseTarget(u), (e) => e.code === 'BLOCKED_TARGET' || e.code === 'BAD_URL', u);
    }
  });
  test('rejects ports other than 80/443', () => {
    for (const u of ['http://example.com:22/', 'http://example.com:6379/', 'https://example.com:8443/']) bad(u, 'BAD_URL');
  });
  test('allowPrivate lifts the private-IP and port rules only', () => {
    assert.equal(parseTarget('http://127.0.0.1:8080/', { allowPrivate: true }).host, '127.0.0.1');
    assert.throws(() => parseTarget('ftp://127.0.0.1/', { allowPrivate: true }), (e) => e.code === 'BAD_URL');
    assert.throws(() => parseTarget('http://u:p@127.0.0.1/', { allowPrivate: true }), (e) => e.code === 'BAD_URL');
  });
});

describe('assertPublicHost', () => {
  test('returns all addresses when every answer is public', async () => {
    const r = await assertPublicHost('example.com', { lookup: mkLookup(['93.184.216.34', '2606:4700:4700::1111']) });
    assert.equal(r.length, 2);
  });
  test('mixed public+private answer is rejected (no first-wins)', async () => {
    await assert.rejects(assertPublicHost('evil.example', { lookup: mkLookup(['93.184.216.34', '10.0.0.5']) }), (e) => e.code === 'BLOCKED_TARGET');
    await assert.rejects(assertPublicHost('evil.example', { lookup: mkLookup(['10.0.0.5', '93.184.216.34']) }), (e) => e.code === 'BLOCKED_TARGET');
  });
  test('private-only answer and IPv4-mapped v6 answer are rejected', async () => {
    await assert.rejects(assertPublicHost('a.example', { lookup: mkLookup(['127.0.0.1']) }), (e) => e.code === 'BLOCKED_TARGET');
    await assert.rejects(assertPublicHost('b.example', { lookup: mkLookup(['::ffff:169.254.169.254']) }), (e) => e.code === 'BLOCKED_TARGET');
  });
  test('lookup failure -> DNS_FAILED', async () => {
    const lookup = (h, o, cb) => { const e = Object.assign(new Error('nx'), { code: 'ENOTFOUND' }); if (typeof o === 'function') cb = o; return typeof cb === 'function' ? cb(e) : Promise.reject(e); };
    await assert.rejects(assertPublicHost('nx.example', { lookup }), (e) => e.code === 'DNS_FAILED');
  });
  test('allowPrivate skips the check', async () => {
    const r = await assertPublicHost('local.example', { allowPrivate: true, lookup: mkLookup(['127.0.0.1']) });
    assert.equal(r[0].address, '127.0.0.1');
  });
});

describe('safeFetch (local raw server)', () => {
  let srv, base;
  const sockets = new Set();
  before(async () => {
    srv = http.createServer((req, res) => {
      const p = req.url;
      if (p === '/host') { res.end(req.headers.host); return; }
      if (p === '/ua') { res.end(req.headers['user-agent'] || ''); return; }
      if (p === '/loop1') { res.writeHead(302, { location: '/loop2' }); res.end(); return; }
      if (p === '/loop2') { res.writeHead(302, { location: '/loop1' }); res.end(); return; }
      if (p.startsWith('/chain/')) { const n = Number(p.slice(7)); res.writeHead(302, { location: `/chain/${n + 1}` }); res.end(); return; }
      if (p === '/to-file') { res.writeHead(302, { location: 'file:///etc/passwd' }); res.end(); return; }
      if (p === '/to-ftp') { res.writeHead(302, { location: 'ftp://example.com/x' }); res.end(); return; }
      if (p === '/redir') { res.writeHead(302, { location: '/host' }); res.end(); return; }
      if (p === '/big') { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('x'.repeat(200000)); return; }
      if (p === '/slow') { res.writeHead(200); const t = setInterval(() => res.write('.'), 50); res.on('close', () => clearInterval(t)); return; }
      if (p === '/cookies') { res.writeHead(200, { 'set-cookie': ['a=1', 'b=2'] }); res.end('ok'); return; }
      res.writeHead(404); res.end('nope');
    });
    srv.on('connection', (s) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
    await new Promise((r) => srv.listen(0, '127.0.0.1', r));
    base = `http://127.0.0.1:${srv.address().port}`;
  });
  after(() => new Promise((r) => { for (const s of sockets) s.destroy(); srv.close(() => r()); }));

  test('private target is blocked without allowPrivate', async () => {
    await assert.rejects(safeFetch(base + '/host', { allowPrivate: false }), (e) => e.code === 'BLOCKED_TARGET');
  });
  test('non-2xx resolves normally; user agent set; set-cookie is an array', async () => {
    assert.equal((await safeFetch(base + '/missing', { allowPrivate: true })).status, 404);
    assert.match((await safeFetch(base + '/ua', { allowPrivate: true })).body, /^header-scan\/1\.0/);
    assert.deepEqual((await safeFetch(base + '/cookies', { allowPrivate: true })).headers['set-cookie'], ['a=1', 'b=2']);
  });
  test('rebinding impossible: DNS asked once, connection uses the pinned IP, Host stays the hostname', async () => {
    const port = srv.address().port;
    // 1st answer is loopback (allowed only via allowPrivate); a 2nd answer would point somewhere unroutable.
    const lookup = mkLookup((n) => (n === 1 ? ['127.0.0.1'] : ['10.255.255.1']));
    const r = await safeFetch(`http://pinned.example.test:${port}/host`, { allowPrivate: true, lookup });
    assert.equal(r.status, 200);
    assert.equal(r.body, `pinned.example.test:${port}`);
    assert.equal(lookup.calls, 1);
  });
  test('blocked answer from injected lookup is refused before any connection', async () => {
    const lookup = mkLookup(['169.254.169.254']);
    await assert.rejects(safeFetch('http://meta.example.test/', { lookup }), (e) => e.code === 'BLOCKED_TARGET');
    assert.equal(lookup.calls, 1);
  });
  test('redirects are followed and recorded; followRedirects:false returns the 3xx', async () => {
    const r = await safeFetch(base + '/redir', { allowPrivate: true });
    assert.equal(r.status, 200);
    assert.equal(r.redirects.length, 1);
    assert.equal(r.redirects[0].status, 302);
    const n = await safeFetch(base + '/redir', { allowPrivate: true, followRedirects: false });
    assert.equal(n.status, 302);
  });
  test('redirect to file: / ftp: is refused even with allowPrivate', async () => {
    await assert.rejects(safeFetch(base + '/to-file', { allowPrivate: true }), (e) => ['BAD_URL', 'BLOCKED_TARGET'].includes(e.code));
    await assert.rejects(safeFetch(base + '/to-ftp', { allowPrivate: true }), (e) => ['BAD_URL', 'BLOCKED_TARGET'].includes(e.code));
  });
  test('redirect loop and too many redirects', async () => {
    await assert.rejects(safeFetch(base + '/loop1', { allowPrivate: true }), (e) => e.code === 'REDIRECT_LOOP');
    await assert.rejects(safeFetch(base + '/chain/0', { allowPrivate: true }), (e) => e.code === 'TOO_MANY_REDIRECTS');
  });
  test('body cap sets truncated', async () => {
    const r = await safeFetch(base + '/big', { allowPrivate: true, maxBytes: 1000 });
    assert.equal(r.truncated, true);
    assert.ok(r.body.length <= 1000);
  });
  test('total timeout applies even when bytes keep arriving', async () => {
    const t0 = Date.now();
    await assert.rejects(safeFetch(base + '/slow', { allowPrivate: true, timeoutMs: 400 }), (e) => e.code === 'TIMEOUT');
    assert.ok(Date.now() - t0 < 3000);
  });
});
