import tls from 'node:tls';
import net from 'node:net';
import { X509Certificate } from 'node:crypto';
import { finding } from '../score.js';
import { assertPublicHost } from '../ssrf.js';

export const IDS = ['tls-https', 'tls-protocol', 'tls-legacy-protocols', 'tls-cert-expiry', 'tls-cert-host',
  'tls-cert-chain', 'tls-cert-key', 'tls-cert-sigalg', 'tls-alpn-h2', 'tls-http-redirect', 'tls-redirect-permanent'];

const T = { // id -> [title, severity]
  'tls-https': ['HTTPS available', 5], 'tls-protocol': ['Negotiated TLS version is modern', 4],
  'tls-legacy-protocols': ['Legacy TLS 1.0/1.1 rejected', 4], 'tls-cert-expiry': ['Certificate not expiring soon', 4],
  'tls-cert-host': ['Certificate matches hostname', 5], 'tls-cert-chain': ['Certificate chain trusted', 4],
  'tls-cert-key': ['Certificate key size', 2], 'tls-cert-sigalg': ['Certificate signature algorithm', 2],
  'tls-alpn-h2': ['HTTP/2 negotiated', 1], 'tls-http-redirect': ['HTTP redirects to HTTPS', 3],
  'tls-redirect-permanent': ['HTTPS redirect is permanent', 1],
};
const add = (out, id, status, evidence = '', fix = '') =>
  out.push(finding(id, 'tls', T[id][0], status, T[id][1], { evidence, fix: status === 'pass' ? '' : fix }));

// Minimal TLS handshake to a pinned IP; certificate is inspected, not enforced.
function handshake(ip, host, port, extra = {}) {
  return new Promise((resolve, reject) => {
    let done = false, timer;
    const end = (fn, v) => { if (done) return; done = true; clearTimeout(timer); sock?.destroy(); fn(v); };
    let sock;
    try {
      sock = tls.connect({ host: ip, port, servername: net.isIP(host) ? undefined : host,
        rejectUnauthorized: false, ALPNProtocols: ['h2', 'http/1.1'], ...extra });
    } catch (e) { return reject(e); }
    timer = setTimeout(() => end(reject, Object.assign(new Error('timeout'), { code: 'TIMEOUT' })), 8000);
    sock.once('secureConnect', () => {
      try {
        end(resolve, { protocol: sock.getProtocol(), alpn: sock.alpnProtocol, authorized: sock.authorized,
          authError: sock.authorizationError, cert: sock.getPeerCertificate(true) });
      } catch (e) { end(reject, e); }
    });
    sock.once('error', (e) => end(reject, e));
  });
}

const SIG = { '2a864886f70d010105': 'sha1WithRSA', '2a864886f70d010104': 'md5WithRSA', '2a864886f70d010102': 'md2WithRSA',
  '2a8648ce3d040101': 'ecdsa-with-SHA1', '2a8648ce380403': 'dsa-with-SHA1',
  '2a864886f70d01010b': 'sha256WithRSA', '2a864886f70d01010c': 'sha384WithRSA', '2a864886f70d01010d': 'sha512WithRSA',
  '2a8648ce3d040302': 'ecdsa-with-SHA256', '2a8648ce3d040303': 'ecdsa-with-SHA384', '2a8648ce3d040304': 'ecdsa-with-SHA512' };
const WEAK = new Set(['sha1WithRSA', 'md5WithRSA', 'md2WithRSA', 'ecdsa-with-SHA1', 'dsa-with-SHA1']);

// Certificate ::= SEQ { tbsCertificate SEQ, signatureAlgorithm SEQ { OID, ... }, ... } -> OID as hex
function sigOid(der) {
  const rd = (p) => {
    let l = der[p + 1], h = 2;
    if (l & 0x80) { const n = l & 0x7f; l = 0; for (let i = 0; i < n; i++) l = l * 256 + der[p + 2 + i]; h = 2 + n; }
    return { h, l };
  };
  let p = rd(0).h;
  const tbs = rd(p); p += tbs.h + tbs.l;
  p += rd(p).h;
  const o = rd(p);
  return der.subarray(p + o.h, p + o.h + o.l).toString('hex');
}

export async function run(ctx) {
  const out = [];
  const { host, url, origin } = ctx.target;
  const port = ctx.allowPrivate ? Number(new URL(origin).port) || 443 : 443;
  const rest = (status, evidence) => IDS.filter((i) => !['tls-https', 'tls-http-redirect', 'tls-redirect-permanent'].includes(i))
    .forEach((i) => add(out, i, status, evidence));

  // HTTP -> HTTPS redirect (independent of the TLS handshake)
  let redirect = null;
  try {
    const r = await ctx.fetch(`http://${host}/`, { followRedirects: false, maxBytes: 4096, timeoutMs: 8000 });
    const loc = String(r.headers.location || '');
    if ([301, 302, 307, 308].includes(r.status)) redirect = { status: r.status, https: /^https:\/\//i.test(loc) };
    else if (r.status === 200) redirect = { status: 200 };
  } catch { /* no http listener: fine */ }

  // TLS handshake to the pinned public address
  let hs = null, err = '';
  try {
    const addrs = await assertPublicHost(host, { allowPrivate: ctx.allowPrivate });
    hs = await handshake(addrs[0].address, host, port);
  } catch (e) { err = e.code || e.message; }

  if (!hs) {
    const httpTarget = url.startsWith('http://');
    add(out, 'tls-https', httpTarget || err ? 'fail' : 'skipped', `HTTPS not reachable (error: ${err})`,
      'Serve the site over HTTPS with a valid certificate.');
    rest('skipped', `no HTTPS (error: ${err})`);
  } else {
    const { protocol, alpn, authorized, authError, cert } = hs;
    add(out, 'tls-https', 'pass', 'HTTPS reachable');
    const old = ['TLSv1', 'TLSv1.1', 'SSLv3'].includes(protocol);
    add(out, 'tls-protocol', old ? 'fail' : 'pass', `negotiated ${protocol}`, 'Enable TLS 1.2/1.3 and disable older versions.');

    // Legacy probe: only a server-side refusal counts as "rejected"; a local OpenSSL limit is skipped.
    try {
      await handshake(await assertPublicHost(host, { allowPrivate: ctx.allowPrivate }).then((a) => a[0].address), host, port,
        { minVersion: 'TLSv1', maxVersion: 'TLSv1.1', ciphers: 'ALL:@SECLEVEL=0' });
      add(out, 'tls-legacy-protocols', 'fail', 'server accepted TLS 1.0/1.1', 'Disable TLS 1.0 and 1.1 on the server.');
    } catch (e) {
      const local = e.code === 'ERR_TLS_INVALID_PROTOCOL_VERSION' || /no protocols available|unsupported protocol/i.test(e.message);
      if (local) add(out, 'tls-legacy-protocols', 'skipped', 'local OpenSSL cannot attempt TLS 1.0/1.1');
      else if (e.code === 'TIMEOUT') add(out, 'tls-legacy-protocols', 'skipped', 'error: TIMEOUT');
      else add(out, 'tls-legacy-protocols', 'pass', 'TLS 1.0/1.1 rejected');
    }

    let x509 = null;
    try { x509 = new X509Certificate(cert.raw); } catch { /* fields fall back to peerCertificate */ }
    const validTo = Date.parse(x509?.validTo ?? cert.valid_to);
    if (Number.isNaN(validTo)) add(out, 'tls-cert-expiry', 'skipped', 'expiry unavailable');
    else {
      const days = Math.floor((validTo - Date.now()) / 864e5);
      add(out, 'tls-cert-expiry', days < 7 ? 'fail' : days < 30 ? 'warn' : 'pass',
        days < 0 ? `expired ${-days} days ago` : `expires in ${days} days`, 'Renew the certificate (automate renewal).');
    }
    const idErr = tls.checkServerIdentity(host, cert);
    add(out, 'tls-cert-host', idErr ? 'fail' : 'pass', idErr ? `hostname ${host} not covered by certificate` : `covers ${host}`,
      'Issue a certificate that includes this hostname in its SAN list.');
    // Node checks the hostname only after chain verification succeeds, so ALTNAME means the chain was fine.
    const chainOk = authorized || authError === 'ERR_TLS_CERT_ALTNAME_INVALID';
    add(out, 'tls-cert-chain', chainOk ? 'pass' : 'fail', chainOk ? 'chain trusted' : `not trusted: ${authError}`,
      'Install a certificate from a trusted CA and serve the full intermediate chain.');

    const type = x509?.publicKey?.asymmetricKeyType;
    const bits = x509?.publicKey?.asymmetricKeyDetails?.modulusLength ?? cert.bits;
    if (type === 'rsa' || cert.modulus) add(out, 'tls-cert-key', bits < 2048 ? 'fail' : 'pass', `RSA ${bits} bits`, 'Use an RSA key of at least 2048 bits or an EC key.');
    else if (type === 'ec' || cert.asn1Curve) add(out, 'tls-cert-key', bits < 256 ? 'fail' : 'pass', `EC ${bits} bits`, 'Use an EC key of at least 256 bits.');
    else add(out, 'tls-cert-key', type ? 'pass' : 'skipped', type ? `key type ${type}` : 'key info unavailable');

    try {
      const name = SIG[sigOid(cert.raw)] ?? `oid ${sigOid(cert.raw)}`;
      add(out, 'tls-cert-sigalg', WEAK.has(name) ? 'fail' : 'pass', name, 'Reissue the certificate with a SHA-256 or stronger signature.');
    } catch { add(out, 'tls-cert-sigalg', 'skipped', 'signature algorithm unavailable'); }

    add(out, 'tls-alpn-h2', alpn === 'h2' ? 'pass' : 'info', `ALPN: ${alpn || 'none'}`, 'Enable HTTP/2 for better performance.');
  }

  // Redirect findings (order: keep IDS order at the end)
  if (!redirect) add(out, 'tls-http-redirect', 'info', 'no HTTP listener reachable on port 80');
  else if (redirect.status === 200) add(out, 'tls-http-redirect', 'fail', 'HTTP serves content (200) without redirecting', 'Redirect all HTTP requests to HTTPS.');
  else if (redirect.https) add(out, 'tls-http-redirect', 'pass', `HTTP ${redirect.status} to https`);
  else add(out, 'tls-http-redirect', 'fail', `HTTP ${redirect.status} redirect does not go to https`, 'Redirect HTTP requests to the https:// URL.');
  if (redirect?.https) {
    const perm = [301, 308].includes(redirect.status);
    add(out, 'tls-redirect-permanent', perm ? 'pass' : 'info', `status ${redirect.status}`, 'Use a 301/308 redirect once HTTPS is stable.');
  } else add(out, 'tls-redirect-permanent', 'skipped', 'no HTTP->HTTPS redirect');

  return IDS.map((id) => out.find((f) => f.id === id));
}
