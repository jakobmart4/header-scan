// Security/response header checks + CORS. One Finding per ID, never throws for target problems.
import { finding } from '../score.js';

export const IDS = [
  'hdr-hsts', 'hdr-hsts-subdomains', 'hdr-hsts-preload', 'hdr-xcto', 'hdr-frame-protection',
  'hdr-referrer-policy', 'hdr-permissions-policy', 'hdr-coop', 'hdr-coep', 'hdr-corp',
  'hdr-server-leak', 'hdr-powered-by', 'hdr-generator-leak', 'hdr-cache-control-html',
  'hdr-compression', 'cors-wildcard-credentials', 'cors-reflected-origin', 'cors-null-origin',
];

const EVIL = 'https://evil.example';
const F = (id, title, status, sev, evidence = '', fix = '') =>
  finding(id, 'headers', title, status, sev, { evidence, fix });

// Parse "max-age=31536000; includeSubDomains; preload" into { maxAge, sub, preload }.
export function parseHsts(v) {
  const parts = v.toLowerCase().split(';').map((s) => s.trim());
  const m = parts.find((p) => p.startsWith('max-age='));
  const n = m ? parseInt(m.slice(8).replace(/"/g, ''), 10) : NaN;
  return { maxAge: Number.isNaN(n) ? 0 : n, sub: parts.includes('includesubdomains'), preload: parts.includes('preload') };
}

const hasFrameAncestors = (csp) => /(^|;)\s*frame-ancestors\s/i.test(csp || '');

async function corsProbe(ctx, origin) {
  try {
    const r = await ctx.fetch(ctx.page.finalUrl || ctx.target.url, { headers: { Origin: origin }, maxBytes: 1024, followRedirects: false });
    return { acao: (r.headers['access-control-allow-origin'] || '').trim(), acac: (r.headers['access-control-allow-credentials'] || '').trim().toLowerCase() === 'true' };
  } catch (e) {
    return { error: e.code || 'NETWORK' };
  }
}

export async function run(ctx) {
  const { page, target } = ctx;
  const h = page.headers || {};
  const https = (page.finalUrl || target.url).startsWith('https://'); // where we ended up, not what was typed
  const out = [];
  const skip = (id, title, sev, why) => F(id, title, 'skipped', sev, why);

  if (!page.status) {
    // Page fetch failed: nothing to evaluate.
    return IDS.map((id) => skip(id, id, 1, 'error: page not fetched'));
  }

  // --- HSTS ---
  const hstsRaw = h['strict-transport-security'];
  const hsts = hstsRaw ? parseHsts(hstsRaw) : null;
  if (!https) {
    out.push(F('hdr-hsts', 'HSTS', 'fail', 4, 'no HTTPS', 'Serve the site over HTTPS and send Strict-Transport-Security.'));
    out.push(skip('hdr-hsts-subdomains', 'HSTS includeSubDomains', 2, 'http target'));
    out.push(F('hdr-hsts-preload', 'HSTS preload', 'info', 1, 'http target'));
  } else {
    if (!hsts) out.push(F('hdr-hsts', 'HSTS', 'fail', 4, 'header missing', 'Send Strict-Transport-Security: max-age=31536000; includeSubDomains.'));
    else if (hsts.maxAge < 15552000) out.push(F('hdr-hsts', 'HSTS', 'warn', 4, `max-age=${hsts.maxAge} (< 180 days)`, 'Raise HSTS max-age to at least 31536000.'));
    else out.push(F('hdr-hsts', 'HSTS', 'pass', 4, `max-age=${hsts.maxAge}`));

    if (!hsts) out.push(skip('hdr-hsts-subdomains', 'HSTS includeSubDomains', 2, 'HSTS missing'));
    else if (!hsts.sub) out.push(F('hdr-hsts-subdomains', 'HSTS includeSubDomains', 'warn', 2, 'includeSubDomains absent', 'Add includeSubDomains to HSTS.'));
    else out.push(F('hdr-hsts-subdomains', 'HSTS includeSubDomains', 'pass', 2, 'present'));

    if (hsts && hsts.preload && hsts.sub && hsts.maxAge >= 31536000) out.push(F('hdr-hsts-preload', 'HSTS preload', 'pass', 1, 'preload-eligible'));
    else out.push(F('hdr-hsts-preload', 'HSTS preload', 'info', 1, 'not preload-eligible (optional)', 'Add preload with max-age>=31536000 and includeSubDomains to join the preload list.'));
  }

  // --- simple presence/value headers ---
  const xcto = h['x-content-type-options'];
  out.push((xcto || '').trim().toLowerCase() === 'nosniff'
    ? F('hdr-xcto', 'X-Content-Type-Options', 'pass', 3, 'nosniff')
    : F('hdr-xcto', 'X-Content-Type-Options', 'fail', 3, xcto ? `value: ${xcto}` : 'header missing', 'Send X-Content-Type-Options: nosniff.'));

  const xfo = (h['x-frame-options'] || '').trim().toUpperCase();
  const fa = hasFrameAncestors(h['content-security-policy']);
  out.push(xfo === 'DENY' || xfo === 'SAMEORIGIN' || fa
    ? F('hdr-frame-protection', 'Clickjacking protection', 'pass', 3, fa ? 'CSP frame-ancestors' : `X-Frame-Options: ${xfo}`)
    : F('hdr-frame-protection', 'Clickjacking protection', 'fail', 3, 'no X-Frame-Options or frame-ancestors', "Send CSP frame-ancestors 'self' (or X-Frame-Options: SAMEORIGIN)."));

  const rp = (h['referrer-policy'] || '').split(',').pop().trim().toLowerCase(); // last valid token wins
  const rpOk = ['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin'];
  const rpBad = ['unsafe-url', 'no-referrer-when-downgrade', 'origin-when-cross-origin'];
  if (rpOk.includes(rp)) out.push(F('hdr-referrer-policy', 'Referrer-Policy', 'pass', 2, rp));
  else if (!rp || rpBad.includes(rp)) out.push(F('hdr-referrer-policy', 'Referrer-Policy', 'warn', 2, rp ? `value: ${rp}` : 'header missing', 'Send Referrer-Policy: strict-origin-when-cross-origin.'));
  else out.push(F('hdr-referrer-policy', 'Referrer-Policy', 'warn', 2, `unrecognized value: ${rp}`, 'Send Referrer-Policy: strict-origin-when-cross-origin.')); // ponytail: unknown token treated as warn

  out.push(h['permissions-policy']
    ? F('hdr-permissions-policy', 'Permissions-Policy', 'pass', 2, 'present')
    : F('hdr-permissions-policy', 'Permissions-Policy', 'warn', 2, 'header missing', 'Send a Permissions-Policy disabling unused features (camera, microphone, geolocation).'));

  for (const [id, name, hdr] of [['hdr-coop', 'COOP', 'cross-origin-opener-policy'], ['hdr-coep', 'COEP', 'cross-origin-embedder-policy'], ['hdr-corp', 'CORP', 'cross-origin-resource-policy']]) {
    out.push(h[hdr]
      ? F(id, name, 'pass', 1, `${hdr}: ${h[hdr]}`)
      : F(id, name, 'info', 1, 'header absent (optional hardening)', `Consider sending ${hdr}.`));
  }

  // --- information leaks ---
  const server = h['server'] || '';
  out.push(/\d+\.\d+/.test(server) || /\/\d/.test(server)
    ? F('hdr-server-leak', 'Server version leak', 'warn', 2, `Server: ${server}`, 'Hide the version in the Server header.')
    : F('hdr-server-leak', 'Server version leak', 'pass', 2, server ? `Server: ${server}` : 'no Server header'));

  const leaks = ['x-powered-by', 'x-aspnet-version'].filter((k) => h[k]);
  out.push(leaks.length
    ? F('hdr-powered-by', 'X-Powered-By leak', 'warn', 2, leaks.map((k) => `${k}: ${h[k]}`).join('; '), 'Remove X-Powered-By / X-AspNet-Version headers.')
    : F('hdr-powered-by', 'X-Powered-By leak', 'pass', 2, 'absent'));

  const gen = /<meta\b[^>]*name\s*=\s*["']?generator["']?[^>]*>/i.exec(page.body || '');
  const genContent = gen && /content\s*=\s*["']([^"']*)["']/i.exec(gen[0]);
  out.push(genContent && /\d+(\.\d+)+/.test(genContent[1])
    ? F('hdr-generator-leak', 'Generator meta version', 'warn', 1, `generator: ${genContent[1]}`, 'Remove the version from the generator meta tag.')
    : F('hdr-generator-leak', 'Generator meta version', 'pass', 1, 'no versioned generator tag'));

  // --- caching ---
  const cc = (h['cache-control'] || '').toLowerCase();
  const setCookie = h['set-cookie'] && h['set-cookie'].length;
  if (!/html/i.test(h['content-type'] || '')) out.push(skip('hdr-cache-control-html', 'Cache-Control on HTML', 2, 'page is not HTML'));
  else if (setCookie && !/no-store|private/.test(cc)) out.push(F('hdr-cache-control-html', 'Cache-Control on HTML', 'warn', 2, 'Set-Cookie without no-store/private', 'Send Cache-Control: private or no-store on pages that set cookies.'));
  else if (!cc) out.push(F('hdr-cache-control-html', 'Cache-Control on HTML', 'warn', 2, 'Cache-Control missing', 'Send an explicit Cache-Control on HTML responses.'));
  else out.push(F('hdr-cache-control-html', 'Cache-Control on HTML', 'pass', 2, `Cache-Control: ${cc}`));

  // --- compression: refetch asking for gzip/br ---
  try {
    const r = await ctx.fetch(target.url, { headers: { 'Accept-Encoding': 'gzip, br' }, maxBytes: 4096 });
    const enc = (r.headers['content-encoding'] || '').toLowerCase();
    if (/gzip|br|deflate|zstd/.test(enc)) out.push(F('hdr-compression', 'Compression', 'pass', 2, `Content-Encoding: ${enc}`));
    else if ((page.body || '').length > 2048) out.push(F('hdr-compression', 'Compression', 'warn', 2, 'HTML > 2 KiB served uncompressed', 'Enable gzip or brotli for text responses.'));
    else out.push(skip('hdr-compression', 'Compression', 2, 'small body, no compression'));
  } catch (e) {
    out.push(skip('hdr-compression', 'Compression', 2, `error: ${e.code || 'NETWORK'}`));
  }

  // --- CORS ---
  const evil = await corsProbe(ctx, EVIL);
  const nul = await corsProbe(ctx, 'null');
  if (evil.error) {
    for (const [id, sev] of [['cors-wildcard-credentials', 4], ['cors-reflected-origin', 3]]) out.push(skip(id, id, sev, `error: ${evil.error}`));
  } else {
    const reflected = evil.acao === EVIL;
    out.push((evil.acac && (evil.acao === '*' || reflected))
      ? F('cors-wildcard-credentials', 'CORS credentials with wildcard/reflected origin', 'fail', 4, `ACAO: ${evil.acao}, credentials allowed`, 'Never allow credentials for wildcard or reflected origins; use an explicit allowlist.')
      : F('cors-wildcard-credentials', 'CORS credentials with wildcard/reflected origin', 'pass', 4, evil.acao ? `ACAO: ${evil.acao}` : 'no CORS headers'));
    out.push(reflected
      ? F('cors-reflected-origin', 'CORS reflected origin', 'warn', 3, 'arbitrary Origin echoed in ACAO', 'Validate Origin against an allowlist instead of echoing it.')
      : F('cors-reflected-origin', 'CORS reflected origin', 'pass', 3, 'Origin not reflected'));
  }
  if (nul.error) out.push(skip('cors-null-origin', 'CORS null origin', 3, `error: ${nul.error}`));
  else out.push(nul.acao === 'null'
    ? F('cors-null-origin', 'CORS null origin', nul.acac ? 'fail' : 'warn', 3, `ACAO: null${nul.acac ? ', credentials allowed' : ''}`, 'Do not allow the null origin.')
    : F('cors-null-origin', 'CORS null origin', 'pass', 3, 'null origin not allowed'));

  return out;
}
