// CSP parsing + mixed content + SRI. One Finding per ID, no network I/O.
import { finding } from '../score.js';

export const IDS = [
  'csp-present', 'csp-report-only', 'csp-unsafe-inline', 'csp-unsafe-eval', 'csp-wildcard',
  'csp-data-uri', 'csp-object-src', 'csp-base-uri', 'csp-frame-ancestors', 'csp-default-src',
  'csp-upgrade-insecure', 'mixed-active', 'mixed-passive', 'sri-external',
];

// "a 'self'; b x y" -> Map(directive -> string[] of sources). First occurrence of a directive wins (per spec).
export function parseCsp(value) {
  const d = new Map();
  for (const part of String(value || '').split(';')) {
    const [name, ...src] = part.trim().split(/\s+/);
    if (name && !d.has(name.toLowerCase())) d.set(name.toLowerCase(), src);
  }
  return d;
}

const lower = (a) => (a || []).map((s) => s.toLowerCase());

export function hasEffectiveUnsafeInline(srcs) {
  const s = lower(srcs);
  return s.includes("'unsafe-inline'") && !s.some((x) => x.startsWith("'nonce-") || /^'sha(256|384|512)-/.test(x) || x === "'strict-dynamic'");
}

const attr = (tag, name) => {
  const m = new RegExp(`(?:^|\\s)${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i').exec(tag);
  return m ? (m[1] ?? m[2] ?? m[3] ?? '') : null;
};
const tags = (html, names) => html.match(new RegExp(`<(?:${names})\\b[^>]*>`, 'gi')) || [];

export async function run(ctx) {
  const { page, target } = ctx;
  const F = (id, title, status, sev, evidence = '', fix = '', cat = 'headers') =>
    finding(id, cat, title, status, sev, { evidence, fix });
  const C = (id, title, status, sev, evidence = '', fix = '') => F(id, title, status, sev, evidence, fix, 'content');

  if (!page.status) {
    return IDS.map((id) => finding(id, /^(mixed|sri)/.test(id) ? 'content' : 'headers', id, 'skipped', 1, { evidence: 'error: page not fetched' }));
  }
  const h = page.headers || {};
  const body = page.body || '';
  const out = [];

  const headerCsp = h['content-security-policy'];
  const roCsp = h['content-security-policy-report-only'];
  const metaTag = tags(body, 'meta').find((t) => /http-equiv\s*=\s*["']?content-security-policy["']?/i.test(t));
  const metaCsp = metaTag ? attr(metaTag, 'content') : null;
  // Evaluate the enforced header (first policy if several joined by ","), else meta.
  const raw = headerCsp ? headerCsp.split(',')[0] : metaCsp;
  const csp = raw ? parseCsp(raw) : null;
  const scriptSrc = csp && (csp.get('script-src') || csp.get('default-src') || []);

  if (headerCsp) out.push(F('csp-present', 'Content-Security-Policy', 'pass', 4, 'enforced header present'));
  else if (metaCsp) out.push(F('csp-present', 'Content-Security-Policy', 'warn', 4, 'only via <meta> (no frame-ancestors, no reporting)', 'Send CSP as an HTTP header.'));
  else out.push(F('csp-present', 'Content-Security-Policy', 'fail', 4, 'no CSP', "Send a Content-Security-Policy header, e.g. default-src 'self'."));

  if (headerCsp && roCsp) out.push(F('csp-report-only', 'CSP report-only', 'pass', 1, 'enforced policy plus report-only'));
  else if (roCsp) out.push(F('csp-report-only', 'CSP report-only', 'info', 1, 'only Report-Only present, nothing enforced', 'Promote the report-only policy to an enforced Content-Security-Policy.'));
  else out.push(F('csp-report-only', 'CSP report-only', headerCsp ? 'pass' : 'info', 1, 'no report-only policy'));

  const sk = (id, title, sev) => F(id, title, 'skipped', sev, 'no CSP');
  if (!csp) {
    out.push(sk('csp-unsafe-inline', "CSP 'unsafe-inline'", 4), sk('csp-unsafe-eval', "CSP 'unsafe-eval'", 3), sk('csp-wildcard', 'CSP wildcard sources', 3),
      sk('csp-data-uri', 'CSP data: sources', 2), sk('csp-object-src', 'CSP object-src', 3), sk('csp-base-uri', 'CSP base-uri', 2),
      sk('csp-frame-ancestors', 'CSP frame-ancestors', 2), sk('csp-default-src', 'CSP default-src', 2), sk('csp-upgrade-insecure', 'CSP upgrade-insecure-requests', 1));
  } else {
    const ss = lower(scriptSrc);
    out.push(hasEffectiveUnsafeInline(scriptSrc)
      ? F('csp-unsafe-inline', "CSP 'unsafe-inline'", 'fail', 4, "script-src allows 'unsafe-inline' without nonce/hash", "Use nonces or hashes instead of 'unsafe-inline'.")
      : F('csp-unsafe-inline', "CSP 'unsafe-inline'", 'pass', 4, 'no effective unsafe-inline in scripts'));
    out.push(ss.includes("'unsafe-eval'")
      ? F('csp-unsafe-eval', "CSP 'unsafe-eval'", 'warn', 3, "script-src allows 'unsafe-eval'", "Remove 'unsafe-eval'.")
      : F('csp-unsafe-eval', "CSP 'unsafe-eval'", 'pass', 3, 'not allowed'));
    const wild = ss.filter((x) => x === '*' || x === 'https:' || x === 'http:');
    out.push(wild.length
      ? F('csp-wildcard', 'CSP wildcard sources', 'fail', 3, `script-src allows: ${wild.join(' ')}`, 'List explicit script origins instead of wildcards or bare schemes.')
      : F('csp-wildcard', 'CSP wildcard sources', 'pass', 3, 'no wildcard script sources'));
    const dataIn = [['script-src/default-src', ss], ['object-src', lower(csp.get('object-src'))]].filter(([, s]) => s.includes('data:'));
    out.push(dataIn.length
      ? F('csp-data-uri', 'CSP data: sources', 'warn', 2, `data: allowed in ${dataIn.map(([n]) => n).join(', ')}`, 'Remove data: from script and object sources.')
      : F('csp-data-uri', 'CSP data: sources', 'pass', 2, 'not allowed'));
    const obj = csp.get('object-src');
    const objOk = obj ? lower(obj).includes("'none'") : lower(csp.get('default-src')).includes("'none'");
    out.push(objOk ? F('csp-object-src', 'CSP object-src', 'pass', 3, "object-src 'none'")
      : F('csp-object-src', 'CSP object-src', 'warn', 3, obj ? `object-src: ${obj.join(' ')}` : 'object-src missing', "Add object-src 'none'."));
    out.push(csp.has('base-uri') ? F('csp-base-uri', 'CSP base-uri', 'pass', 2, 'present')
      : F('csp-base-uri', 'CSP base-uri', 'warn', 2, 'base-uri missing', "Add base-uri 'self' (or 'none')."));
    // frame-ancestors is ignored in <meta> CSP; only count it from the header.
    out.push(headerCsp && csp.has('frame-ancestors') ? F('csp-frame-ancestors', 'CSP frame-ancestors', 'pass', 2, 'present')
      : F('csp-frame-ancestors', 'CSP frame-ancestors', 'warn', 2, 'frame-ancestors missing', "Add frame-ancestors 'self' (X-Frame-Options alone is not enough)."));
    out.push(csp.has('default-src') ? F('csp-default-src', 'CSP default-src', 'pass', 2, 'present')
      : F('csp-default-src', 'CSP default-src', 'warn', 2, 'default-src missing', "Add a restrictive default-src, e.g. 'self'."));
    out.push(csp.has('upgrade-insecure-requests') || csp.has('block-all-mixed-content')
      ? F('csp-upgrade-insecure', 'CSP upgrade-insecure-requests', 'pass', 1, 'present')
      : F('csp-upgrade-insecure', 'CSP upgrade-insecure-requests', 'info', 1, 'absent', 'Add upgrade-insecure-requests if the site is HTTPS-only.'));
  }

  // --- mixed content ---
  const finalUrl = page.finalUrl || target.url;
  if (!finalUrl.startsWith('https://')) {
    out.push(C('mixed-active', 'Mixed active content', 'skipped', 5, 'http target'), C('mixed-passive', 'Mixed passive content', 'skipped', 3, 'http target'));
  } else {
    const isHttp = (u) => u != null && /^\s*http:\/\//i.test(u);
    const active = [];
    for (const t of tags(body, 'script|iframe|link')) {
      const name = /^<link/i.test(t) ? 'link' : /^<script/i.test(t) ? 'script' : 'iframe';
      if (name === 'link') { if (/stylesheet/i.test(attr(t, 'rel') || '') && isHttp(attr(t, 'href'))) active.push('link'); }
      else if (isHttp(attr(t, 'src'))) active.push(name);
    }
    out.push(active.length
      ? C('mixed-active', 'Mixed active content', 'fail', 5, `${active.length} http:// active resource(s): ${[...new Set(active)].join(', ')}`, 'Load scripts, frames and stylesheets over https://.')
      : C('mixed-active', 'Mixed active content', 'pass', 5, 'none found'));
    let passive = 0;
    for (const t of tags(body, 'img|audio|video|source')) {
      const srcset = attr(t, 'srcset') || '';
      if (isHttp(attr(t, 'src')) || /(^|,)\s*http:\/\//i.test(srcset)) passive++;
    }
    out.push(passive
      ? C('mixed-passive', 'Mixed passive content', 'warn', 3, `${passive} http:// media resource(s)`, 'Load images and media over https://.')
      : C('mixed-passive', 'Mixed passive content', 'pass', 3, 'none found'));
  }

  // --- SRI on cross-origin scripts/stylesheets ---
  let base;
  try { base = new URL(finalUrl); } catch { base = null; }
  const missing = [];
  if (base) {
    for (const t of tags(body, 'script|link')) {
      const isLink = /^<link/i.test(t);
      if (isLink && !/stylesheet/i.test(attr(t, 'rel') || '')) continue;
      const ref = attr(t, isLink ? 'href' : 'src');
      if (!ref) continue;
      let u;
      try { u = new URL(ref, base); } catch { continue; }
      if (/^https?:$/.test(u.protocol) && u.host !== base.host && !attr(t, 'integrity')) missing.push(u.host);
    }
  }
  out.push(missing.length
    ? C('sri-external', 'Subresource Integrity', 'warn', 3, `${missing.length} cross-origin resource(s) without integrity; hosts: ${[...new Set(missing)].slice(0, 3).join(', ')}`, 'Add integrity (and crossorigin) attributes to third-party scripts and stylesheets.')
    : C('sri-external', 'Subresource Integrity', 'pass', 3, 'all cross-origin resources have integrity, or none'));

  return out;
}
