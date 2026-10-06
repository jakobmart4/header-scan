// CSP parsing + mixed content + SRI. One Finding per ID, no network I/O.
import { finding } from '../score.js';
import { BYPASS_HOSTS } from '../data/csp-bypass-hosts.js';

export const IDS = [
  'csp-present', 'csp-report-only', 'csp-unsafe-inline', 'csp-unsafe-eval', 'csp-wildcard',
  'csp-data-uri', 'csp-object-src', 'csp-base-uri', 'csp-frame-ancestors', 'csp-default-src',
  'csp-upgrade-insecure', 'csp-style-unsafe-inline', 'csp-script-bypass-hosts', 'mixed-active', 'mixed-passive', 'sri-external',
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

const RANK = { fail: 0, warn: 1, info: 2, pass: 3 };
const lower = (a) => (a || []).map((s) => s.toLowerCase());

export function hasEffectiveUnsafeInline(srcs) {
  const s = lower(srcs);
  return s.includes("'unsafe-inline'") && !s.some((x) => x.startsWith("'nonce-") || /^'sha(256|384|512)-/.test(x) || x === "'strict-dynamic'");
}

// First directive of `names` present in the policy (present-but-empty counts); eff() is its lowercased source list, [] if none.
const dirOf = (csp, ...names) => names.find((n) => csp.has(n));
const eff = (csp, ...names) => lower(csp.get(dirOf(csp, ...names)));

// "HTTPS://A.b:443/P?q" -> ['a.b', '/P'] (host lowercased, path case-sensitive like CSP, no scheme/port/query). ponytail: no percent-decoding, add if needed.
const splitSrc = (s) => {
  const t = s.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
  const i = t.indexOf('/');
  return [(i < 0 ? t : t.slice(0, i)).toLowerCase().replace(/:(\d+|\*)$/, ''), i < 0 ? '' : t.slice(i).replace(/[?#].*$/, '')];
};
// "*.com", "https://*.net": a wildcard over a whole TLD. That is csp-wildcard material, not a bypass host.
const bareWild = (s) => /^\*\.[^.]+$/.test(splitSrc(s)[0]);
// A concrete source host under a shared wildcard entry is that tenant's own site: no match.
const hostMatch = (s, e) => {
  const sw = s.startsWith('*.'), ew = e.startsWith('*.');
  const S = sw ? s.slice(2) : s, E = ew ? e.slice(2) : e;
  return sw ? E.endsWith('.' + S) || (ew && E === S) : !ew && S === E;
};

// Script sources that allow a known CSP bypass: one hit per source token, level 'host' (whole host/gadget loadable) beats 'path' (path-limited, open redirects still defeat it).
const BYPASS = BYPASS_HOSTS.map((e) => ({ ...e, split: splitSrc(e.pattern) }));
// ponytail: only the first 1000 distinct sources are matched (a meta CSP in a 1 MiB page can hold 500K tokens); real policies have dozens.
export function bypassHits(sources) {
  const out = [], seen = new Set();
  for (const source of sources || []) {
    if (seen.has(source)) continue;
    if (seen.size >= 1000) break;
    seen.add(source);
    const tok = String(source);
    if (tok.startsWith("'") || tok.endsWith(':') || tok === '*' || !tok.includes('.') || bareWild(tok)) continue;
    const [sh, sp] = splitSrc(tok);
    const whole = sp === '' || sp === '/';
    let best = null;
    for (const { pattern, reason, ref, split: [eh, gp] } of BYPASS) {
      if (!hostMatch(sh, eh)) continue;
      let level = 'host';
      if (!whole) {
        if (!gp) level = 'path';
        else if (!(sp.endsWith('/') ? gp.startsWith(sp) : sp === gp)) continue;
      }
      if (!best || (best.level === 'path' && level === 'host')) best = { source, level, pattern, reason, ref };
    }
    if (best) out.push(best);
  }
  return out;
}

export const attr = (tag, name) => {
  const m = new RegExp(`(?:^|\\s)${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i').exec(tag);
  return m ? (m[1] ?? m[2] ?? m[3] ?? '') : null;
};
// Drop HTML comments and the bodies of <script>/<style> so text inside them is never mistaken for markup (one pass, so order is right).
// Linear on hostile input: a closer that does not exist ("-->", "</script>") is searched for once, not once per opener.
export function stripInert(html) {
  html = String(html || '');
  const re = /<!--|<(script|style)\b[^<>]*>/gi;
  const close = { '': /-->/g, script: /<\/script\s*>/gi, style: /<\/style\s*>/gi };
  const none = {}; // closer -> index from which on it does not occur
  let out = '', last = 0, m;
  while ((m = re.exec(html))) {
    const k = m[1]?.toLowerCase() ?? '';
    if (k in none && re.lastIndex >= none[k]) continue;
    close[k].lastIndex = re.lastIndex;
    const c = close[k].exec(html);
    if (!c) { none[k] = re.lastIndex; continue; }
    out += html.slice(last, m.index) + (k ? `${m[0]}</${m[1]}>` : '');
    last = re.lastIndex = c.index + c[0].length;
  }
  return out + html.slice(last);
}
const tags = (html, names) => html.match(new RegExp(`<(?:${names})\\b[^<>]*>`, 'gi')) || [];

export async function run(ctx) {
  const { page, target } = ctx;
  const F = (id, title, status, sev, evidence = '', fix = '', cat = 'headers') =>
    finding(id, cat, title, status, sev, { evidence, fix });
  const C = (id, title, status, sev, evidence = '', fix = '') => F(id, title, status, sev, evidence, fix, 'content');

  if (!page.status) {
    return IDS.map((id) => finding(id, /^(mixed|sri)/.test(id) ? 'content' : 'headers', id, 'skipped', 1, { evidence: 'error: page not fetched' }));
  }
  const h = page.headers || {};
  const body = stripInert(page.body);
  const out = [];

  const headerCsp = h['content-security-policy'];
  const roCsp = h['content-security-policy-report-only'];
  const metaTag = tags(body, 'meta').find((t) => /http-equiv\s*=\s*["']?content-security-policy["']?/i.test(t));
  const metaCsp = metaTag ? attr(metaTag, 'content') : null;
  // Enforced header wins, else meta. Node joins duplicate headers with ",", so split into policies; the browser
  // enforces all of them (intersection), so a problem is reported only if every policy has it (merge loop below).
  const headerPolicies = String(headerCsp || '').split(',').map((p) => p.trim()).filter(Boolean);
  const hasHeader = headerPolicies.length > 0;
  const policies = (hasHeader ? headerPolicies : metaCsp ? [metaCsp] : []).map(parseCsp);

  if (hasHeader) out.push(F('csp-present', 'Content-Security-Policy', 'pass', 4, `enforced header present${policies.length > 1 ? ` (${policies.length} policies; a problem is reported only if every policy has it)` : ''}`));
  else if (metaCsp) out.push(F('csp-present', 'Content-Security-Policy', 'warn', 4, 'only via <meta> (no frame-ancestors, no reporting)', 'Send CSP as an HTTP header.'));
  else out.push(F('csp-present', 'Content-Security-Policy', 'fail', 4, 'no CSP', "Send a Content-Security-Policy header, e.g. default-src 'self'."));

  if (hasHeader && roCsp) out.push(F('csp-report-only', 'CSP report-only', 'pass', 1, 'enforced policy plus report-only'));
  else if (roCsp) out.push(F('csp-report-only', 'CSP report-only', 'info', 1, 'only Report-Only present, nothing enforced', 'Promote the report-only policy to an enforced Content-Security-Policy.'));
  else out.push(F('csp-report-only', 'CSP report-only', hasHeader ? 'pass' : 'info', 1, 'no report-only policy'));

  // One policy -> the 11 policy-level findings as {f, a}. a=false: this policy has no directive that decides the check,
  // so it says nothing about it (e.g. a frame-ancestors-only policy must not "pass" the script checks of another policy).
  const evalPolicy = (csp, isHeader) => {
    const r = [];
    const add = (f, a = true) => r.push({ f, a });
    const scriptSrc = csp.get('script-src') || csp.get('default-src') || [];
    const sa = csp.has('script-src') || csp.has('default-src');
    const ss = lower(scriptSrc);
    add(hasEffectiveUnsafeInline(scriptSrc)
      ? F('csp-unsafe-inline', "CSP 'unsafe-inline'", 'fail', 4, "script-src allows 'unsafe-inline' without nonce/hash", "Use nonces or hashes instead of 'unsafe-inline'.")
      : F('csp-unsafe-inline', "CSP 'unsafe-inline'", 'pass', 4, 'no effective unsafe-inline in scripts'), sa);
    add(ss.includes("'unsafe-eval'")
      ? F('csp-unsafe-eval', "CSP 'unsafe-eval'", 'warn', 3, "script-src allows 'unsafe-eval'", "Remove 'unsafe-eval'.")
      : F('csp-unsafe-eval', "CSP 'unsafe-eval'", 'pass', 3, 'not allowed'), sa);
    const wild = ss.filter((x) => x === '*' || x === 'https:' || x === 'http:' || bareWild(x));
    add(wild.length
      ? F('csp-wildcard', 'CSP wildcard sources', 'fail', 3, `script-src allows: ${wild.join(' ')}`, 'List explicit script origins instead of wildcards or bare schemes.')
      : F('csp-wildcard', 'CSP wildcard sources', 'pass', 3, 'no wildcard script sources'), sa);
    const dataIn = [['script-src/default-src', ss], ['object-src', lower(csp.get('object-src'))]].filter(([, s]) => s.includes('data:'));
    add(dataIn.length
      ? F('csp-data-uri', 'CSP data: sources', 'warn', 2, `data: allowed in ${dataIn.map(([n]) => n).join(', ')}`, 'Remove data: from script and object sources.')
      : F('csp-data-uri', 'CSP data: sources', 'pass', 2, 'not allowed'), sa);
    const obj = csp.get('object-src');
    const objOk = obj ? lower(obj).includes("'none'") : lower(csp.get('default-src')).includes("'none'");
    add(objOk ? F('csp-object-src', 'CSP object-src', 'pass', 3, "object-src 'none'")
      : F('csp-object-src', 'CSP object-src', 'warn', 3, obj ? `object-src: ${obj.join(' ')}` : 'object-src missing', "Add object-src 'none'."));
    add(csp.has('base-uri') ? F('csp-base-uri', 'CSP base-uri', 'pass', 2, 'present')
      : F('csp-base-uri', 'CSP base-uri', 'warn', 2, 'base-uri missing', "Add base-uri 'self' (or 'none')."));
    // frame-ancestors is ignored in <meta> CSP; only count it from the header.
    add(isHeader && csp.has('frame-ancestors') ? F('csp-frame-ancestors', 'CSP frame-ancestors', 'pass', 2, 'present')
      : F('csp-frame-ancestors', 'CSP frame-ancestors', 'warn', 2, 'frame-ancestors missing', "Add frame-ancestors 'self' (X-Frame-Options alone is not enough)."));
    add(csp.has('default-src') ? F('csp-default-src', 'CSP default-src', 'pass', 2, 'present')
      : F('csp-default-src', 'CSP default-src', 'warn', 2, 'default-src missing', "Add a restrictive default-src, e.g. 'self'."));
    add(csp.has('upgrade-insecure-requests') || csp.has('block-all-mixed-content')
      ? F('csp-upgrade-insecure', 'CSP upgrade-insecure-requests', 'pass', 1, 'present')
      : F('csp-upgrade-insecure', 'CSP upgrade-insecure-requests', 'info', 1, 'absent', 'Add upgrade-insecure-requests if the site is HTTPS-only.'));

    // 'strict-dynamic' never neutralises styles, so drop it before the shared unsafe-inline test.
    const styleDir = dirOf(csp, 'style-src-elem', 'style-src', 'default-src');
    const noDyn = (l) => l.filter((x) => x !== "'strict-dynamic'");
    const attrDir = dirOf(csp, 'style-src', 'default-src'); // style-src-attr falls back to style-src, not to style-src-elem
    const attrOpen = !csp.has('style-src-attr') && attrDir !== styleDir && hasEffectiveUnsafeInline(noDyn(eff(csp, 'style-src', 'default-src')));
    add(hasEffectiveUnsafeInline(noDyn(eff(csp, 'style-src-elem', 'style-src', 'default-src')))
      ? F('csp-style-unsafe-inline', "CSP style 'unsafe-inline'", 'warn', 2, `${styleDir} allows 'unsafe-inline' without nonce/hash`, "Put a nonce or hash on <style> elements and move style attributes into classes instead of allowing 'unsafe-inline'.")
      : attrOpen
        ? F('csp-style-unsafe-inline', "CSP style 'unsafe-inline'", 'info', 2, `${styleDir} restricts <style> elements, but ${attrDir} still allows inline style attributes (no style-src-attr)`, "Add style-src-attr 'none' once no inline style attributes remain.")
        : F('csp-style-unsafe-inline', "CSP style 'unsafe-inline'", 'pass', 2, 'no effective unsafe-inline in styles'),
    !!styleDir);

    // Host allowlists are ignored by browsers when 'strict-dynamic' is present. Only the script directive chain is judged.
    const bl = eff(csp, 'script-src-elem', 'script-src', 'default-src');
    const hits = bl.includes("'strict-dynamic'") ? [] : bypassHits(bl);
    const bt = 'CSP script allowlist bypass hosts';
    if (!hits.length) add(F('csp-script-bypass-hosts', bt, 'pass', 3, bl.includes("'strict-dynamic'") ? 'host allowlist ignored (strict-dynamic)' : 'no known bypass hosts in script sources'), sa || csp.has('script-src-elem'));
    else {
      const why = (x) => (x.level === 'path' ? 'path-limited, open-redirect risk only' : x.reason);
      const ev = hits.slice(0, 5).map((x) => `${x.source} (${why(x)})`).join('; ') + (hits.length > 5 ? `; +${hits.length - 5} more` : '');
      add(finding('csp-script-bypass-hosts', 'headers', bt, hits.some((x) => x.level === 'host') ? 'warn' : 'info', 3, {
        evidence: ev, ref: hits[0].ref,
        fix: "Replace host allowlists with nonces plus 'strict-dynamic', or self-host the script; allowlisted hosts that serve JSONP/AngularJS/user content defeat the policy.",
      }));
    }
    return r;
  };

  const sk = (id, title, sev) => F(id, title, 'skipped', sev, 'no CSP');
  if (!policies.length) {
    out.push(sk('csp-unsafe-inline', "CSP 'unsafe-inline'", 4), sk('csp-unsafe-eval', "CSP 'unsafe-eval'", 3), sk('csp-wildcard', 'CSP wildcard sources', 3),
      sk('csp-data-uri', 'CSP data: sources', 2), sk('csp-object-src', 'CSP object-src', 3), sk('csp-base-uri', 'CSP base-uri', 2),
      sk('csp-frame-ancestors', 'CSP frame-ancestors', 2), sk('csp-default-src', 'CSP default-src', 2), sk('csp-upgrade-insecure', 'CSP upgrade-insecure-requests', 1),
      sk('csp-style-unsafe-inline', "CSP style 'unsafe-inline'", 2), sk('csp-script-bypass-hosts', 'CSP script allowlist bypass hosts', 3));
  } else {
    // Per check: the best finding among the policies that speak to it (all policies when none does).
    const evals = policies.map((c) => evalPolicy(c, hasHeader));
    evals[0].forEach((_, i) => {
      const all = evals.map((e) => e[i]);
      const pool = all.some((x) => x.a) ? all.filter((x) => x.a) : all;
      out.push(pool.reduce((b, x) => (RANK[x.f.status] > RANK[b.f.status] ? x : b)).f);
    });
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
