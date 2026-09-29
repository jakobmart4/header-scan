// Cookie flag checks. Evidence lists cookie NAMES only, never values.
import { finding } from '../score.js';

export const IDS = [
  'cookie-secure', 'cookie-httponly', 'cookie-samesite', 'cookie-samesite-none',
  'cookie-prefix', 'cookie-domain', 'cookie-lifetime', 'cookie-cache-control',
];

const SESSION_RE = /sess|auth|token|sid|jwt|login/i;
const DAY = 86400000;

// "name=value; Secure; Max-Age=5" -> { name, secure, httpOnly, sameSite, path, domain, maxAgeMs|null }
export function parseCookie(line, now = Date.now()) {
  const [pair, ...attrs] = String(line).split(';');
  const c = { name: pair.split('=')[0].trim(), secure: false, httpOnly: false, sameSite: '', path: '', domain: '', lifetimeMs: null };
  for (const a of attrs) {
    const i = a.indexOf('=');
    const k = (i < 0 ? a : a.slice(0, i)).trim().toLowerCase();
    const v = i < 0 ? '' : a.slice(i + 1).trim();
    if (k === 'secure') c.secure = true;
    else if (k === 'httponly') c.httpOnly = true;
    else if (k === 'samesite') c.sameSite = v.toLowerCase();
    else if (k === 'path') c.path = v;
    else if (k === 'domain') c.domain = v;
    else if (k === 'max-age' && /^-?\d+$/.test(v)) c.lifetimeMs = parseInt(v, 10) * 1000; // Max-Age wins over Expires
    else if (k === 'expires' && c.lifetimeMs === null) {
      const t = Date.parse(v);
      if (!Number.isNaN(t)) c.lifetimeMs = t - now;
    }
  }
  return c;
}

const names = (cs) => cs.map((c) => c.name).slice(0, 10).join(', ');

export async function run(ctx) {
  const { page, target } = ctx;
  const F = (id, title, status, sev, evidence = '', fix = '') => finding(id, 'cookies', title, status, sev, { evidence, fix });
  const raw = page.headers['set-cookie'];
  const cookies = (Array.isArray(raw) ? raw : raw ? [raw] : []).map((l) => parseCookie(l));
  const https = (page.finalUrl || target.url).startsWith('https://');

  if (!page.status) {
    return [['cookie-secure', 4], ['cookie-httponly', 3], ['cookie-samesite', 3], ['cookie-samesite-none', 3], ['cookie-prefix', 1], ['cookie-domain', 2], ['cookie-lifetime', 2], ['cookie-cache-control', 2]]
      .map(([id, sev]) => F(id, id, 'skipped', sev, 'error: page not fetched'));
  }
  const none = (id, title, sev) => F(id, title, 'info', sev, 'no cookies set');
  const sessionLike = cookies.filter((c) => SESSION_RE.test(c.name));
  const out = [];

  // secure
  if (!cookies.length) out.push(none('cookie-secure', 'Cookie Secure flag', 4));
  else {
    const bad = cookies.filter((c) => !c.secure);
    out.push(bad.length && https
      ? F('cookie-secure', 'Cookie Secure flag', 'fail', 4, `without Secure: ${names(bad)}`, 'Add the Secure attribute to all cookies.')
      : F('cookie-secure', 'Cookie Secure flag', 'pass', 4, https ? `${cookies.length} cookie(s) all Secure` : 'http page, not evaluated'));
  }

  // httponly
  if (!cookies.length) out.push(none('cookie-httponly', 'Cookie HttpOnly flag', 3));
  else {
    const sBad = sessionLike.filter((c) => !c.httpOnly);
    const oBad = cookies.filter((c) => !c.httpOnly && !SESSION_RE.test(c.name));
    if (sBad.length) out.push(F('cookie-httponly', 'Cookie HttpOnly flag', 'fail', 3, `session-like without HttpOnly: ${names(sBad)}`, 'Add HttpOnly to session and auth cookies.'));
    else if (oBad.length) out.push(F('cookie-httponly', 'Cookie HttpOnly flag', 'warn', 3, `without HttpOnly: ${names(oBad)}`, 'Add HttpOnly unless scripts must read the cookie.'));
    else out.push(F('cookie-httponly', 'Cookie HttpOnly flag', 'pass', 3, 'all HttpOnly'));
  }

  // samesite
  if (!cookies.length) out.push(none('cookie-samesite', 'Cookie SameSite', 3));
  else {
    const bad = cookies.filter((c) => !c.sameSite);
    out.push(bad.length
      ? F('cookie-samesite', 'Cookie SameSite', 'warn', 3, `without SameSite: ${names(bad)}`, 'Set SameSite=Lax (or Strict) explicitly.')
      : F('cookie-samesite', 'Cookie SameSite', 'pass', 3, 'all set'));
  }

  // samesite=none needs Secure
  if (!cookies.length) out.push(none('cookie-samesite-none', 'SameSite=None requires Secure', 3));
  else {
    const bad = cookies.filter((c) => c.sameSite === 'none' && !c.secure);
    out.push(bad.length
      ? F('cookie-samesite-none', 'SameSite=None requires Secure', 'fail', 3, `SameSite=None without Secure: ${names(bad)}`, 'Add Secure to SameSite=None cookies (browsers reject them otherwise).')
      : F('cookie-samesite-none', 'SameSite=None requires Secure', 'pass', 3, 'ok'));
  }

  // prefixes (case-sensitive per RFC 6265bis is lenient; browsers match case-insensitively, so do we)
  const pref = cookies.filter((c) => /^__(host|secure)-/i.test(c.name));
  if (!pref.length) out.push(F('cookie-prefix', 'Cookie name prefixes', 'info', 1, 'no __Host-/__Secure- cookies (optional hardening)'));
  else {
    const bad = pref.filter((c) => !c.secure || (/^__host-/i.test(c.name) && (c.path !== '/' || c.domain)));
    out.push(bad.length
      ? F('cookie-prefix', 'Cookie name prefixes', 'warn', 1, `invalid prefix use: ${names(bad)}`, '__Host- needs Secure, Path=/ and no Domain; __Secure- needs Secure.')
      : F('cookie-prefix', 'Cookie name prefixes', 'pass', 1, `valid: ${names(pref)}`));
  }

  // domain scope on session cookies
  if (!cookies.length) out.push(none('cookie-domain', 'Cookie Domain scope', 2));
  else {
    const bad = sessionLike.filter((c) => c.domain);
    out.push(bad.length
      ? F('cookie-domain', 'Cookie Domain scope', 'warn', 2, `Domain set on: ${names(bad)}`, 'Drop the Domain attribute so the cookie is host-only.')
      : F('cookie-domain', 'Cookie Domain scope', 'pass', 2, 'no Domain on session cookies'));
  }

  // lifetime > 400 days on session cookies
  if (!cookies.length) out.push(none('cookie-lifetime', 'Session cookie lifetime', 2));
  else {
    const bad = sessionLike.filter((c) => c.lifetimeMs !== null && c.lifetimeMs > 400 * DAY);
    out.push(bad.length
      ? F('cookie-lifetime', 'Session cookie lifetime', 'warn', 2, `lifetime > 400 days: ${names(bad)}`, 'Shorten session cookie lifetime (browsers cap at 400 days anyway).')
      : F('cookie-lifetime', 'Session cookie lifetime', 'pass', 2, 'ok'));
  }

  // cache-control public + cookie
  if (!cookies.length) out.push(none('cookie-cache-control', 'Cookies on publicly cacheable page', 2));
  else {
    const cc = (page.headers['cache-control'] || '').toLowerCase();
    out.push(/\bpublic\b/.test(cc)
      ? F('cookie-cache-control', 'Cookies on publicly cacheable page', 'warn', 2, 'Set-Cookie with Cache-Control: public', 'Use Cache-Control: private/no-store on responses that set cookies.')
      : F('cookie-cache-control', 'Cookies on publicly cacheable page', 'pass', 2, 'not public'));
  }
  return out;
}
