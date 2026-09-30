// Stateless domain-ownership verification via DNS TXT. See SPEC.md 5.
// Token = base64url(expiresAtMs) "." base64url(HMAC-SHA256(secret, host|expiresAtMs)).slice(0,32)
import crypto from 'node:crypto';
import { isIP } from 'node:net';

const PREFIX = 'headerscan-verify=';
const SHARED_SUFFIXES = [
  'vercel.app', 'netlify.app', 'pages.dev', 'github.io', 'onrender.com', 'herokuapp.com',
  'azurewebsites.net', 'web.app', 'firebaseapp.com', 'workers.dev',
];

let processSecret;
export function getSecret() {
  if (process.env.HEADERSCAN_SECRET) return process.env.HEADERSCAN_SECRET;
  processSecret ??= crypto.randomBytes(32).toString('hex'); // random per process, never a fixed value
  return processSecret;
}

export function txtNameFor(host) {
  return '_headerscan-verify.' + host;
}

export function isSharedHost(host) {
  const h = String(host).toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
  if (isIP(h)) return true;
  return SHARED_SUFFIXES.some((s) => h === s || h.endsWith('.' + s));
}

function mac(secret, host, exp) {
  return crypto.createHmac('sha256', secret).update(`${host}|${exp}`).digest('base64url').slice(0, 32);
}

export function makeToken(host, { secret = getSecret(), now = Date.now(), ttlMs = 86400000 } = {}) {
  const h = String(host).toLowerCase();
  const expiresAt = now + ttlMs;
  const token = Buffer.from(String(expiresAt)).toString('base64url') + '.' + mac(secret, h, expiresAt);
  return { token, txtName: txtNameFor(h), txtValue: PREFIX + token, expiresAt };
}

export function tokenValid(host, token, { secret = getSecret(), now = Date.now() } = {}) {
  if (typeof host !== 'string' || typeof token !== 'string' || token.length > 200) return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const expStr = Buffer.from(parts[0], 'base64url').toString();
  if (!/^\d{1,16}$/.test(expStr)) return false;
  const exp = Number(expStr);
  if (exp <= now) return false;
  const want = Buffer.from(mac(secret, host.toLowerCase(), exp));
  const got = Buffer.from(parts[1]);
  return want.length === got.length && crypto.timingSafeEqual(want, got);
}

// resolveTxt: name -> string[] (or string[][] chunk arrays). Any DNS error means "not verified".
export async function isVerified(host, resolveTxt, { secret, now } = {}) {
  if (typeof host !== 'string' || isSharedHost(host)) return false;
  let records;
  try { records = await resolveTxt(txtNameFor(host.toLowerCase())); } catch { return false; }
  if (!Array.isArray(records)) return false;
  for (const rec of records) {
    let v = Array.isArray(rec) ? rec.join('') : rec;
    if (typeof v !== 'string') continue;
    v = v.trim().replace(/"\s+"/g, '').replace(/^"+|"+$/g, '').trim(); // joins "a" "b" chunks, strips quotes
    if (v.slice(0, PREFIX.length).toLowerCase() !== PREFIX) continue;
    if (tokenValid(host, v.slice(PREFIX.length).trim(), { secret, now })) return true;
  }
  return false;
}
