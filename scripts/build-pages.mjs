// Build dist/ for Cloudflare Pages: copy public/, write _headers with a CSP that allows the inline
// <style>/<script> by SHA-256 hash (same rule as server.js loadIndex).
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import crypto from 'node:crypto';

rmSync('dist', { recursive: true, force: true });
mkdirSync('dist');
cpSync('public', 'dist', { recursive: true });

const html = readFileSync('public/index.html', 'utf8');
const hash = (s) => `'sha256-${crypto.createHash('sha256').update(s, 'utf8').digest('base64')}'`;
const style = [...html.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/gi)].map((m) => hash(m[1]));
const script = [...html.matchAll(/<script(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)<\/script>/gi)].map((m) => hash(m[1]));
const csp = `default-src 'none'; script-src ${script.join(' ') || "'none'"}; style-src ${style.join(' ') || "'none'"}; ` +
  "connect-src 'self'; img-src data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";

writeFileSync('dist/_headers', `/*
  Content-Security-Policy: ${csp}
  Strict-Transport-Security: max-age=31536000; includeSubDomains
  X-Content-Type-Options: nosniff
  Referrer-Policy: no-referrer
  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
  Cross-Origin-Opener-Policy: same-origin
  Cross-Origin-Resource-Policy: same-origin
`);
console.log(`dist/ ready (${script.length} script + ${style.length} style hashes)`);
