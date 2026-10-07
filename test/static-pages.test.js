// Static site files: privacy page, security.txt, sitemap, footer links and the site-wide CSP built by scripts/build-pages.mjs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';

const root = new URL('../', import.meta.url);
const read = (p) => readFileSync(new URL(p, root), 'utf8');

test('privacy page is self-contained (CSP default-src none): no scripts, no inline style attributes, no loaded external resources', () => {
  const h = read('public/privacy.html');
  assert.match(h, /<html lang="en">/);
  assert.match(h, /<h1>Privacy<\/h1>/);
  assert.doesNotMatch(h, /<script/i);
  assert.doesNotMatch(h, /\sstyle="/i);
  assert.doesNotMatch(h, /<(img|link rel="stylesheet"|iframe|video|audio|source)[^>]+(src|href)="https?:/i);
  assert.equal((h.match(/<style>/g) || []).length, 1);
});

test('no personal contact data is published (no email addresses, no security.txt)', () => {
  assert.equal(existsSync(new URL('public/.well-known/security.txt', root)), false);
  for (const f of ['public/privacy.html', 'public/index.html', 'public/llms.txt', 'public/sitemap.xml', 'public/robots.txt']) {
    assert.doesNotMatch(read(f), /mailto:|[\w.+-]+@[\w-]+\.[\w.-]+/i, `${f} contains an email address`);
  }
});

test('sitemap and the UI footer point to the privacy page', () => {
  assert.match(read('public/sitemap.xml'), /<loc>https:\/\/[^<]+\/privacy<\/loc>/);
  assert.match(read('public/index.html'), /<a href="\/privacy">Privacy<\/a>/);
});

test('build-pages writes one site-wide CSP that allows the inline style of every html page by hash', () => {
  execFileSync(process.execPath, ['scripts/build-pages.mjs'], { cwd: root, stdio: 'pipe' });
  const headers = read('dist/_headers');
  const hash = (s) => `'sha256-${crypto.createHash('sha256').update(s, 'utf8').digest('base64')}'`;
  for (const f of ['public/index.html', 'public/privacy.html']) {
    for (const m of read(f).matchAll(/<style[^>]*>([\s\S]*?)<\/style>/gi)) assert.ok(headers.includes(hash(m[1])), `${f} style hash missing from CSP`);
  }
  assert.equal((headers.match(/^\s*Content-Security-Policy:/gm) || []).length, 1, 'exactly one CSP rule (Cloudflare joins multiple matching rules)');
  assert.match(headers, /default-src 'none'/);
});

test('cold start: the UI prewarms the backend via /api/health and says when a free host is waking; privacy page discloses it', () => {
  const ui = read('public/index.html');
  assert.match(ui, /fetch\('\/api\/health'/);
  assert.match(ui, /Waking up the scanner/);
  assert.match(read('public/privacy.html'), /wake up/i);
});
