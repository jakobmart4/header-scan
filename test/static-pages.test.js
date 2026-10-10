// Static site files: privacy page, security.txt, sitemap, footer links and the site-wide CSP built by scripts/build-pages.mjs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import vm from 'node:vm';

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
  assert.ok(ui.includes("api('/api/health'"));
  assert.match(ui, /Waking up the scanner/);
  assert.match(read('public/privacy.html'), /wake up/i);
});

test('cold start: the wake message waits 5 s, is cleared with the scan and when the page-load health answers meanwhile', () => {
  const app = read('ui/src/app.js');
  const run = app.slice(app.indexOf('async function runScan'), app.indexOf('async function loadSample'));
  assert.ok(run.includes("if (!awake()) { wakeMsg = running; say($('status'), 'Waking up the scanner"), 'the wake message remembers the scan status');
  assert.match(run, /\}, 5000\);/);
  assert.ok(run.indexOf('clearTimeout(wake)') > run.lastIndexOf('catch (e)'), 'timer cleared after both success and failure');
  assert.match(run, /clearTimeout\(wake\);\s*wakeMsg = '';/);
  assert.ok(app.includes("api('/api/health', { cache: 'no-store' }).then(function () { if (wakeMsg) { say($('status'), wakeMsg); wakeMsg = ''; } })"), 'health answering mid-scan restores the scan status');
});

test('cold start: any JSON answer of the backend marks it awake for 14 min (Render sleeps after ~15); the Worker waking 502 and static files do not', async () => {
  // run the real api()/awake() from app.js with a stub fetch and clock
  const app = read('ui/src/app.js');
  const src = app.slice(app.indexOf('async function api('), app.indexOf('// Grade band'));
  let now = 1e12, reply;
  const ctx = vm.createContext({ Date: { now: () => now }, fetch: async () => reply, Error, JSON });
  vm.runInContext(src, ctx);
  const res = (status, body) => ({ ok: status < 400, status, json: async () => body });
  const call = (path, status, body) => { reply = res(status, body); return ctx.api(path).catch(() => {}); };
  assert.equal(ctx.awake(), false, 'unknown at page load');
  await call('/samples/mixed.json', 200, {});
  assert.equal(ctx.awake(), false, 'a static sample is not the backend');
  await call('/api/scan?url=x', 502, { error: { code: 'BACKEND_UNREACHABLE', message: 'waking' } });
  assert.equal(ctx.awake(), false, 'the Worker waking 502 is not an answer of the backend');
  for (const [status, code] of [[400, 'BAD_URL'], [429, 'RATE_LIMITED'], [502, 'SCAN_FAILED'], [200, null]]) {
    now += 3600000;
    assert.equal(ctx.awake(), false);
    await call('/api/scan?url=x', status, code ? { error: { code, message: 'm' } } : { ok: true });
    assert.equal(ctx.awake(), true, String(status));
  }
  now += 13 * 60000;
  assert.equal(ctx.awake(), true, '13 min after the last answer');
  now += 2 * 60000;
  assert.equal(ctx.awake(), false, '15 min after the last answer');
});
