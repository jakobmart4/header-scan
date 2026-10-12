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

test('overview category rows: the stretched .crow-go button is not flattened by the display: contents wrapper rule', () => {
  const css = read('ui/src/charts.css');
  const rules = [...css.matchAll(/^([^{}\n]*#cats > \.crow > [^{}\n]*)\{[^}]*display:\s*contents/gm)].map((m) => m[1]);
  assert.ok(rules.length, 'wrapper rule found');
  for (const sel of rules) assert.match(sel, /:not\(\.crow-go\)/, sel);
});

test('finding toggle: the accessible name ends with the status and severity in a visually hidden span', () => {
  const app = read('ui/src/app.js');
  const row = app.slice(app.indexOf('function compactRow('), app.indexOf('function fxRows('));
  assert.ok(row.includes("b.appendChild(h('span', 'sr', ' (' + li.dataset.s + ', severity ' + li.dataset.sev + ' of 5)'));"));
  assert.ok(row.indexOf("'sr'") > row.indexOf('b.appendChild(tt)'), 'the visible title stays first in the name');
  assert.match(read('ui/src/base.css'), /\.sr \{[^}]*clip-path: inset\(50%\)/);
  assert.ok(app.includes("t = r.li.querySelector('.fnd-tt') || r.li.querySelector('.fnd-title')"), 'top fixes copy the visible title, not the sr suffix');
});

test('empty URL / host: the field gets aria-invalid and focus, cleared again on input', () => {
  const app = read('ui/src/app.js');
  const run = app.slice(app.indexOf('async function runScan'), app.indexOf('async function loadSample'));
  assert.match(run, /if \(!url\) \{ u\.setAttribute\('aria-invalid', 'true'\); u\.focus\(\); say\(\$\('status'\), 'Enter a URL first\.', 'err'\); return; \}/);
  assert.ok(run.includes("u.removeAttribute('aria-invalid');"), 'a filled-in URL (also from the deep-scan button) is valid');
  assert.ok(app.includes("$('url').addEventListener('input', function () { this.removeAttribute('aria-invalid'); });"));
  const show = app.slice(app.indexOf('function show('), app.indexOf('renderRaw(r);'));
  assert.ok(show.includes("$('url').removeAttribute('aria-invalid');"), 'a loaded sample or share link clears a stale empty-URL error');
  const ver = app.slice(app.indexOf("$('verify-start').addEventListener"), app.indexOf("$('deep-btn').addEventListener"));
  assert.match(ver, /if \(!host\) \{ hs\.setAttribute\('aria-invalid', 'true'\); hs\.focus\(\); say\(\$\('verify-msg'\), 'Enter the host you own\.', 'err'\); return; \}/);
  assert.match(ver, /\$\('host'\)\.addEventListener\('input', function \(\) \{\s*this\.removeAttribute\('aria-invalid'\);/);
});

test('scan finished status announces both grades and the fail/warn counts of the real report shape', () => {
  const app = read('ui/src/app.js');
  const ctx = vm.createContext({});
  vm.runInContext(app.slice(app.indexOf('function counts('), app.indexOf('// ISO timestamp')), ctx);
  const r = JSON.parse(read('public/samples/mixed.json')), c = ctx.counts(r.findings);
  assert.ok(c.fail > 0 && c.warn > 0);
  assert.equal(ctx.doneMsg(r), `Scan finished: Security ${r.score.security.grade}, Quality ${r.score.quality.grade}, ${c.fail} failed, ${c.warn} warnings.`);
  assert.match(ctx.doneMsg(r), /^Scan finished: Security [A-F][+-]?, Quality [A-F][+-]?, \d+ failed, \d+ warnings\.$/);
  const run = app.slice(app.indexOf('async function runScan'), app.indexOf('async function loadSample'));
  assert.ok(run.includes("say($('status'), doneMsg(r), 'ok');"));
  assert.ok(app.includes("say($('status'), 'Sample report loaded: ' + name + '.');") && app.includes("say($('status'), 'Shared report opened.');"), 'samples and share links keep their own message');
});

test('build-ui strips CSS comments, indentation and full-line JS comments; strings with // and the script itself survive', () => {
  const ui = read('public/index.html');
  const style = ui.match(/<style>([\s\S]*?)<\/style>/)[1], script = ui.match(/<script>([\s\S]*?)<\/script>/)[1];
  assert.doesNotMatch(style, /\/\*/, 'no CSS comments');
  assert.doesNotMatch(style, /^[ \t]+/m, 'no CSS indentation');
  assert.doesNotMatch(style, /\n\n/, 'no blank lines');
  assert.doesNotMatch(script, /^[ \t]*\/\/.*$/m, 'no full-line JS comments');
  assert.doesNotThrow(() => new vm.Script(script), 'the stripped script still parses');
  const src = read('ui/src/app.js');
  for (const line of src.split('\n').filter((l) => /\/\/|\/\*/.test(l) && !/^\s*\/\//.test(l)).slice(0, 50)) {
    const code = line.trim();
    assert.ok(script.includes(code), 'a line with code and // or /* is kept verbatim: ' + code);
  }
});
