// ACTIVE probes: run only for a verified domain owner (ctx.verified === true, set server-side).
// Read-only GETs against a fixed allowlist; a HIT needs status + tiny signature + body differing from a baseline 404.
// Response bodies are hashed/tested in memory and discarded; nothing from them reaches evidence.
import { createHash, randomBytes } from 'node:crypto';
import { finding } from '../score.js';

const sha = (s) => createHash('sha256').update(Buffer.from(s, 'latin1').subarray(0, 1024)).digest('hex');
const has = (...needles) => (b) => needles.some((n) => b.includes(n));
const re = (r) => (b) => r.test(b);
const SQL = re(/CREATE TABLE|INSERT INTO|MySQL dump/);
const API = re(/"swagger"|"openapi"/);

// id, path, severity, signature id, test(body latin1 string), opts
const PROBES = [
  ['exp-probe-git-head', '/.git/HEAD', 5, 'git-ref', re(/^ref: refs\//)],
  ['exp-probe-git-config', '/.git/config', 5, 'git-core', has('[core]')],
  ['exp-probe-env', '/.env', 5, 'env-line', re(/^[A-Z][A-Z0-9_]{2,}=/m)],
  ['exp-probe-svn', '/.svn/wc.db', 4, 'sqlite-header', (b) => b.startsWith('SQLite format 3')],
  ['exp-probe-hg', '/.hg/requires', 4, 'hg-requires', has('revlogv1', 'store')],
  ['exp-probe-ds-store', '/.DS_Store', 2, 'bud1', (b) => b.slice(4, 8) === 'Bud1'],
  ['exp-probe-backup-zip', '/backup.zip', 5, 'zip-magic', (b) => b.startsWith('PK\x03\x04'), { range: true }],
  ['exp-probe-backup-sql', '/backup.sql', 5, 'sql-dump', SQL],
  ['exp-probe-backup-tgz', '/backup.tar.gz', 5, 'gzip-magic', (b) => b.startsWith('\x1f\x8b'), { range: true }],
  ['exp-probe-db-sql', '/db.sql', 5, 'sql-dump', SQL],
  ['exp-probe-wp-config-bak', '/wp-config.php.bak', 5, 'wp-config', has('DB_PASSWORD', '<?php')],
  ['exp-probe-phpinfo', '/phpinfo.php', 4, 'phpinfo', has('phpinfo()', 'PHP Version')],
  ['exp-probe-server-status', '/server-status', 3, 'apache-status', has('Apache Server Status')],
  ['exp-probe-actuator-env', '/actuator/env', 5, 'property-sources', has('propertySources')],
  ['exp-probe-actuator', '/actuator', 3, 'links', has('_links')],
  ['exp-probe-admin', '/admin', 2, 'password-form', re(/type\s*=\s*["']?password/i), { protectedOk: true }],
  ['exp-probe-phpmyadmin', '/phpmyadmin/', 3, 'phpmyadmin', has('phpMyAdmin')],
  ['exp-probe-debug', '/debug', 3, 'debug-output', re(/Traceback|stack trace|DEBUG = True/i)],
  ['exp-probe-swagger', '/swagger.json', 1, 'api-spec', API, { info: true }],
  ['exp-probe-openapi', '/openapi.json', 1, 'api-spec', API, { info: true }],
  ['exp-probe-package-json', '/package.json', 2, 'dependencies', has('"dependencies"')],
  ['exp-probe-vercel', '/.vercel/project.json', 2, 'project-id', has('projectId')],
  ['exp-probe-web-inf', '/WEB-INF/web.xml', 4, 'web-app', has('<web-app')],
  ['exp-probe-dir-listing', '/uploads/', 3, 'index-of', has('Index of /')],
];
const GATE = 'exp-probes-gate';
export const IDS = [GATE, ...PROBES.map((p) => p[0])];

const DELAY_MS = 500; // <= 2 req/s
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const mk = (id, title, status, sev, evidence, fix = '') => finding(id, 'exposure', title, status, sev, { evidence, fix });

export async function run(ctx) {
  const host = ctx.target.host;
  if (ctx.verified !== true) {
    return [mk(GATE, 'Active probes (owner verification required)', 'skipped', 5, 'domain ownership not verified: active probes disabled',
      `Add a TXT record at _headerscan-verify.${host} with the token from the verify step to enable active probes.`)];
  }
  const out = [mk(GATE, 'Active probes (owner verification required)', 'pass', 5, 'owner verified')];

  const get = async (path, range) => {
    const opts = { method: 'GET', followRedirects: false, maxBytes: 65536, encoding: 'latin1', headers: range ? { Range: 'bytes=0-4095' } : {} };
    if (opts.method !== 'GET') throw new Error('probes are GET only'); // guard against future edits
    try { return await ctx.fetch(new URL(path, ctx.target.origin).href, opts); } catch (e) { return { error: e.code || 'error' }; }
  };

  const base = await get(`/${randomBytes(8).toString('hex')}-hs-probe`);
  const baseHash = base.error ? null : sha(base.body);
  let stop = '', fives = 0;

  for (const [id, path, sev, sig, test, o = {}] of PROBES) {
    const title = `Exposed ${path}`;
    if (stop) { out.push(mk(id, title, 'skipped', sev, stop)); continue; }
    await sleep(DELAY_MS);
    const r = await get(path, o.range);
    if (r.error) {
      if (r.error === 'BUDGET') stop = 'stopped: request budget exhausted';
      out.push(mk(id, title, 'skipped', sev, `error: ${r.error}`));
      continue;
    }
    fives = r.status >= 500 ? fives + 1 : 0;
    if (r.status === 429) stop = 'stopped: target rate-limited the scan (429)';
    else if (fives >= 3) stop = 'stopped: 3 consecutive server errors';
    if (stop) { out.push(mk(id, title, 'skipped', sev, stop)); continue; }
    const ok = r.status === 200 || r.status === 206;
    if (ok && test(r.body) && sha(r.body) !== baseHash) {
      out.push(mk(id, title, o.info ? 'info' : 'fail', sev, `HTTP ${r.status}, signature '${sig}' matched`,
        o.info ? 'Make sure API docs are meant to be public.' : `Remove ${path} from the web root and block access to it.`));
    } else {
      const ev = ok ? '200 without signature, ignored' : o.protectedOk && (r.status === 401 || r.status === 403) ? 'protected' : 'not found';
      out.push(mk(id, title, 'pass', sev, ev));
    }
  }
  return out;
}
