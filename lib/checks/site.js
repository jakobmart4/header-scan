// Site-level passive checks: robots/sitemap/llms/security.txt, 404 behaviour, favicon, bundles, source maps.
// Own fetches go through ctx.fetch only (SSRF-safe, budgeted). Never puts response bodies in evidence.
import { randomBytes } from 'node:crypto';
import { finding } from '../score.js';
import { stripInert } from './csp.js';
import { pageType } from './html.js';

// id -> [title, severity, checklist#]  (category derived from the id prefix)
const META = {
  'seo-robots-txt': ['robots.txt exists and is valid', 3, 30],
  'ai-robots-blocks-all': ['robots.txt does not block all crawlers', 5],
  'ai-robots-blocks-bots': ['AI crawlers are not blocked (may be intentional)', 2, 13],
  'seo-robots-sensitive': ['robots.txt does not advertise sensitive paths', 1],
  'seo-sitemap': ['sitemap.xml is present and valid', 3, 15],
  'ai-llms-txt': ['llms.txt present (optional standard)', 1, 12],
  'ux-404-page': ['Custom 404 page returns a real 404', 3, 3],
  'ux-favicon': ['Favicon present', 2, 14],
  'ux-default-hostname': ['Site is not on a default hosting hostname', 2, 1],
  'seo-duplicate-titles': ['Titles and descriptions are unique across pages', 3, 5],
  'ux-thank-you': ['Thank-you page exists', 1, 24],
  'ux-js-bundle-size': ['JavaScript bundles are small and compressed', 2, 20],
  'exp-source-maps': ['Source maps are not public', 3, 18],
  'exp-security-txt': ['security.txt (RFC 9116) present', 2],
  'exp-security-txt-fields': ['security.txt has Contact and a future Expires', 2],
  'exp-error-leak': ['404 page does not leak stack traces or paths', 3],
};
export const IDS = Object.keys(META);

const MAX = 262144;
const CAT = { seo: 'seo', ai: 'ai', ux: 'ux', exp: 'exposure' };
const AI_BOTS = ['GPTBot', 'ChatGPT-User', 'OAI-SearchBot', 'ClaudeBot', 'Claude-Web', 'anthropic-ai', 'PerplexityBot', 'Google-Extended', 'CCBot', 'Bytespider'];
const DEFAULT_HOSTS = ['.vercel.app', '.netlify.app', '.pages.dev', '.github.io', '.onrender.com', '.herokuapp.com', '.web.app'];
const DEFAULT_404 = /Cannot (GET|POST) |<center>\s*nginx|<address>\s*Apache|Not Found<\/h1>\s*<p>The requested URL|^\s*Not Found\s*$/i;
const NOT_PAGE = /\.(pdf|jpe?g|png|gif|svg|webp|zip|css|js|xml|ico|mp4|txt)(\?|$)/i;

const ct = (r) => String(r.headers?.['content-type'] || '').toLowerCase();
const isHtml = (r) => ct(r).includes('html') || /^\s*<(!doctype|html)/i.test(r.body || '');
const attr = (tag, name) => (tag.match(new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i')) || []).slice(1).find((x) => x !== undefined);
const title = (html) => (html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1] || '').replace(/\s+/g, ' ').trim();
const metaDesc = (html) => {
  for (const m of html.matchAll(/<meta\b[^>]*>/gi)) if (/^description$/i.test(attr(m[0], 'name') || '')) return (attr(m[0], 'content') || '').trim();
  return '';
};

// Groups of consecutive User-agent lines with their Disallow paths; plus Sitemap URLs.
export function parseRobots(text) {
  const groups = [], sitemaps = [];
  let cur = null, lastWasAgent = false;
  for (const raw of String(text).split(/\r?\n/)) {
    const m = raw.replace(/#.*/, '').match(/^\s*([A-Za-z-]+)\s*:\s*(.*?)\s*$/);
    if (!m) continue;
    const k = m[1].toLowerCase();
    if (k === 'user-agent') {
      if (!cur || !lastWasAgent) groups.push((cur = { agents: [], disallow: [] }));
      cur.agents.push(m[2].toLowerCase());
      lastWasAgent = true;
      continue;
    }
    lastWasAgent = false;
    if (k === 'sitemap') sitemaps.push(m[2]);
    else if (k === 'disallow' && cur) cur.disallow.push(m[2]);
  }
  return { groups, sitemaps };
}

export async function run(ctx) {
  const out = {};
  const set = (id, status, evidence = '', fix = '') => { out[id] = [status, evidence, fix]; };
  const get = async (url, opts = {}) => {
    try { return await ctx.fetch(url, { maxBytes: MAX, ...opts }); } catch (e) { return { error: e.code || 'error' }; }
  };
  const err = (r) => `error: ${r.error}`;
  const page = ctx.page;
  const html = page.status ? stripInert(page.body) : '';
  const base = page.status ? new URL(page.finalUrl).origin : ctx.target.origin;
  const at = (p) => new URL(p, base).href;
  // Page-type signals from the RAW body (JSON-LD lives in script bodies, which stripInert blanks). null = old strict behaviour.
  let type = null;
  if (page.status) { try { type = pageType(page.body, page.finalUrl); } catch { type = null; } }

  // --- robots.txt
  const rr = await get(at('/robots.txt'));
  let robots = null;
  if (rr.error) set('seo-robots-txt', 'skipped', err(rr));
  else if (rr.status === 200 && !isHtml(rr) && /^\s*user-agent\s*:/im.test(rr.body)) {
    robots = parseRobots(rr.body);
    set('seo-robots-txt', 'pass', 'robots.txt found with User-agent rules');
  } else if (rr.status === 200) set('seo-robots-txt', 'fail', isHtml(rr) ? 'returns HTML (SPA fallback?)' : 'no User-agent line', 'Serve a plain-text robots.txt with at least one User-agent group.');
  else set('seo-robots-txt', 'warn', `HTTP ${rr.status}`, 'Add a robots.txt at the site root.');

  if (robots) {
    const blocksAll = robots.groups.some((g) => g.agents.includes('*') && g.disallow.includes('/'));
    set('ai-robots-blocks-all', blocksAll ? 'fail' : 'pass', blocksAll ? 'User-agent: * has Disallow: /' : 'not blocked', 'Remove "Disallow: /" from the wildcard group unless the site is meant to be private.');
    const blocked = AI_BOTS.filter((b) => robots.groups.some((g) => g.agents.includes(b.toLowerCase()) && g.disallow.includes('/')));
    set('ai-robots-blocks-bots', blocked.length ? 'warn' : 'pass', blocked.length ? `disallowed: ${blocked.join(', ')}` : 'no AI crawler blocked', 'Allow AI crawlers in robots.txt if you want to be visible in AI search.');
    const sens = [...new Set(robots.groups.flatMap((g) => g.disallow).filter((p) => /\/(admin|backup|private|wp-admin|\.git)/i.test(p)))];
    set('seo-robots-sensitive', sens.length ? 'info' : 'pass', sens.length ? `Disallow lists: ${sens.slice(0, 5).join(', ')} (hint only)` : 'none', 'Do not rely on robots.txt to hide paths; protect them with auth.');
  } else for (const id of ['ai-robots-blocks-all', 'ai-robots-blocks-bots', 'seo-robots-sensitive']) set(id, 'skipped', rr.error ? err(rr) : 'no usable robots.txt');

  // --- sitemap
  const listed = robots?.sitemaps[0];
  const sr = await get(listed || at('/sitemap.xml'));
  let sitemapUrls = [];
  if (sr.error) set('seo-sitemap', 'skipped', err(sr));
  else if (sr.status === 200 && /<urlset|<sitemapindex/i.test(sr.body)) {
    sitemapUrls = [...sr.body.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)].map((m) => m[1]);
    set('seo-sitemap', 'pass', `${sitemapUrls.length} <loc> entries`);
  } else if (listed) set('seo-sitemap', 'fail', `listed in robots.txt but HTTP ${sr.status}${sr.status === 200 ? ' / not XML' : ''}`, 'Fix the Sitemap: URL in robots.txt or publish a valid sitemap there.');
  else set('seo-sitemap', 'warn', sr.status === 200 ? '/sitemap.xml is not XML' : `/sitemap.xml HTTP ${sr.status}`, 'Publish /sitemap.xml and list it in robots.txt.');

  // --- llms.txt
  const lr = await get(at('/llms.txt'));
  if (lr.error) set('ai-llms-txt', 'skipped', err(lr));
  else if (lr.status === 200 && !isHtml(lr) && lr.body.length > 20) set('ai-llms-txt', 'pass', 'llms.txt found');
  else set('ai-llms-txt', 'warn', `HTTP ${lr.status}${lr.status === 200 ? ' (HTML or too short)' : ''}`, 'Optionally add /llms.txt describing the site for LLMs.');

  // --- 404 behaviour + error leak (one shared request)
  const nf = await get(at(`/${randomBytes(8).toString('hex')}-nf`));
  // 403 is info only for a tool or a known bot filter (Cloudflare challenge); a marketing site on S3/CloudFront answering 403 still warns.
  const BOT_FILTER = (r) => !!r.headers?.['cf-mitigated'] || /cf-chl|challenge-platform|Just a moment.../i.test(r.body || '');
  if (nf.error) {
    set('ux-404-page', 'skipped', err(nf));
    set('exp-error-leak', 'skipped', err(nf));
  } else {
    if (nf.status === 200) set('ux-404-page', 'fail', 'random path returns HTTP 200 (soft 404)', 'Return HTTP 404 for unknown URLs.');
    else if (nf.status === 401 || (nf.status === 403 && (type?.isSinglePageTool || BOT_FILTER(nf)))) set('ux-404-page', 'info', `unknown paths answer HTTP ${nf.status} (auth-gated or filtering host); custom 404 not assessable`);
    else if (nf.status === 404 && nf.body.length >= 300 && !DEFAULT_404.test(nf.body)) set('ux-404-page', 'pass', 'HTTP 404 with a custom page');
    else if (nf.status === 404 && type?.isSinglePageTool) set('ux-404-page', 'info', 'real HTTP 404; a custom 404 page is not needed on a single-page tool');
    else if (nf.status === 404) set('ux-404-page', 'warn', 'HTTP 404 but tiny or server-default body', 'Add a helpful custom 404 page with navigation.');
    else set('ux-404-page', 'warn', `random path returns HTTP ${nf.status}`, 'Return HTTP 404 with a custom page for unknown URLs.');
    const leak = /\bat .* \(.*:\d+:\d+\)/.test(nf.body) ? 'stack frame' : /Traceback \(most recent/.test(nf.body) ? 'Traceback' : /C:\\|\/var\/www/.test(nf.body) ? 'absolute path' : '';
    set('exp-error-leak', leak ? 'fail' : 'pass', leak ? `404 body contains a ${leak}` : 'no stack/path patterns', 'Disable debug output and show generic error pages in production.');
  }

  // --- favicon
  // rel tokens must be exactly "icon" (so "apple-touch-icon" alone does not count; "shortcut icon" does)
  if ([...html.matchAll(/<link\b[^>]*>/gi)].some((m) => (attr(m[0], 'rel') || '').toLowerCase().split(/\s+/).includes('icon'))) set('ux-favicon', 'pass', '<link rel=icon> found');
  else {
    const fr = await get(at('/favicon.ico'), { maxBytes: 1024 });
    if (fr.error) set('ux-favicon', 'skipped', err(fr));
    else if (fr.status === 200 && ct(fr).startsWith('image/')) set('ux-favicon', 'pass', '/favicon.ico found');
    else set('ux-favicon', 'warn', 'no <link rel=icon> and no /favicon.ico', 'Add a favicon.');
  }

  // --- default hostname
  const fh = new URL(page.finalUrl).hostname;
  const dh = DEFAULT_HOSTS.find((s) => fh.endsWith(s));
  set('ux-default-hostname', dh ? 'warn' : 'pass', dh ? `served from ${fh}` : fh, 'Use a custom domain instead of the hosting provider default.');

  // --- crawl <=10 same-origin pages for duplicate titles/descriptions
  const seen = new Set([page.finalUrl.split('#')[0]]);
  const cands = [];
  const hrefs = [...html.matchAll(/<a\b[^>]*\bhref\s*=\s*["']([^"'#][^"']*)["']/gi)].map((m) => m[1]);
  for (const h of [...hrefs, ...sitemapUrls]) {
    let u;
    try { u = new URL(h, page.finalUrl); } catch { continue; }
    u.hash = '';
    if (!/^https?:$/.test(u.protocol) || u.origin !== base || NOT_PAGE.test(u.pathname) || seen.has(u.href)) continue;
    seen.add(u.href);
    cands.push(u.href);
  }
  const crawled = (await Promise.all(cands.slice(0, 9).map((u) => get(u)))).filter((r) => !r.error && r.status === 200 && isHtml(r));
  const docs = (html ? [html] : []).concat(crawled.map((r) => r.body));
  if (docs.length < 2) set('seo-duplicate-titles', 'info', `only ${docs.length} page(s) found to compare`);
  else {
    const dup = (vals) => { const c = {}; for (const v of vals.filter(Boolean)) c[v] = (c[v] || 0) + 1; return Object.values(c).filter((n) => n > 1).length; };
    const dt = dup(docs.map(title)), dd = dup(docs.map(metaDesc));
    if (dt) set('seo-duplicate-titles', 'fail', `${dt} duplicated title(s) across ${docs.length} pages`, 'Give every page a unique <title>.');
    else if (dd) set('seo-duplicate-titles', 'warn', `${dd} duplicated meta description(s) across ${docs.length} pages`, 'Give every page a unique meta description.');
    else set('seo-duplicate-titles', 'pass', `${docs.length} pages, all unique`);
  }

  // --- thank-you page (a 200 equal to the 404/home shell does not count)
  // Only search/tool, login or button-only forms on the page: nothing to thank for, so no fetches.
  if (type && type.formCount > 0 && !type.hasLeadForm) set('ux-thank-you', 'skipped', type.onlySearchForms ? 'no lead or conversion form: only search/tool form(s) on the page' : 'no lead or conversion form: only login, search/tool or button-only form(s) on the page');
  else {
    const ty = await Promise.all(['/thank-you', '/thanks', '/aitah', '/tanks'].map((p) => get(at(p))));
    const shell = (r) => r.body.slice(0, 1024) === (nf.body || '').slice(0, 1024) || r.body.slice(0, 1024) === html.slice(0, 1024);
    const tyOk = ty.some((r) => !r.error && r.status === 200 && isHtml(r) && !shell(r));
    if (tyOk) set('ux-thank-you', 'pass', 'thank-you page found');
    else if (ty.every((r) => r.error)) set('ux-thank-you', 'skipped', err(ty[0]));
    else if (type ? type.hasLeadForm : /<form\b/i.test(html)) set('ux-thank-you', 'warn', 'form present but no thank-you page found', 'Add a thank-you page after form submission (also useful for conversion tracking).');
    else set('ux-thank-you', 'info', 'no thank-you page and no form');
  }

  // --- JS bundles: size, compression, source maps (<=3 same-origin scripts)
  const scripts = [];
  for (const m of html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']?([^"'\s>]+)/gi)) {
    try {
      const u = new URL(m[1], page.finalUrl);
      if (u.origin === base && !scripts.includes(u.href)) scripts.push(u.href);
    } catch { /* ignore bad src */ }
  }
  const files = [];
  for (const u of scripts.slice(0, 3)) {
    // Range: tail only. Big bundles keep their sourceMappingURL comment at the very end; a server that ignores
    // Range sends the whole file (capped at 1 MiB by ctx.fetch). Identity encoding, so the tail is readable text.
    const g = await get(u, { maxBytes: 1048576, headers: { range: 'bytes=-2048' } });
    if (g.error || (g.status !== 200 && g.status !== 206)) continue;
    // ponytail: HEAD to learn Content-Encoding/transferred size; servers that mishandle HEAD are treated as "unknown"
    const h = await get(u, { method: 'HEAD', headers: { 'accept-encoding': 'gzip, br' }, maxBytes: 1024 });
    const enc = h.error || h.status !== 200 ? null : h.headers['content-encoding'] || '';
    const cl = Number(h.headers?.['content-length']);
    const tail = g.status === 206;
    const clen = Number(g.headers['content-length']);
    const whole = tail ? Number(/\/(\d+)\s*$/.exec(g.headers['content-range'] || '')?.[1]) : clen || g.body.length;
    // atLeast: the size is a lower bound; blind: the tail (where the map comment lives) was not seen
    files.push({ url: u, g, enc, size: enc && cl ? cl : whole || g.body.length,
      atLeast: tail ? !whole : g.truncated && !clen, blind: !tail && g.truncated });
  }
  if (!scripts.length) {
    set('ux-js-bundle-size', 'info', 'no same-origin scripts');
    set('exp-source-maps', 'skipped', 'no same-origin scripts');
  } else if (!files.length) {
    set('ux-js-bundle-size', 'skipped', 'scripts not fetchable');
    set('exp-source-maps', 'skipped', 'scripts not fetchable');
  } else {
    const total = files.reduce((s, f) => s + f.size, 0);
    const kb = (n) => Math.round(n / 1024) + ' KB';
    const plain = files.filter((f) => f.enc === '' && f.size > 1024).length;
    const big = files.some((f) => f.size > 300 * 1024);
    const note = `${files.length} script(s), ${files.some((f) => f.atLeast) ? '>= ' : ''}${kb(total)} total${plain ? `, ${plain} uncompressed` : ''}`;
    if (total > 1024 * 1024) set('ux-js-bundle-size', 'fail', note, 'Split, tree-shake and compress the JavaScript bundles.');
    else if (total > 500 * 1024 || big || plain) set('ux-js-bundle-size', 'warn', note, 'Reduce bundle size and enable gzip/brotli.');
    else set('ux-js-bundle-size', 'pass', note);

    const exposed = [];
    for (const f of files) {
      const ref = f.g.headers.sourcemap || f.g.headers['x-sourcemap'] || f.g.body.slice(-2048).match(/\/\/[#@]\s*sourceMappingURL=(\S+)/)?.[1];
      if (!ref || ref.startsWith('data:')) continue;
      let mu;
      try { mu = new URL(ref, f.url).href; } catch { continue; }
      const mr = await get(mu, { maxBytes: 1024 });
      if (!mr.error && mr.status === 200 && !ct(mr).includes('html')) exposed.push(new URL(f.url).pathname);
    }
    const blind = files.some((f) => f.blind);
    if (exposed.length) set('exp-source-maps', 'warn', `source map reachable for: ${exposed.join(', ')}`, 'Do not publish .map files to production (or restrict them).');
    else if (blind) set('exp-source-maps', 'info', 'a bundle is over 1 MiB and the server ignores Range: its tail was not checked');
    else set('exp-source-maps', 'pass', 'none referenced or reachable', '');
  }

  // --- security.txt (RFC 9116)
  let sec = await get(at('/.well-known/security.txt'));
  let secBody = null;
  const okBody = (r) => !r.error && r.status === 200 && !isHtml(r);
  if (sec.error) set('exp-security-txt', 'skipped', err(sec));
  else if (okBody(sec)) {
    secBody = sec.body;
    if (ct(sec).startsWith('text/plain')) set('exp-security-txt', 'pass', '/.well-known/security.txt found');
    else set('exp-security-txt', 'warn', `served as "${ct(sec) || 'no content-type'}"`, 'Serve security.txt as text/plain.');
  } else {
    sec = await get(at('/security.txt'));
    if (okBody(sec)) {
      secBody = sec.body;
      set('exp-security-txt', 'warn', 'only at legacy /security.txt', 'Move security.txt to /.well-known/security.txt.');
    } else set('exp-security-txt', 'info', 'no security.txt', 'Publish /.well-known/security.txt with a Contact and an Expires field.');
  }
  if (secBody === null) set('exp-security-txt-fields', 'skipped', 'no security.txt');
  else {
    const contact = /^\s*contact\s*:\s*\S+/im.test(secBody);
    const exp = secBody.match(/^\s*expires\s*:\s*(.+?)\s*$/im)?.[1];
    const t = exp ? Date.parse(exp) : NaN;
    const problems = [!contact && 'Contact missing', !exp && 'Expires missing', exp && (isNaN(t) ? 'Expires unparsable' : t < Date.now() && 'Expires in the past')].filter(Boolean);
    set('exp-security-txt-fields', problems.length ? 'warn' : 'pass', problems.length ? problems.join('; ') : 'Contact and Expires valid', 'Add a Contact and a future Expires (RFC 9116).');
  }

  return IDS.map((id) => {
    const [status, evidence, fix] = out[id] || ['skipped', 'not evaluated', ''];
    const [t, sev, checklist] = META[id];
    return finding(id, CAT[id.split('-')[0]], t, status, sev, { evidence, fix: status === 'pass' ? '' : fix, checklist });
  });
}
