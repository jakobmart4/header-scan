// HTML checks (SEO / UX hygiene / structured data). Raw HTML only: no DOM, no headless browser.
import { finding } from '../score.js';

// id -> [title, severity, checklist#]
const META = {
  'seo-title': ['Page has a <title>', 3, 31],
  'seo-title-length': ['Title length is 10-60 characters', 1, 31],
  'seo-meta-description': ['Meta description present', 3, 6],
  'seo-meta-desc-length': ['Meta description is 70-160 characters', 1, 6],
  'seo-canonical': ['Canonical URL is absolute and same-host', 2, 11],
  'seo-h1': ['Exactly one <h1>', 3, 9],
  'seo-heading-order': ['Heading levels do not skip', 1],
  'seo-lang': ['<html lang> is valid', 3, 16],
  'seo-viewport': ['Viewport meta tag present', 3],
  'seo-og-image': ['og:image present', 2, 7],
  'seo-og-basic': ['og:title and og:description present', 1],
  'seo-twitter-card': ['twitter:card present', 1],
  'seo-structured-data': ['Valid JSON-LD structured data', 2, 8],
  'seo-noindex': ['Page is not noindexed', 4],
  'seo-spa-shell': ['Raw HTML has real content (no empty SPA shell)', 4, 2],
  'ux-alt-text': ['Images have alt text', 3, 17],
  'ux-internal-links': ['Internal links present', 2, 23],
  'ux-cta-above-fold': ['Call to action near the top (heuristic)', 1, 22],
  'ux-breadcrumbs': ['Breadcrumbs', 1, 25],
  'ux-case-studies': ['Case studies / portfolio link', 1, 26],
  'ux-faq': ['FAQ content', 1, 27],
  'ux-response-time': ['Response-time promise', 1, 28],
  'ux-maps': ['Map / location embed or link', 1, 34],
  'ux-reviews': ['Reviews / ratings markup or widget', 1, 35],
  'ux-local-schema': ['LocalBusiness schema is complete', 1, 37],
  'ux-privacy-policy': ['Privacy policy link works', 2, 38],
  'ux-analytics': ['Analytics present', 1, 39],
  'ux-team-photo': ['Team / about photo (low confidence)', 1, 40],
  'ux-theme-color': ['theme-color meta tag', 1],
  'ux-console-errors': ['No console errors', 1, 19],
  'ux-sticky-mobile-cta': ['Sticky mobile CTA', 1, 29],
};
export const IDS = Object.keys(META);

// Tokenizer-lite: comments | raw-text elements (script/style/title) | tags. Quote-aware attributes.
const ATTR = `((?:"[^"]*"|'[^']*'|[^'">])*)`;
const TOKEN = () => new RegExp(
  `<!--[\\s\\S]*?-->|<(script|style|title)\\b${ATTR}>([\\s\\S]*?)<\\/\\1\\s*>|<(\\/?)([a-zA-Z][\\w:-]*)${ATTR}>`, 'gi');

function attrs(s) {
  const a = {};
  for (const m of s.matchAll(/([^\s"'<>\/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g)) {
    const k = m[1].toLowerCase();
    if (!(k in a)) a[k] = m[2] ?? m[3] ?? m[4] ?? '';
  }
  return a;
}

const decode = (s) => s.replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#0?39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>');
const squash = (s) => s.replace(/\s+/g, ' ').trim();

function parse(html) {
  const tags = []; // open tags (and script/style/title) with position
  const scripts = [];
  let title;
  for (const m of html.matchAll(TOKEN())) {
    if (m[1]) {
      const n = m[1].toLowerCase();
      const a = attrs(m[2]);
      tags.push({ n, a, pos: m.index, end: m.index + m[0].length });
      if (n === 'script') scripts.push({ a, body: m[3] });
      if (n === 'title' && title === undefined) title = squash(decode(m[3]));
    } else if (m[5] && !m[4]) {
      tags.push({ n: m[5].toLowerCase(), a: attrs(m[6]), pos: m.index, end: m.index + m[0].length });
    }
  }
  const text = squash(html.replace(TOKEN(), ' '));
  return { tags, scripts, title, text };
}

// JSON-LD: flat list of every object node, plus parse-failure count.
function jsonld(scripts) {
  const nodes = [];
  let invalid = 0, blocks = 0;
  const walk = (v) => {
    if (Array.isArray(v)) return v.forEach(walk);
    if (v && typeof v === 'object') { nodes.push(v); Object.values(v).forEach(walk); }
  };
  for (const s of scripts) {
    if ((s.a.type || '').toLowerCase() !== 'application/ld+json') continue;
    try { walk(JSON.parse(s.body)); blocks++; } catch { invalid++; }
  }
  const typesOf = (n) => [].concat(n['@type'] ?? []).map(String);
  return { nodes, invalid, blocks, typesOf, has: (k) => nodes.some((n) => k in n) };
}

const HEADING = /^h[1-6]$/;
const PRIV = /privacy|privaatsus|andmekaitse|cookies/i;
const ANALYTICS = /googletagmanager\.com\/gtag\/js|gtag\(|\bG-[A-Z0-9]{6,}\b|\bUA-\d{4,}-\d+|gtm\.js|\bGTM-[A-Z0-9]+|plausible|matomo|umami|fathom/i;
const CONSENT = /cookie|consent|gdpr|küpsis/i;
const LOCAL_TYPE = /LocalBusiness|Restaurant|Dentist|Physician|Store|Hotel|Attorney|Plumber|Electrician|Salon|AutoRepair|RealEstateAgent|ProfessionalService|Accountant|Bakery|CafeOrCoffeeShop|GymOrHealthClub/;

function context(ctx) {
  const html = String(ctx.page.body).slice(0, 1048576);
  const p = parse(html);
  const d = { ...p, html, ld: jsonld(p.scripts), page: ctx.page, ctx };
  d.meta = (name) => p.tags.find((t) => t.n === 'meta' && [t.a.name, t.a.property].some((v) => v && v.toLowerCase() === name))?.a.content?.trim();
  d.bodyPos = p.tags.find((t) => t.n === 'body')?.pos ?? 0;
  d.count = (n) => p.tags.filter((t) => t.n === n).length;
  d.elText = (t) => {
    const rest = html.slice(t.end, t.end + 600);
    const i = rest.search(/<\/(a|button)\b/i);
    return squash(rest.slice(0, i < 0 ? 200 : i).replace(TOKEN(), ' '));
  };
  d.url = (href) => { try { return new URL(href, ctx.page.finalUrl); } catch { return null; } };
  d.isShell = p.text.length < 200 && p.tags.some((t) => t.n === 'div' && /^(root|app|__next)$/.test(t.a.id || ''));
  d.scriptText = p.scripts.map((s) => `${s.a.src || ''} ${s.body}`).join('\n');
  return d;
}

// Each rule returns [status, evidence, fix].
const RULES = {
  'seo-title': (d) => d.title ? ['pass', `"${d.title}"`, ''] : ['fail', 'no <title> found', 'Add a unique, descriptive <title> in <head>.'],
  'seo-title-length': (d) => !d.title ? ['skipped', 'no title', '']
    : d.title.length < 10 || d.title.length > 60 ? ['warn', `${d.title.length} characters`, 'Keep the title between 10 and 60 characters.']
    : ['pass', `${d.title.length} characters`, ''],
  'seo-meta-description': (d) => d.meta('description') ? ['pass', 'present', ''] : ['fail', 'meta description missing or empty', 'Add <meta name="description" content="..."> summarising the page.'],
  'seo-meta-desc-length': (d) => {
    const v = d.meta('description');
    if (!v) return ['skipped', 'no meta description', ''];
    return v.length < 70 || v.length > 160 ? ['warn', `${v.length} characters`, 'Keep the description between 70 and 160 characters.'] : ['pass', `${v.length} characters`, ''];
  },
  'seo-canonical': (d) => {
    const link = d.tags.find((t) => t.n === 'link' && (t.a.rel || '').toLowerCase().split(/\s+/).includes('canonical'));
    const href = link?.a.href ?? /<([^>]+)>[^,]*?rel="?canonical/i.exec(d.page.headers.link || '')?.[1];
    const fix = 'Add an absolute <link rel="canonical"> pointing at this site.';
    if (!href) return ['warn', 'no canonical link', fix];
    if (!/^https?:\/\//i.test(href)) return ['warn', 'canonical is not absolute', fix];
    const u = d.url(href);
    return u && u.host === d.url(d.page.finalUrl)?.host ? ['pass', u.origin, ''] : ['warn', `canonical points at host ${u?.host}`, 'Point the canonical URL at this host.'];
  },
  'seo-h1': (d) => {
    const n = d.count('h1');
    if (n === 1) return ['pass', '1 <h1>', ''];
    if (n > 1) return ['warn', `${n} <h1> elements`, 'Use a single <h1> per page.'];
    return ['fail', d.isShell ? '0 in raw HTML (empty SPA shell)' : 'no <h1>', 'Add one <h1> describing the page, rendered in the server HTML.'];
  },
  'seo-heading-order': (d) => {
    const lv = d.tags.filter((t) => HEADING.test(t.n)).map((t) => +t.n[1]);
    for (let i = 1; i < lv.length; i++) if (lv[i] > lv[i - 1] + 1) return ['warn', `h${lv[i - 1]} followed by h${lv[i]}`, 'Do not skip heading levels.'];
    return ['pass', `${lv.length} headings`, ''];
  },
  'seo-lang': (d) => {
    const lang = d.tags.find((t) => t.n === 'html')?.a.lang;
    return lang && /^[a-z]{2,3}(-[A-Za-z0-9]+)*$/.test(lang) ? ['pass', lang, ''] : ['fail', lang ? `invalid lang "${lang}"` : '<html lang> missing', 'Set <html lang="en"> (or the page language).'];
  },
  'seo-viewport': (d) => /width\s*=\s*device-width/i.test(d.meta('viewport') || '') ? ['pass', 'width=device-width', ''] : ['fail', 'viewport meta missing', 'Add <meta name="viewport" content="width=device-width, initial-scale=1">.'],
  'seo-og-image': (d) => {
    const v = d.meta('og:image');
    if (!v) return ['fail', 'og:image missing', 'Add <meta property="og:image"> with an absolute image URL.'];
    return /^https?:\/\//i.test(v) ? ['pass', 'absolute URL', ''] : ['warn', 'og:image is not an absolute URL', 'Use an absolute http(s) URL for og:image.'];
  },
  'seo-og-basic': (d) => {
    const miss = ['og:title', 'og:description'].filter((k) => !d.meta(k));
    return miss.length ? ['warn', `missing ${miss.join(', ')}`, 'Add og:title and og:description meta tags.'] : ['pass', 'both present', ''];
  },
  'seo-twitter-card': (d) => d.meta('twitter:card') ? ['pass', d.meta('twitter:card'), ''] : ['warn', 'twitter:card missing', 'Add <meta name="twitter:card" content="summary_large_image">.'],
  'seo-structured-data': (d) => {
    const { ld } = d;
    if (ld.invalid) return ['fail', `${ld.invalid} JSON-LD block(s) are not valid JSON`, 'Fix the JSON syntax of your application/ld+json blocks.'];
    const typed = ld.nodes.filter((n) => '@type' in n);
    return typed.length ? ['pass', `types: ${[...new Set(typed.flatMap(ld.typesOf))].slice(0, 6).join(', ')}`, ''] : ['warn', 'no JSON-LD with @type', 'Add JSON-LD structured data (Organization, LocalBusiness, ...).'];
  },
  'seo-noindex': (d) => {
    const robots = `${d.meta('robots') || ''} ${d.meta('googlebot') || ''}`;
    const hit = /noindex/i.test(robots) ? 'meta robots' : /noindex/i.test(d.page.headers['x-robots-tag'] || '') ? 'X-Robots-Tag header' : '';
    return hit ? ['fail', `noindex via ${hit}`, 'Remove noindex unless the page must stay out of search.'] : ['pass', 'indexable', ''];
  },
  'seo-spa-shell': (d) => {
    if (d.isShell) return ['fail', `empty shell: ${d.text.length} chars of visible text, root div present`, 'Server-render or pre-render the page so crawlers and AI bots see content.'];
    const fp = /\/assets\/index-[\w-]+\.js|\/@vite\/client/.test(d.html) || (d.scripts.some((s) => s.a.type === 'module' && s.a.src) && d.tags.some((t) => t.n === 'div' && /^(root|app)$/.test(t.a.id || '')));
    return fp ? ['warn', `client-side app fingerprint, ${d.text.length} chars of text`, 'Confirm key content is present in the raw HTML (SSR/prerender).'] : ['pass', `${d.text.length} chars of visible text`, ''];
  },
  'ux-alt-text': (d) => {
    const imgs = d.tags.filter((t) => t.n === 'img');
    if (!imgs.length) return ['info', 'no images', ''];
    const miss = imgs.filter((t) => !('alt' in t.a)).length;
    return miss ? ['fail', `${miss} of ${imgs.length} images missing alt`, 'Add alt text (alt="" for decorative images).'] : ['pass', `${imgs.length} images, all with alt`, ''];
  },
  'ux-internal-links': (d) => {
    const base = d.url(d.page.finalUrl);
    const set = new Set();
    for (const t of d.tags) {
      if (t.n !== 'a' || !t.a.href || /^(#|javascript:|mailto:|tel:|data:)/i.test(t.a.href.trim())) continue;
      const u = d.url(t.a.href.trim());
      if (u && base && u.origin === base.origin) set.add(u.pathname + u.search);
    }
    const n = set.size;
    if (n >= 3) return ['pass', `${n} internal links`, ''];
    const fix = 'Link to your other key pages with plain <a href> links.';
    return n ? ['warn', `${n} internal link(s)`, fix] : ['fail', d.isShell ? '0 internal links (SPA shell, links rendered by JS)' : '0 internal links', fix];
  },
  'ux-cta-above-fold': (d) => {
    const hit = d.tags.some((t) => (t.n === 'a' || t.n === 'button') && t.pos >= d.bodyPos && t.pos < d.bodyPos + 3000
      && /\b(contact|book|get|buy|start|call|quote|kontakt|broneeri|telli)|tel:|mailto:/i.test(`${d.elText(t)} ${t.a.href || ''}`));
    return hit ? ['pass', 'CTA-like link/button in first 3000 chars of body (heuristic)', ''] : ['warn', 'no CTA-like link/button in first 3000 chars of body (heuristic)', 'Put a clear call-to-action near the top of the page.'];
  },
  'ux-breadcrumbs': (d) => {
    const hit = d.ld.nodes.some((n) => d.ld.typesOf(n).includes('BreadcrumbList'))
      || d.tags.some((t) => /breadcrumb/i.test(t.a['aria-label'] || '') || /breadcrumb/i.test(t.a.class || ''));
    return hit ? ['pass', 'breadcrumbs found', ''] : ['info', 'no breadcrumbs', ''];
  },
  'ux-case-studies': (d) => {
    const hit = d.tags.find((t) => t.n === 'a' && /case-stud|portfolio|projects|tood|cases|our-work/i.test(t.a.href || ''));
    return hit ? ['pass', `link to ${hit.a.href.slice(0, 80)}`, ''] : ['info', 'no case study / portfolio link', ''];
  },
  'ux-faq': (d) => {
    const faq = d.ld.nodes.filter((n) => d.ld.typesOf(n).includes('FAQPage')).reduce((s, n) => s + [].concat(n.mainEntity ?? []).length, 0);
    const details = d.count('details');
    const section = /\b(FAQ|KKK|korduma)/i.test(d.text) ? (d.text.match(/\?/g) || []).length : 0;
    const n = Math.max(faq, details, section);
    if (n >= 5) return ['pass', `${n} FAQ items`, ''];
    return n ? ['warn', `${n} FAQ items`, 'Aim for at least 5 real customer questions.'] : ['info', 'no FAQ content', ''];
  },
  'ux-response-time': (d) => /within \d+ (hour|business day)|reply within|vastame|24 ?h|1 tööpäeva/i.test(d.text) ? ['pass', 'response-time promise found', ''] : ['info', 'no response-time promise', ''],
  'ux-maps': (d) => {
    const hit = d.tags.some((t) => (t.n === 'iframe' && /google\.[a-z.]+\/maps|maps\.google|openstreetmap/i.test(t.a.src || ''))
      || (t.n === 'a' && /maps\.app\.goo\.gl|goo\.gl\/maps/i.test(t.a.href || '')))
      || d.ld.has('hasMap') || d.ld.has('geo');
    return hit ? ['pass', 'map embed/link found', ''] : ['info', 'no map found', ''];
  },
  'ux-reviews': (d) => d.ld.has('aggregateRating') || d.ld.has('review') || /trustpilot|elfsight|google-reviews/i.test(d.html)
    ? ['pass', 'review markup/widget found (authenticity not verified)', ''] : ['info', 'no reviews found', ''],
  'ux-local-schema': (d) => {
    const biz = d.ld.nodes.find((n) => d.ld.typesOf(n).some((t) => LOCAL_TYPE.test(t)));
    if (!biz) return ['info', 'no LocalBusiness schema', ''];
    const miss = [['address'], ['telephone'], ['openingHours', 'openingHoursSpecification']].filter((ks) => !ks.some((k) => k in biz)).map((ks) => ks[0]);
    return miss.length ? ['warn', `missing ${miss.join(', ')}`, 'Add address, telephone and opening hours to the LocalBusiness JSON-LD.'] : ['pass', 'address, telephone, opening hours present', ''];
  },
  'ux-privacy-policy': async (d) => {
    const link = d.tags.find((t) => t.n === 'a' && t.a.href && PRIV.test(`${t.a.href} ${d.elText(t)}`));
    if (!link) {
      const need = d.count('form') > 0 || ANALYTICS.test(d.scriptText);
      return [need ? 'fail' : 'warn', need ? 'no privacy policy link but page has a form or analytics' : 'no privacy policy link', 'Publish a privacy policy and link it from every page.'];
    }
    const u = d.url(link.a.href.trim());
    if (!u || !/^https?:$/.test(u.protocol)) return ['warn', 'privacy link is not http(s)', 'Link to a real privacy policy page.'];
    try {
      const r = await d.ctx.fetch(u.href, { maxBytes: 262144 });
      return r.status === 200 && r.body.trim() ? ['pass', `${u.pathname} returns 200`, ''] : ['warn', `${u.pathname} returned HTTP ${r.status}${r.body.trim() ? '' : ' (empty)'}`, 'Make the privacy policy link resolve to a real page.'];
    } catch (e) {
      return ['warn', `could not fetch policy: ${e.code || 'error'}`, 'Make the privacy policy link resolve to a real page.'];
    }
  },
  'ux-analytics': (d) => {
    if (!ANALYTICS.test(d.scriptText)) return ['info', 'no analytics detected', ''];
    return ['pass', CONSENT.test(d.html) ? 'analytics detected' : 'analytics detected, no consent/cookie notice keywords found (GDPR hint)', ''];
  },
  'ux-team-photo': (d) => d.tags.some((t) => t.n === 'img' && /team|meeskond|staff|founder|about/i.test(`${t.a.alt || ''} ${t.a.src || ''}`))
    ? ['info', 'team-like image found (low confidence)', ''] : ['info', 'no team-like image found (low confidence)', ''],
  'ux-theme-color': (d) => d.meta('theme-color') ? ['pass', d.meta('theme-color'), ''] : ['info', 'theme-color missing', ''],
  'ux-console-errors': () => ['skipped', 'needs a headless browser (not in v1)', ''],
  'ux-sticky-mobile-cta': () => ['skipped', 'needs a headless browser (not in v1)', ''],
};

export async function run(ctx) {
  const noPage = !ctx.page || !ctx.page.status || !ctx.page.body;
  let d;
  if (!noPage) {
    try { d = context(ctx); } catch (e) { d = null; }
  }
  const out = [];
  for (const id of IDS) {
    const [title, sev, checklist] = META[id];
    const cat = id.startsWith('seo-') ? 'seo' : 'ux';
    let r;
    if (!d) r = ['skipped', 'error: no page body', ''];
    else {
      try { r = await RULES[id](d); } catch (e) { r = ['skipped', `error: ${e.code || e.message}`, '']; }
    }
    out.push(finding(id, cat, title, r[0], sev, { evidence: r[1], fix: r[2], checklist }));
  }
  return out;
}
