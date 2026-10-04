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
const PRIV = /privacy|privaatsus|andmekaitse|isikuandme|datenschutz|confidentialit|privacidad|tietosuoja|integritet|cookie[\s_-]*(policy|notice|statement|poliitika)|k[üu]psis/i;
// Analytics: a known script src, or a real call/ID in an inline script (comments stripped). Bare words in prose or comments do not count.
const ANALYTICS_SRC = /googletagmanager\.com|google-analytics\.com|gtm\.js|plausible|matomo|piwik|umami|fathom|cloudflareinsights|clarity\.ms|hotjar|mixpanel|posthog|segment\.com|connect\.facebook\.net/i;
const ANALYTICS_CALL = /gtag\(|\bdataLayer\b|\b_paq\b|\bG-[A-Z0-9]{6,}\b|\bUA-\d{4,}-\d+|\bGTM-[A-Z0-9]+|\bfbq\(|\b_hsq\b/;
const REVIEW_SRC = /trustpilot|elfsight|google-reviews/i;
const jsNoComments = (js) => js.replace(/\/\*[\s\S]*?\*\/|(^|[^:'"\w])\/\/.*$/gm, '$1');
const filled = (v) => typeof v === 'string' ? v.trim() !== '' : Array.isArray(v) ? v.some(filled)
  : v && typeof v === 'object' ? Object.entries(v).some(([k, x]) => k[0] !== '@' && filled(x)) : v != null;
const CONSENT = /cookie|consent|gdpr|küpsis/i;
const LOCAL_TYPE = /LocalBusiness|Restaurant|Dentist|Physician|Store|Hotel|Attorney|Plumber|Electrician|Salon|AutoRepair|RealEstateAgent|ProfessionalService|Accountant|Bakery|CafeOrCoffeeShop|GymOrHealthClub/;
// Personal-data field hints, tested on name/id/autocomplete and on placeholder/aria-label/title/label text.
// Lookbehinds keep tool fields out: hostname, domain_name, username, ip_address, hotel are not personal. Passwords are handled by type.
const PERSONAL = [
  /(?:full|first|last|sur|nick|company|business|contact|customer)[\s_-]?name/,
  /(?<![a-z]|(?:user|host|domain|file|path|site|server|dir|sub)[\s_-]?)name(?![a-z])/,
  /e-?mail|(?<![a-z])mail(?![a-z])|courriel|correo/,
  /phone|(?<![a-z])tel(?![a-z])|(?<![a-z])telefon|puhelin|mobile|gsm|whatsapp/,
  /(?<![a-z]|(?:ip|mac|web|url|site|website|domain|host)[\s_-]?)address|aadress/,
  /(?<![a-z])zip(?![a-z])|postal|postcode/,
  /nimi|(?<![a-z])nom(?![a-z])|nombre|vorname|nachname|pr[eé]nom/,
  /message|(?<![a-z])msg|enquiry|inquiry|question|consulta|pregunta|nachricht|(?<![a-z])(service|budget|appointment)(?![a-z])/,
  /cc-/,
];
const personalText = (v) => { const x = String(v).toLowerCase(); return PERSONAL.some((r) => r.test(x)) || /\S@\S/.test(x) || /^\s*[+\d][\d\s()-]{6,}$/.test(x); };
// Positive "this is a search/tool box" evidence on a field name/id/autocomplete (whole value).
const TOOLNAME = /^(q|s|k|query|search|keywords?|term|find|filter|lookup|url|uri|link|site|website|host|hostname|domain|domain[_-]?name|ip|ip[_-]?address)$/i;
const LEAD_ACTION = /contact|kontakt|enquiry|inquiry|quote|book|broneeri|subscribe|signup|sign-up|register|order|message|feedback|newsletter/i;
// Links that mean "this page sells or promotes something": CTA words, contact links, app-store links.
const LEADLINK = /\b(contact|book|get|buy|start|call|quote|download|install|try|sign ?up|log ?in|free|demo|trial|pricing|subscribe|join|kontakt|broneeri|telli)\b|tel:|mailto:|apps\.apple\.com|play\.google\.com/i;
// Legal/utility pages (like the page itself and /) are not "other pages" for tool detection.
const UTILITY_PATH = /^\/(privacy|terms|tos|imprint|impressum|legal|cookies?|disclaimer|accessibility|security(\.txt)?|robots\.txt|sitemap[^/]*|llms(-full)?\.txt|\.well-known|privaatsus|andmekaitse|kasutustingimused)(\/|$|[-_.])/i;
const COMMERCE_PATH = /(cart|checkout|basket)(\/|\?|$)/i;
const COMMERCE_SRC = /stripe|paypal|shopify|woocommerce/i;
const CASE_PATH = /(^|\/)(case-stud(y|ies)|portfolio|projects|tood|cases|our-work)(\/|$|[-_.])/i;
// Page-type signals for the applicability-aware ux-* rules and site.js (docs/UX-SPEC.md). Pure: no network, never throws.
// Unknown stays strict: a form that cannot be shown to be a search/tool box is a lead form.
// Linear in the input: form/noscript scans use sorted positions and moving indexes (a 1 MiB page of "<form>" must not stall the scanner).
let memo; // one-entry cache: html.js and site.js classify the same body in one scan
const lowerBound = (arr, pos) => { let lo = 0, hi = arr.length; while (lo < hi) { const m = (lo + hi) >> 1; if (arr[m].pos < pos) lo = m + 1; else hi = m; } return lo; };
export function pageType(html, finalUrl, parsed) {
  const h = String(html ?? '').slice(0, 1048576);
  if (memo && memo.h === h && memo.u === finalUrl) return memo.v;
  const p = parsed ?? parse(h);
  const abs = (href) => { try { return new URL(href, finalUrl); } catch { return null; } };
  const base = abs('');
  const isAppShell = p.text.length < 200 && p.tags.some((t) => t.n === 'div' && /^(root|app|__next)$/.test(t.a.id || ''));
  const types = new Set(jsonld(p.scripts).nodes.flatMap((n) => [].concat(n['@type'] ?? []).map(String)));
  const app = types.has('WebApplication') || types.has('SoftwareApplication');

  // <noscript> ranges: forms inside are not real forms. Closes are matched with one moving index.
  const nsClose = [...h.matchAll(/<\/noscript\b/gi)].map((m) => m.index);
  const ns = [];
  for (let i = 0, k = 0, upto = -1; i < p.tags.length; i++) {
    const t = p.tags[i];
    if (t.n !== 'noscript' || t.pos < upto) continue;
    while (k < nsClose.length && nsClose[k] < t.end) k++;
    if (k < nsClose.length) { ns.push([t.pos, nsClose[k]]); upto = nsClose[k]; }
  }

  // Each counted form gets its controls (input/textarea/select/button between its tag and the next </form or <form) and a class:
  // lead (default), search (positive tool/search evidence), auth (login: password is the only personal field), inert (controls, nothing to type).
  const formTags = p.tags.filter((t) => t.n === 'form');
  const closes = [...h.matchAll(/<\/form\b/gi)].map((m) => m.index);
  const ctrl = p.tags.filter((t) => /^(input|textarea|select|button)$/.test(t.n));
  let labels; // label[for] id -> text, built once and only if a form needs it
  const labelOf = (id) => {
    if (!id) return '';
    labels ??= new Map(p.tags.filter((t) => t.n === 'label' && t.a.for).map((t) => [t.a.for, h.slice(t.end, t.end + 120).split(/<\/label/i)[0].replace(/<[^>]*>/g, ' ')]));
    return labels.get(id) || '';
  };
  const typeOf = (t) => (t.a.type || '').trim().toLowerCase();
  const classify = (f, fields) => {
    if (!fields.length) return 'lead'; // unknown (empty, JS-rendered) stays strict
    const vis = fields.filter((t) => t.n === 'textarea' || t.n === 'select' || (t.n === 'input' && !/^(hidden|submit|button|reset|image)$/.test(typeOf(t))));
    if (!vis.length) return 'inert'; // logout / consent / toggle: collects nothing
    const other = vis.some((t) => (t.n === 'textarea' && !app) || /^(email|tel|file)$/.test(typeOf(t))
      || personalText(`${t.a.name || ''} ${t.a.id || ''} ${t.a.autocomplete || ''}`)
      || personalText(`${t.a.placeholder || ''} ${t.a['aria-label'] || ''} ${t.a.title || ''} ${labelOf(t.a.id)}`));
    if (other) return 'lead';
    const action = (f.a.action || '').trim(), post = /^post$/i.test(f.a.method || '');
    if (LEAD_ACTION.test(action) || (post && !/search|find|lookup/i.test(action))) return 'lead';
    if (vis.some((t) => typeOf(t) === 'password')) return 'auth';
    const get = !post && action !== '' && action !== '#' && !/^javascript:/i.test(action);
    const positive = app || get || (f.a.role || '').toLowerCase() === 'search'
      || vis.some((t) => typeOf(t) === 'search' || [t.a.name, t.a.id, t.a.autocomplete].some((v) => TOOLNAME.test((v || '').trim())));
    return positive ? 'search' : 'lead';
  };
  const forms = [];
  for (let i = 0, ci = 0, ni = 0; i < formTags.length; i++) {
    const f = formTags[i];
    while (ni < ns.length && ns[ni][1] <= f.pos) ni++;
    if (ni < ns.length && ns[ni][0] <= f.pos) continue;
    while (ci < closes.length && closes[ci] < f.end) ci++;
    const stop = Math.min(closes[ci] ?? Infinity, formTags[i + 1]?.pos ?? Infinity);
    const fields = [];
    for (let k = lowerBound(ctrl, f.end); k < ctrl.length && ctrl[k].pos < stop; k++) fields.push(ctrl[k]);
    const action = (f.a.action || '').trim();
    forms.push({ cls: classify(f, fields), jsOnly: action === '' || action === '#' || /^javascript:/i.test(action) });
  }
  const hasLeadForm = forms.some((f) => f.cls === 'lead');
  const searchForm = forms.some((f) => f.cls === 'search');

  const links = p.tags.filter((t) => t.n === 'a' && t.a.href).map((t) => t.a.href.trim());
  const host = (u) => u.host.replace(/^www\./i, '');
  const internal = new Set(), pages = new Set(); // pages: internal links minus the page itself, "/" and legal/utility paths
  for (const href of links) {
    if (/^(#|javascript:|mailto:|tel:|data:)/i.test(href)) continue;
    const u = abs(href);
    if (!u || !base || host(u) !== host(base)) continue;
    internal.add(u.pathname + u.search);
    if (u.pathname !== base.pathname && u.pathname !== '/' && !UTILITY_PATH.test(u.pathname)) pages.add(u.pathname + u.search);
  }
  const hasContactLink = links.some((href) => /^(tel|mailto):/i.test(href));
  // JSON-LD Product (not Offer) | cart/checkout/basket link | "add to cart" text | payment/shop script. A bare /shop link is not commerce.
  const hasCommerce = types.has('Product')
    || links.some((href) => { const u = abs(href); return u && /^https?:$/.test(u.protocol) && COMMERCE_PATH.test(u.pathname + u.search); })
    || /add to (cart|basket)/i.test(p.text)
    || p.scripts.some((s) => COMMERCE_SRC.test(s.a.src || ''));
  const hasTracker = p.scripts.some((s) => ANALYTICS_SRC.test(s.a.src || '') || ANALYTICS_CALL.test(jsNoComments(s.body)));
  // Any link (also cross-origin: app.example.com, app stores) whose text or href reads like a sales/sign-up call to action.
  const promo = () => p.tags.some((t) => t.n === 'a' && t.a.href
    && LEADLINK.test(`${t.a.href} ${h.slice(t.end, t.end + 300).split(/<\/a\b/i)[0].replace(/<[^>]*>/g, ' ')}`));

  // Tool = no shell, at most one real other page, no lead form, no shop, no contact link (unless an app-typed page has a search form),
  // and positive evidence: app JSON-LD with a search/tool form or no promo links, or exactly one JS-only search form and no promo links.
  // ponytail: a tool whose other pages exist but are unlinked on the scanned page is treated as single-page
  // (evidence says "single-page tool" so the reader can tell why). A tracker does not stop tool status.
  const evidence = (app && (searchForm || !promo())) || (forms.length === 1 && forms[0].cls === 'search' && forms[0].jsOnly && !promo());
  const isSinglePageTool = !isAppShell && pages.size <= 1 && !hasLeadForm && !hasCommerce && (!hasContactLink || (app && searchForm)) && evidence;
  const v = { isAppShell, formCount: forms.length, hasLeadForm, hasAuthForm: forms.some((f) => f.cls === 'auth'), onlySearchForms: forms.every((f) => f.cls === 'search'),
    hasCommerce, hasTracker, internalLinks: internal.size, hasContactLink, isSinglePageTool };
  memo = { h, u: finalUrl, v };
  return v;
}

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
  d.type = pageType(html, ctx.page.finalUrl, p);
  d.isShell = d.type.isAppShell;
  d.analytics = d.type.hasTracker;
  d.hText = (t) => { // text of a heading element
    const rest = html.slice(t.end, t.end + 300);
    const i = rest.search(new RegExp(`</${t.n}\\b`, 'i'));
    return squash(rest.slice(0, i < 0 ? 200 : i).replace(TOKEN(), ' '));
  };
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
  'seo-viewport': (d) => /width\s*=\s*device-width/i.test(d.meta('viewport') || '') ? ['pass', 'width=device-width', '']
    : d.tags.some((t) => t.n === 'meta' && t.a.name?.toLowerCase() === 'viewport') ? ['warn', 'viewport lacks width=device-width', 'Use <meta name="viewport" content="width=device-width, initial-scale=1">.']
      : ['fail', 'viewport meta missing','Add <meta name="viewport" content="width=device-width, initial-scale=1">.'],
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
    if (d.type.isSinglePageTool) return ['skipped', 'single-page tool: no other pages to link to', ''];
    const n = d.type.internalLinks;
    if (n >= 3) return ['pass', `${n} internal links`, ''];
    const fix = 'Link to your other key pages with plain <a href> links.';
    return n ? ['warn', `${n} internal link(s)`, fix] : ['fail', d.isShell ? '0 internal links (SPA shell, links rendered by JS)' : '0 internal links', fix];
  },
  'ux-cta-above-fold': (d) => {
    if (d.type.isSinglePageTool) return ['skipped', 'single-page tool: the on-page form is the primary action', ''];
    const hit = d.tags.some((t) => (t.n === 'a' || t.n === 'button') && t.pos >= d.bodyPos && t.pos < d.bodyPos + 3000
      && /\b(contact|book|get|buy|start|call|quote|kontakt|broneeri|telli)\b|tel:|mailto:/i.test(`${d.elText(t)} ${t.a.href || ''}`));
    return hit ? ['pass', 'CTA-like link/button in first 3000 chars of body (heuristic)', ''] : ['warn', 'no CTA-like link/button in first 3000 chars of body (heuristic)', 'Put a clear call-to-action near the top of the page.'];
  },
  'ux-breadcrumbs': (d) => {
    const hit = d.ld.nodes.some((n) => d.ld.typesOf(n).includes('BreadcrumbList'))
      || d.tags.some((t) => /breadcrumb/i.test(t.a['aria-label'] || '') || /breadcrumb/i.test(t.a.class || ''));
    return hit ? ['pass', 'breadcrumbs found', ''] : ['info', 'no breadcrumbs', ''];
  },
  'ux-case-studies': (d) => {
    // same-origin links only, matched on whole path segments (not external links or slug substrings)
    const host = d.url(d.page.finalUrl)?.host;
    const hit = d.tags.find((t) => { const u = t.n === 'a' && t.a.href && d.url(t.a.href.trim()); return u && u.host === host && CASE_PATH.test(u.pathname); });
    return hit ? ['pass', `link to ${hit.a.href.slice(0, 80)}`, ''] : ['info', 'no case study / portfolio link', ''];
  },
  'ux-faq': (d) => {
    const faq = d.ld.nodes.filter((n) => d.ld.typesOf(n).includes('FAQPage')).reduce((s, n) => s + [].concat(n.mainEntity ?? []).length, 0);
    const details = d.count('details') >= 2 ? d.count('details') : 0; // a lone <details> is a disclosure widget
    // question-style headings count only when a heading names the FAQ
    const hs = d.tags.filter((t) => HEADING.test(t.n)).map(d.hText);
    const section = hs.some((x) => /\b(FAQ|KKK|korduma)/i.test(x)) ? hs.filter((x) => x.endsWith('?')).length : 0;
    const n = Math.max(faq, details, section);
    if (n >= 5) return ['pass', `${n} FAQ items`, ''];
    if (d.type.isSinglePageTool) return ['skipped', 'single-page tool: FAQ content not expected', ''];
    return n ? ['warn', `${n} FAQ items`, 'Aim for at least 5 real customer questions.'] : ['info', 'no FAQ content', ''];
  },
  'ux-response-time': (d) => /within \d+ (hour|business day)|reply within|vastame|\b24 ?h\b|1 tööpäeva/i.test(d.text) ? ['pass', 'response-time promise found', ''] : ['info', 'no response-time promise', ''],
  'ux-maps': (d) => {
    const hit = d.tags.some((t) => (t.n === 'iframe' && /google\.[a-z.]+\/maps|maps\.google|openstreetmap/i.test(t.a.src || ''))
      || (t.n === 'a' && /maps\.app\.goo\.gl|goo\.gl\/maps/i.test(t.a.href || '')))
      || d.ld.has('hasMap') || d.ld.has('geo');
    return hit ? ['pass', 'map embed/link found', ''] : ['info', 'no map found', ''];
  },
  'ux-reviews': (d) => d.ld.has('aggregateRating') || d.ld.has('review')
    || d.tags.some((t) => (t.n === 'script' || t.n === 'iframe' || t.n === 'a') && REVIEW_SRC.test(t.a.src || t.a.href || ''))
    ? ['pass', 'review markup/widget found (authenticity not verified)', ''] : ['info', 'no reviews found', ''],
  'ux-local-schema': (d) => {
    const biz = d.ld.nodes.find((n) => d.ld.typesOf(n).some((t) => LOCAL_TYPE.test(t)));
    if (!biz) return ['info', 'no LocalBusiness schema', ''];
    const miss = [['address'], ['telephone'], ['openingHours', 'openingHoursSpecification']].filter((ks) => !ks.some((k) => filled(biz[k]))).map((ks) => ks[0]);
    return miss.length ? ['warn', `missing ${miss.join(', ')}`, 'Add address, telephone and opening hours to the LocalBusiness JSON-LD.'] : ['pass', 'address, telephone, opening hours present', ''];
  },
  'ux-privacy-policy': async (d) => {
    const hits = d.tags.filter((t) => t.n === 'a' && t.a.href && PRIV.test(`${t.a.href} ${d.elText(t)}`));
    const link = hits.find((t) => !/^s*(#|javascript:|mailto:|tel:|data:)/i.test(t.a.href)) ?? hits[0]; // a javascript:/# anchor is not the policy
    if (!link) {
      const t = d.type;
      const fix = 'Publish a privacy policy and link it from every page.';
      if (t.hasLeadForm || t.hasTracker) return ['fail', 'no privacy policy link but page has a form or analytics', fix];
      if (t.hasCommerce) return ['fail', 'no privacy policy link but page has checkout/cart links', fix];
      if (t.isSinglePageTool) return ['info', 'no personal-data form or tracker found in the raw HTML (single-page tool); add a policy if the server logs or stores user input', ''];
      return ['warn', 'no privacy policy link', fix];
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
    if (!d.analytics) return ['info', 'no analytics detected', ''];
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
