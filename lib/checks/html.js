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

// Tokenizer-lite: comments | raw-text elements (script/style/title) | tags | doctype/xml declarations. Quote-aware attributes.
// Linear on hostile input: a missing terminator ("-->", closing quote, "</script>", ">") is searched for once and remembered, and the
// work spent on tags that never close is budgeted (the rest of the page then counts as text). Never a backtracking regex over the whole body.
const NAME = /[a-zA-Z][\w:-]*/y;
const RAW = /(script|style|title)\b/iy;
const PLAIN = /[^'">]*/y;
const RAW_CLOSE = { script: /<\/script\s*>/gi, style: /<\/style\s*>/gi, title: /<\/title\s*>/gi };
// ponytail: tags past this count are still tokenized (the text stays right) but not kept, so a 1 MiB page of "<p>" cannot hold
// hundreds of MB of tag objects; a real page has a few thousand tags.
const MAX_TAGS = 50000;
const NO_ATTRS = Object.freeze({});

function attrs(s) {
  let a = NO_ATTRS; // shared by every attribute-less tag
  for (const m of s.matchAll(/([^\s"'<>\/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g)) {
    if (a === NO_ATTRS) a = {};
    const k = m[1].toLowerCase();
    if (!(k in a)) a[k] = m[2] ?? m[3] ?? m[4] ?? '';
  }
  return a;
}

const decode = (s) => s.replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#0?39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>');
const squash = (s) => s.replace(/\s+/g, ' ').trim();

// textOnly: keep no tags, only the text (link text, labels, headings: comments, script/style bodies and quoted ">" handled like the page).
function tokenize(html, textOnly = false) {
  const tags = []; // open tags (and script/style/title) with position
  const scripts = [];
  const gaps = []; // text between tokens
  let title;
  const n = html.length, budget = 2 * n + 65536;
  let work = 0, last = 0, i = 0;
  let noComment = false, noGt = false;
  const noClose = {}, noQuote = { '"': Infinity, "'": Infinity }; // first index after which that terminator does not exist
  // End index of the ">" that closes a tag whose attributes start at j, or -1 (quotes may hide ">").
  const tagEnd = (j) => {
    const from = j;
    for (;;) {
      PLAIN.lastIndex = j; PLAIN.test(html); j = PLAIN.lastIndex;
      const ch = html[j];
      if (ch === '>') return j;
      if (ch === undefined) break;
      const k = j >= noQuote[ch] ? -1 : html.indexOf(ch, j + 1);
      if (k < 0) { noQuote[ch] = Math.min(noQuote[ch], j); break; }
      j = k + 1;
    }
    work += j - from + 1;
    return -1;
  };
  const token = (start, end) => { gaps.push(html.slice(last, start)); last = end; };
  while (work <= budget && (i = html.indexOf('<', i)) >= 0) {
    const c = html[i + 1];
    if (c === '!' && html.startsWith('--', i + 2)) {
      const e = noComment ? -1 : html.indexOf('-->', i + 4);
      if (e < 0) { noComment = true; i++; continue; }
      token(i, e + 3); i = e + 3; continue;
    }
    if (c === '!' || c === '?') { // <!doctype ...>, <?xml ...?>: not content
      const e = noGt ? -1 : html.indexOf('>', i + 2);
      if (e < 0) { noGt = true; i++; continue; }
      token(i, e + 1); i = e + 1; continue;
    }
    const closing = c === '/';
    NAME.lastIndex = i + (closing ? 2 : 1);
    if (!NAME.test(html)) { i++; continue; }
    const e = tagEnd(NAME.lastIndex);
    if (e < 0) { i++; continue; }
    RAW.lastIndex = i + 1;
    const raw = closing ? null : RAW.exec(html)?.[1].toLowerCase();
    const re = raw && RAW_CLOSE[raw];
    let close = null;
    if (re && !(raw in noClose && e + 1 >= noClose[raw])) {
      re.lastIndex = e + 1;
      close = re.exec(html);
      if (!close) noClose[raw] = e + 1;
    }
    const keep = !textOnly && tags.length < MAX_TAGS;
    if (close) {
      const end = close.index + close[0].length;
      if (keep) {
        const a = attrs(html.slice(NAME.lastIndex, e));
        tags.push({ n: raw, a, pos: i, end });
        if (raw === 'script') scripts.push({ a, body: html.slice(e + 1, close.index) });
        if (raw === 'title' && title === undefined) title = squash(decode(html.slice(e + 1, close.index)));
      }
      token(i, end); i = end; continue;
    }
    if (!closing && keep) tags.push({ n: html.slice(i + 1, NAME.lastIndex).toLowerCase(), a: attrs(html.slice(NAME.lastIndex, e)), pos: i, end: e + 1 });
    token(i, e + 1); i = e + 1;
  }
  gaps.push(html.slice(last));
  return { tags, scripts, title, text: squash(gaps.join(' ')) };
}

let parsed; // one-entry cache: html.js (context) and site.js (pageType) parse the same body in one scan
function parse(html) {
  if (parsed && parsed.h === html) return parsed.v;
  const v = tokenize(html);
  parsed = { h: html, v };
  return v;
}
// Text of a small slice (link text, label, heading). Linear like the page parse.
const stripTags = (s) => tokenize(s, true).text;

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
  // Only string types count: String() on a hostile object ({"toString":1}) throws and would void every HTML finding.
  const typesOf = (n) => [].concat(n['@type'] ?? []).filter((t) => typeof t === 'string');
  return { nodes, invalid, blocks, typesOf, has: (k) => nodes.some((n) => k in n) };
}

const HEADING = /^h[1-6]$/;
const PRIV = /privacy|privaatsus|andmekaitse|isikuandme|datenschutz|confidentialit|privacidad|tietosuoja|integritet|cookie[\s_-]*(policy|notice|statement|poliitika)|k[üu]psis/i;
// Analytics: a known script src, or a real call/ID in an inline script (comments stripped). Bare words in prose or comments do not count.
const ANALYTICS_SRC = /googletagmanager\.com|google-analytics\.com|gtm\.js|plausible|matomo|piwik|umami|fathom|cloudflareinsights|clarity\.ms|hotjar|mixpanel|posthog|segment\.com|connect\.facebook\.net/i;
const ANALYTICS_CALL =/gtag\(|\bdataLayer\b|\b_paq\b|\bG-[A-Z0-9]{6,}\b|\bUA-\d{4,}-\d+|\bGTM-[A-Z0-9]+|\bfbq\(|\b_hsq\b/;
const REVIEW_SRC = /trustpilot|elfsight|google-reviews/i;
// One pass: an unclosed "/*" is searched for once, not once per opener (a body of "/*/*/*..." must not go quadratic).
function jsNoComments(js) {
  const re = /\/\*|(^|[^:'"\w])\/\/.*$/gm;
  let out = '', last = 0, m, noEnd = false;
  while ((m = re.exec(js))) {
    if (m[0] === '/*') {
      const e = noEnd ? -1 : js.indexOf('*/', m.index + 2);
      if (e < 0) { noEnd = true; continue; }
      out += js.slice(last, m.index); last = re.lastIndex = e + 2;
    } else { out += js.slice(last, m.index) + m[1]; last = re.lastIndex; }
  }
  return out + js.slice(last);
}
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
// ux-cta-above-fold words (link text or href). Unicode lookarounds instead of \b (ä/ö/ü/õ are not \w); Estonian stems are prefixes
// (kontakt -> kontaktid, telli -> tellimus). Deliberately not: log in, free, learn more, read more (navigation, not a call to action).
const CTA = /(?<!\p{L})(contact|book|get|buy|start|call|quote|order|shop|sign ?up|join|subscribe|try|demo|trial|pricing|donate|download|install|request|schedule|reserve|apply|register)(?!\p{L})|(?<!\p{L})(kontakt|broneeri|telli|osta|helista|registreeru|liitu|alusta|proovi|küsi|anneta|laadi alla)|tel:|mailto:/iu;
// Content-page signals (docs, news, blog, wiki, forum) for ux-cta-above-fold: a sales call to action is not expected there.
const CONTENT_LD = /(Article|Posting|QAPage|APIReference)$/; // also NewsArticle, BlogPosting, TechArticle, DiscussionForumPosting
const CONTENT_META = /^(MediaWiki|Docusaurus|MkDocs|Sphinx|VitePress|VuePress|GitBook|Discourse|phpBB|XenForo)\b/i;
const CONTENT_HOST = /^(docs?|documentation|developers?|wiki|forums?|community|blog|news)$/i;
const CONTENT_PATH = /^(docs?|documentation|wiki|forums?|blog|news|manual|reference|tutorials?)$/i;
// Legal/utility pages (like the page itself and /) are not "other pages" for tool detection.
const UTILITY_PATH = /^\/(privacy|terms|tos|imprint|impressum|legal|cookies?|disclaimer|accessibility|security(\.txt)?|robots\.txt|sitemap[^/]*|llms(-full)?\.txt|\.well-known|privaatsus|andmekaitse|kasutustingimused)(\/|$|[-_.])/i;
const COMMERCE_PATH = /(cart|checkout|basket)(\/|\?|$)/i;
const COMMERCE_SRC = /stripe|paypal|shopify|woocommerce/i;
const CASE_PATH = /(^|\/)(case-stud(y|ies)|portfolio|projects|tood|cases|our-work)(\/|$|[-_.])/i;
// Page-type signals for the applicability-aware ux-* rules and site.js (docs/specs/UX-SPEC.md). Pure: no network, never throws.
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
  const shellRoot = p.tags.some((t) => t.n === 'app-root' || (t.n === 'div' && /^(root|app|__next|__nuxt|___gatsby|svelte)$/.test(t.a.id || '')));
  const isAppShell = p.text.length < 200 && shellRoot;
  const ld = jsonld(p.scripts);
  const types = new Set(ld.nodes.flatMap(ld.typesOf));
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
    labels ??= new Map(p.tags.filter((t) => t.n === 'label' && t.a.for).map((t) => [t.a.for, stripTags(h.slice(t.end, t.end + 120).split(/<\/label/i)[0])]));
    return labels.get(id) || '';
  };
  const typeOf = (t) => (t.a.type || '').trim().toLowerCase();
  const classify = (f, fields) => {
    if (!fields.length) return 'lead'; // unknown (empty, JS-rendered) stays strict
    const vis = fields.filter((t) => t.n === 'textarea' || t.n === 'select' || (t.n === 'input' && !/^(hidden|submit|button|reset|image)$/.test(typeOf(t))));
    if (!vis.length) return 'inert'; // logout / consent / toggle: collects nothing
    const searchRole = (f.a.role || '').toLowerCase() === 'search'; // free-text hints ("Search by name") do not turn a search box into a lead form
    const other = vis.some((t) => (t.n === 'textarea' && !app) || /^(email|tel|file)$/.test(typeOf(t))
      || personalText(`${t.a.name || ''} ${t.a.id || ''} ${t.a.autocomplete || ''}`)
      || (!searchRole && typeOf(t) !== 'search' && personalText(`${t.a.placeholder || ''} ${t.a['aria-label'] || ''} ${t.a.title || ''} ${labelOf(t.a.id)}`)));
    if (other) return 'lead';
    const action = (f.a.action || '').trim(), post = /^post$/i.test(f.a.method || '');
    if (LEAD_ACTION.test(action) || (post && !/search|find|lookup/i.test(action))) return 'lead';
    if (vis.some((t) => typeOf(t) === 'password')) return 'auth';
    const get = !post && action !== '' && action !== '#' && !/^javascript:/i.test(action);
    const positive = app || get || searchRole
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
  let promoHit; // computed once, only if a rule needs it
  const promo = () => (promoHit ??= p.tags.some((t) => t.n === 'a' && t.a.href
    && LEADLINK.test(`${t.a.href} ${stripTags(h.slice(t.end, t.end + 300).split(/<\/a\b/i)[0])}`)));

  // Tool = no shell, at most one real other page, no lead form, no shop, no contact link (unless an app-typed page has a search form),
  // and positive evidence: app JSON-LD with a search/tool form or no promo links, or exactly one JS-only search form and no promo links.
  // ponytail: a tool whose other pages exist but are unlinked on the scanned page is treated as single-page
  // (evidence says "single-page tool" so the reader can tell why). A tracker does not stop tool status.
  const evidence = (app && (searchForm || !promo())) || (forms.length === 1 && forms[0].cls === 'search' && forms[0].jsOnly && !promo());
  const isSinglePageTool = !isAppShell && pages.size <= 1 && !hasLeadForm && !hasCommerce && (!hasContactLink || (app && searchForm)) && evidence;
  // Minimal page (placeholder, parked or "hello world" page): almost no text, no other page to link to, no form. Business-site rules have nothing to judge.
  // Not minimal: a client-app root of any size, a first-party script bundle, promo/contact links (also cross-origin) and any iframe embed or
  // field (also outside a <form> or inside <noscript>): these are shells, sales pages or data-collecting pages, which keep the strict rules.
  // One first-party script is tolerated on a page that already shows real text and has no links (example.com adds a small /s.js);
  // an empty generic root plus a script stays an app.
  const own = p.scripts.filter((s) => s.a.src && !ANALYTICS_SRC.test(s.a.src));
  const bundle = own.length > 1 || (own.length === 1 && (p.text.trim().length < 60 || p.tags.some((t) => t.n === 'a' && t.a.href)));
  const embeds = p.tags.some((t) => /^(iframe|input|textarea|select)$/.test(t.n));
  const isMinimal = !shellRoot && !bundle && !embeds && p.text.length < 250 && pages.size === 0 && forms.length === 0 && !hasCommerce && !hasContactLink && !promo();
  // Content page (docs, news, blog, wiki, forum): the first signal found, '' if none. A shop is never a content page.
  // Deliberately not signals: WebSite/SearchAction JSON-LD, breadcrumbs, many internal links, a lead form (comment/newsletter forms are common).
  const meta = (k) => (p.tags.find((t) => t.n === 'meta' && [t.a.name, t.a.property].some((x) => x && x.toLowerCase() === k))?.a.content || '').trim();
  const contentSignal = (() => {
    if (hasCommerce) return '';
    const art = [...types].find((t) => CONTENT_LD.test(t));
    if (art) return `JSON-LD ${art}`;
    if (/^article$/i.test(meta('og:type'))) return 'og:type article';
    const gen = CONTENT_META.exec(meta('generator'));
    if (gen) return `generator ${gen[1]}`;
    const label = base ? host(base).split('.') : [];
    if (label.length > 2 && CONTENT_HOST.test(label[0])) return `host ${label[0]}.`;
    const seg = base?.pathname.split('/').filter(Boolean).slice(0, 2).find((x) => CONTENT_PATH.test(x));
    if (seg) return `path /${seg}/`;
    const rel = p.tags.find((t) => (t.n === 'a' || t.n === 'link') && /(^|\s)(next|prev)(\s|$)/i.test(t.a.rel || ''));
    if (rel) return `rel=${/next/i.test(rel.a.rel) ? 'next' : 'prev'}`;
    const articles = p.tags.filter((t) => t.n === 'article').length;
    return articles >= 5 ? `${articles} <article> elements` : '';
  })();
  const v = { isAppShell, formCount: forms.length, hasLeadForm, hasAuthForm: forms.some((f) => f.cls === 'auth'), onlySearchForms: forms.every((f) => f.cls === 'search'),
    hasCommerce, hasTracker, internalLinks: internal.size, hasContactLink, isSinglePageTool, isMinimal, contentSignal };
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
    return squash(stripTags(rest.slice(0, i < 0 ? 200 : i)));
  };
  d.url = (href) => { try { return new URL(href, ctx.page.finalUrl); } catch { return null; } };
  d.type = pageType(html, ctx.page.finalUrl, p);
  d.isShell = d.type.isAppShell;
  d.analytics = d.type.hasTracker;
  d.hText = (t) => { // text of a heading element
    const rest = html.slice(t.end, t.end + 300);
    const i = rest.search(new RegExp(`</${t.n}\\b`, 'i'));
    return squash(stripTags(rest.slice(0, i < 0 ? 200 : i)));
  };
  return d;
}

// A policy link names itself: a short link text ("Privacy policy") or a short last path segment (/privacy, /legal/privacy-policy/).
// Prose that merely contains the word does not count (blog slug /blog/privacy-friendly-analytics, a 6-word sentence about privacy).
const words = (s) => s.split(/[\s_.-]+/).filter(Boolean).length;
function isPolicyLink(d, t) {
  const text = d.elText(t);
  if (text.length <= 40 && words(text) <= 4 && PRIV.test(text)) return true;
  let seg = (d.url(t.a.href.trim())?.pathname ?? t.a.href).split('/').filter(Boolean).pop() || '';
  try { seg = decodeURIComponent(seg); } catch { /* keep raw */ }
  seg = seg.replace(/\.(html?|php|aspx?)$/i, '');
  return words(seg) <= 2 && PRIV.test(seg);
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
    const typed = ld.nodes.filter((n) => ld.typesOf(n).length);
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
    if (d.type.isMinimal) return ['skipped', 'minimal page: nothing to link to', ''];
    if (d.type.isSinglePageTool) return ['skipped', 'single-page tool: no other pages to link to', ''];
    const n = d.type.internalLinks;
    if (n >= 3) return ['pass', `${n} internal links`, ''];
    const fix = 'Link to your other key pages with plain <a href> links.';
    return n ? ['warn', `${n} internal link(s)`, fix] : ['fail', d.isShell ? '0 internal links (SPA shell, links rendered by JS)' : '0 internal links', fix];
  },
  'ux-cta-above-fold': (d) => {
    if (d.type.isMinimal) return ['skipped', 'minimal page: no sales content to call to action on', ''];
    if (d.type.isSinglePageTool) return ['skipped', 'single-page tool: the on-page form is the primary action', ''];
    if (d.isShell) return ['skipped', 'empty client-rendered shell: no content in the raw HTML to judge (see seo-spa-shell)', ''];
    if (d.type.contentSignal) return ['skipped', `content page (${d.type.contentSignal}): a sales call to action is not expected`, ''];
    // Window = the first 2000 characters of visible text from <body>, not raw markup (nav SVG and inline scripts push CTAs far down).
    // Linear: each stretch between two links/buttons is read once.
    let seen = 0, at = d.bodyPos, hit = false;
    for (const t of d.tags) {
      if ((t.n !== 'a' && t.n !== 'button') || t.pos < d.bodyPos) continue;
      seen += stripTags(d.html.slice(at, t.pos)).length;
      at = t.pos;
      if (seen > 2000) break;
      if (CTA.test(t.a.href || '') || CTA.test(d.elText(t))) { hit = true; break; }
    }
    const where = 'CTA-like link/button in the first 2000 characters of visible text (heuristic)';
    return hit ? ['pass', where, ''] : ['warn', `no ${where}`, 'Put a clear call-to-action near the top of the page.'];
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
    if (d.type.isMinimal) return ['skipped', 'minimal page: FAQ content not expected', ''];
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
    const hits = d.tags.filter((t) => t.n === 'a' && t.a.href && isPolicyLink(d, t));
    const link = hits.find((t) => !/^\s*(#|javascript:|mailto:|tel:|data:)/i.test(t.a.href)) ?? hits[0]; // a javascript:/# anchor is not the policy
    if (!link) {
      const t = d.type;
      const fix = 'Publish a privacy policy and link it from every page.';
      if (t.hasLeadForm || t.hasTracker) return ['fail', 'no privacy policy link but page has a form or analytics', fix];
      if (t.hasCommerce) return ['fail', 'no privacy policy link but page has checkout/cart links', fix];
      if (t.isMinimal) return ['info', 'minimal page with no form and no tracker: no privacy policy needed', ''];
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
