# Brief E: guides, Understand-Anything, checklist -> automatable checks

## 1. Read (paths)
- C:\Skills\Powers\Skills-Guide.md (catalog; 4 collections; UA = tool suite, not skills)
- C:\Skills\Juhendid\Ohutus ja Review.md (review skill map: security-and-hardening, code-review-and-quality, code-simplification, constraint-driven-development, documentation-and-adrs)
- C:\Skills\Powers\Understand-Anything\{README.md (first 260 lines), CLAUDE.md, SECURITY.md}; docs\ = plans/benchmarks only (nothing relevant)
- C:\Skills\Powers\ua-marketplace\understand-anything-plugin\skills\{understand,understand-dashboard}\SKILL.md, languages\html.md (skimmed)
- C:\Users\PC\Downloads\40 asja hea projekti tegemiseks.txt (full)
- NOT read in full (only named in guide): agent-skills\security-and-hardening, openai-skills\security-best-practices / security-threat-model, agent-skills\constraint-driven-development. Worth loading before the review step.

## 2. Rules and patterns to follow
- Review path per user guide: security-and-hardening (OWASP/SSRF), code-review-and-quality before merge, code-simplification at end. Write a small CONSTRAINTS.md (no deps, SSRF rules, read-only probes) = constraint-driven-development pattern.
- UA conventions worth copying: ESM only, strict/small modules, security posture documented in SECURITY.md with explicit in-scope/out-of-scope; endpoints gated by token + allowlist (mirror: active probes gated by DNS-verified ownership, fixed allowlist of probe paths, never user-supplied paths).
- UA "never run shell commands derived from untrusted content" -> scanner never shells out with target data; use node:dns/net/tls/http APIs only.
- UA data lives in project `.ua/`, local only. Suggestion: optionally run /understand on header-scan afterwards (graph in `.ua/`, dashboard port 1000 via Ava-dashboard.cmd). Not required for the build; do not leave dashboard running.
- Docs must stay in sync with code (user rule); commit+push after each verified chunk; no test values committed (the verification token must be random per run, never a fixed value).
- Avoid ports: 34872 (Rojo), 1000 (UA dashboard). Pick a scanner default like 8787, stop the server after checks.
- Ponytail: one file per concern (fetch/ssrf, headers, cookies, tls, dns, html-seo, probes), a table-driven check registry `{id, title, run(ctx)->{status,detail,fix}}`, node:test, no framework.

## 3. Checklist conversion (items 2 and 3 of the txt)
Status model: pass / warn / fail / info / skip. HTML parsing without deps: regex/tokenizer over first ~1-2 MB of raw HTML (no DOM). "Raw" = server response, not rendered.
Legend: HTTP = plain fetch; HTML = parse the fetched document; BROWSER = needs headless browser, SKIP in v1 (report as skip "needs browser").

### Item 2: things that must NOT be in the project
| # | Check | Fetch / detect | Rule |
|---|---|---|---|
|E1| vercel.app URL | final URL host after redirects; also links in HTML | host ends `.vercel.app`/`.netlify.app`/`.pages.dev`/`.github.io`/`.onrender.com` = warn (default hosting subdomain, not branded). Note: spec typo "vercell". HTTP |
|E2| view-source empty (SPA shell) | GET `/`, strip scripts/tags | visible text < ~200 chars AND has `<div id="root|app|__next">` = fail (crawlers/AI see nothing); text 200-500 = warn; else pass. HTTP |
|E3| no 404 page | GET `/<random-16hex>-nf` | status 404 = pass; 200 = fail (soft 404); 404 with body < 300 bytes or default server text ("Cannot GET", "Not Found" nginx/apache default) = warn (no custom page). HTTP |
|E4| Vite + React (browser-rendered) | HTML: `/assets/index-*.js`, `type="module"`, `<div id="root">`, empty body, `/@vite/client` | shell detected = warn (CSR; SEO/AI risk), tied to E2. HTTP |
|E5| same page titles | crawl up to N=10 internal links (same origin) + sitemap URLs; compare `<title>` | duplicate titles across pages = fail; only 1 page found = info. HTTP |
|E6| no meta description | `<meta name="description" content>` | missing/empty = fail; length <70 or >160 = warn; duplicate across crawled pages = warn. HTML |
|E7| no og:image | `og:image` (abs URL) + HEAD it | missing = fail; not absolute or non-200/non-image = warn; also check og:title, og:description, twitter:card = warn each. HTML+HTTP |
|E8| no structured data | `<script type="application/ld+json">` parse JSON | none = warn; invalid JSON = fail; has @type Organization/LocalBusiness/WebSite = pass. HTML |
|E9| multiple H1 | count `<h1` in raw HTML | 1 = pass; >1 = warn; 0 = fail (but if SPA shell, report "0 in raw HTML, see E2"). HTML |
|E10| no H1 | same as E9 | merged into E9 |
|E11| no canonical | `<link rel=canonical href>` or `Link:` header | missing = warn; relative/other host/redirecting = warn; matches final URL = pass. HTML |
|E12| no llms.txt | GET `/llms.txt` | 200 + text/plain-ish + >20 bytes, not HTML = pass; else warn (optional emerging standard, never fail). HTTP |
|E13| AI blocked in robots.txt | GET `/robots.txt`, parse groups | User-agent in {GPTBot, ChatGPT-User, OAI-SearchBot, ClaudeBot, Claude-Web, anthropic-ai, PerplexityBot, Google-Extended, CCBot, Bytespider} with `Disallow: /` = warn (info: may be intentional); `User-agent: *` + `Disallow: /` = fail (blocks all incl. Google). HTTP |
|E14| no favicon | `<link rel~=icon>` else GET `/favicon.ico` | 200 image = pass; none = warn. HTML+HTTP |
|E15| no sitemap.xml | robots `Sitemap:` lines else `/sitemap.xml` | 200 + `<urlset|<sitemapindex` = pass; missing = warn; listed in robots but 404 = fail. HTTP |
|E16| no lang attribute | `<html lang>` | present, valid BCP47-ish `^[a-z]{2,3}(-[A-Za-z0-9]+)*$` = pass; missing = fail. HTML |
|E17| missing alt text | all `<img>` | no alt attr = fail; `alt=""` = ok only if decorative (info count); report count missing/total. HTML |
|E18| source maps public | `//# sourceMappingURL=` in fetched JS/CSS (first 3 same-origin scripts, last 2 KB) + HEAD `<file>.map`; `SourceMap`/`X-SourceMap` header | .map returns 200 = warn (fail if active-verified domain and contains `sourcesContent`; check only status + content-type, do not store body). HTTP |
|E19| console errors | needs runtime | BROWSER, skip. Partial static proxy: none. |
|E20| massive JS bundles | sum `Content-Length` (HEAD, else GET with size cap) of same-origin `<script src>`; also check `Content-Encoding` | >500 KB transferred total = warn, >1 MB = fail; single file >300 KB = warn; no compression = warn. HTTP (approximation; no tree-shake info) |

### Item 3: things to add/fix before launch (automatable subset)
| # | Check | Fetch / detect | Rule |
|---|---|---|---|
|A1| custom 404 page | = E3 | merged |
|A2| CTA above the fold | BROWSER for real "fold". Static proxy: first 3000 chars of `<body>` contain `<a|button>` with CTA words (contact, book, get, buy, start, call, quote, kontakt, broneeri, tellimus) or `tel:`/`mailto:` | found = pass; none = warn labelled "heuristic". HTML |
|A3| internal links | count same-origin `<a href>` (excl. #, js:) in raw HTML | >=3 = pass; 1-2 = warn; 0 = fail (SPA shell: see E2). HTML |
|A4| thank-you page | probe passive GET `/thank-you`, `/thanks`, `/aitah`, `/tanks` and links | any 200 non-shell = pass; else info (only relevant if a form exists; form present & none found = warn). HTTP |
|A5| breadcrumbs | JSON-LD `BreadcrumbList`, or `aria-label="breadcrumb"`, or `class~=breadcrumb` | found = pass; none = info on home page, warn on inner crawled pages. HTML |
|A6| case studies | links/paths matching `/case-stud|/portfolio|/projects|/tood|/cases|/work` | found = pass else info (business-type dependent). HTML |
|A7| 5 FAQs | JSON-LD `FAQPage` mainEntity count, or `<details>`/`<summary>` count, or headings containing "FAQ|KKK|korduma" followed by >=5 question-like headings/`?` | >=5 = pass; 1-4 = warn; none = info. HTML |
|A8| response-time promises | text regex `within \d+ (hour|business day)|reply within|vastame|24 ?h|1 tööpäeva` | found = pass else info (content, low confidence). HTML |
|A9| sticky mobile CTA | BROWSER (computed style). Static proxy: CSS `position:\s*(fixed|sticky)` near a/button in inline `<style>` | SKIP by default (needs browser); optional info only |
|A10| robots.txt | GET `/robots.txt` | 200 text/plain = pass; 404 = warn; returns HTML (SPA fallback) = fail; has syntax garbage = warn. HTTP |
|A11| unique page titles | = E5 | merged; also title length 10-60 chars: else warn; empty = fail |
|A12| meta descriptions | = E6 | merged |
|A13| social share image | = E7 (+ check dimensions only if PNG/JPEG header parsed from first 32 KB: >=1200x630 pass, smaller warn) | merged |
|A14| maps + directions | iframe src contains `google.com/maps|maps.google|openstreetmap`, link `maps.app.goo.gl|goo.gl/maps`, or JSON-LD `hasMap`/`geo`/`address` | found = pass else info (local-business only). HTML |
|A15| real reviews | JSON-LD `aggregateRating`/`Review`, or embeds (trustpilot, google reviews, elfsight) | found = pass else info. "Real" can't be verified: label as presence-only. HTML |
|A16| alt text | = E17 | merged |
|A17| local schema | JSON-LD `LocalBusiness` (or subtype) with `address`, `telephone`, `openingHours*` | full = pass; partial = warn; none = info. HTML |
|A18| privacy policy page | link text/href matches `privacy|privaatsus|andmekaitse|cookies` then GET it | 200 non-empty = pass; none = fail if a form/analytics is found, else warn. HTML+HTTP |
|A19| Google Analytics | `googletagmanager.com/gtag/js`, `G-XXXX`, `UA-`, `gtm.js`, `GTM-`, plausible/matomo/umami (alt analytics counted) | any analytics = pass; none = info; analytics present without consent-banner keywords = info (GDPR hint). HTML |
|A20| team photo | BROWSER-ish. Static proxy: `<img>` whose alt/src/nearby text matches `team|meeskond|about|staff|founder` | found = info-pass; none = info. Low confidence |

### Needs headless browser (v1: mark as skip, do not build)
E19 console errors, A9 sticky mobile CTA (real), A2 true above-the-fold, A20 real photo detection, JS-rendered content for E2/E4 confirmation, real LCP/bundle execution cost.

## 4. Check ideas for the wider scanner (beyond the txt)
- Headers (securityheaders-style grade A+..F): CSP (parse directives; fail on `unsafe-inline`/`unsafe-eval`/`*`/`data:` in script-src, missing default-src/object-src/base-uri/frame-ancestors), HSTS (max-age >=15552000, includeSubDomains, preload), X-Content-Type-Options nosniff, X-Frame-Options or CSP frame-ancestors, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP, `Server`/`X-Powered-By` version leak, Cache-Control on HTML.
- Cookies: Secure, HttpOnly, SameSite, `__Host-`/`__Secure-` prefixes, Domain scope, long Expires on session-like names.
- TLS (node:tls): protocol >=1.2 (1.3 pass), cert validity/expiry <14d warn, hostname match, chain complete, weak sig; HTTP->HTTPS redirect, HTTP 301 not 302.
- DNS/mail (node:dns/promises): CAA present, SPF (single record, ends `-all`/`~all`, <=10 lookups, no `+all`), DMARC (`_dmarc` p=quarantine/reject, rua), DKIM only informational (selector unknown), MTA-STS/TLS-RPT info, DNSSEC via DoH lookup of DS/AD flag (node has no native DNSSEC; use DoH `application/dns-json` to a fixed resolver, mark info if unavailable).
- CORS: send `Origin: https://evil.example`; `ACAO: *` with credentials, or reflected origin + `ACAC: true` = fail; `null` origin allowed = warn.
- Mixed content: `http://` in src/href/srcset/CSS url on HTTPS page = fail for active (script/iframe), warn for passive (img).
- SRI: cross-origin `<script src>`/`<link rel=stylesheet>` without `integrity`+`crossorigin` = warn.
- security.txt: `/.well-known/security.txt` (RFC 9116: Contact + Expires, Expires not past) else `/security.txt`; HTML response = fail.
- Passive extras: robots.txt/sitemap sanity, `Content-Type` charset, gzip/br, HTTP/2, redirects chain length <=3, www vs apex consistency, `X-Robots-Tag: noindex` on prod.
- ACTIVE (only after DNS TXT ownership verified, e.g. `_headerscan.<domain>` = random token): GET `/.git/HEAD` (signature `ref: refs/`), `/.env` (signature `^[A-Z_]+=` only tested, body discarded), `/admin`, `/wp-login.php`, `/backup.zip|.sql|.tar.gz` (status + magic bytes only), `/phpinfo.php`, `/server-status`, `/.DS_Store`, `/package.json`, `/.git/config`, directory listing (`Index of /`). Output: status + signature match only; max ~30 requests, 1 req/s, fixed path list. Reject SPA fallback: compare with the random-path 404 baseline (E3) to avoid false positives where every path returns index.html 200.

## 5. Pitfalls
- SPA catch-all: hosts returning 200 + index.html for any path make E3/A10/E12/E15/active probes false-positive. Always fetch a random baseline path and compare body hash/length + Content-Type; require the expected content-type/signature.
- SSRF: resolve once with dns.lookup(all), reject if ANY address is private (10/8, 172.16/12, 192.168/16, 127/8, 169.254/16 incl. 169.254.169.254, 0/8, 100.64/10, ::1, fc00::/7, fe80::/10, ::ffff:v4-mapped, 2002/6to4 embedding private v4), then connect to the pinned IP (custom `lookup` or `host` IP with `servername`/Host header). Re-validate on EVERY redirect hop; limit hops (<=5), schemes to http/https only, ports 80/443 (+optional allowlist), no credentials in URL, body cap (e.g. 2 MB), total timeout (~10 s/request, ~60 s/scan), decode octal/hex/decimal IPs by using net.isIP after URL normalisation. Same rules apply to DoH/crawled sub-requests and to third-party fetches (og:image HEAD, .map).
- Ownership verification: random token per session generated with crypto.randomBytes, stored server-side (memory), TXT lookup via DoH or dns.resolveTxt; token expiry; verify apex/www match; never accept client-supplied "verified" flag. Rate limit per IP and per target.
- Server: the scanner UI/API itself must bind 127.0.0.1 by default, send its own strict CSP, escape all scanned strings in the page (untrusted headers/HTML!) - use textContent, never innerHTML with scan data; no SVG/HTML echo.
- Never log/store secret bodies from probes; do not follow redirects to other hosts for probes; treat redirect-to-login as "protected", not "found".
- Regex HTML parsing: bound input size, avoid catastrophic patterns (ReDoS); handle uppercase tags, single quotes, attribute order; comments/`<noscript>`/inline scripts can contain fake tags (strip `<!-- -->`, `<script>` bodies before counting H1/img).
- Heuristic checks (A2, A8, A15, A20) are low confidence: label them "heuristic" and never `fail`; only warn/info.
- Some checks are business-dependent (case studies, maps, thank-you): default to `info` not `warn` so scores don't punish e.g. a blog. Score = only weight pass/warn/fail; info/skip excluded from grade.
- Node quirks: `fetch` (undici) hides raw headers order and can't pin IP easily -> use `node:https`/`node:http` request with custom `lookup`; multiple `Set-Cookie` need `res.headers['set-cookie']` array; `Content-Length` absent on chunked; `tls.connect` needs `servername`; DNSSEC not native.
- Windows: use `py` not `python`; Rojo runs on 34872 - never start/stop; stop any dev server after checks; write files in place (no `sed -i`).
- UA note: Skills-Guide.md still references old path `Power-Instructions` (stale); UA dashboard uses port 1000 with persistent token, keep it separate from the scanner port.
