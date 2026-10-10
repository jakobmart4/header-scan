# UX applicability contract (2026-09-30)

Sources: docs/research/ux-corpus.md (12 real sites), docs/research/ux-audit.md, docs/research/ux-research.md. Contract for 3 parallel builders (A code, B tests+docs, C share image).
Goal: page-type aware `ux-*` rules. A check that cannot apply returns `skipped` or `info`, never a misleading `fail`/`warn`. Genuine marketing / lead-gen pages stay exactly as strict as today.
Rules: no deps, passive only, IDs/severities/checklist numbers unchanged (SPEC counts 31/16/144/119/25 stay true), no commits, no servers left running, never port 34872.

## 1. Shared helper (owner A): `export function pageType(html, finalUrl, parsed = parse(html))` in lib/checks/html.js

Pure, no network, never throws for any string. `html` is sliced to 1048576 chars first. `parsed` is the object returned by the existing `parse()` (pass it from `context()` to avoid a second parse). JSON-LD comes from `jsonld(parsed.scripts)`.
Call sites: `context()` sets `d.type = pageType(html, ctx.page.finalUrl, p)`, `d.isShell = d.type.isAppShell`, `d.analytics = d.type.hasTracker`. lib/checks/site.js imports it and calls `pageType(page.body, page.finalUrl)` on the RAW body (NOT the `stripInert` copy: JSON-LD lives in script bodies), inside try/catch (null on error means old strict behaviour); only when `page.status` is truthy.

Returned object (exact names):

| field | type | definition |
|---|---|---|
| `isAppShell` | bool | unchanged `isShell`: visible text < 200 chars and a `div` with id root/app/__next |
| `formCount` | int | forms outside `<noscript>...</noscript>` (tokenised tags, so `<form-field>` is not a form) |
| `hasLeadForm` | bool | any counted form that is NOT benign (default strict, see below) |
| `hasCommerce` | bool | JSON-LD type `Product` (NOT `Offer`: the tool's own JSON-LD has an Offer); or `<a href>` path + query with a segment or query value matching `[/=](shopping\|view\|my\|mini)?[-_]?(cart\|checkout\|basket)` followed by `/ ? & # .` or the end (`/view-cart`, `/shopping_cart`, `/cart.php`, `?page=cart` count; `/wiki/Food_cart`, `/blog/cart-abandonment` do not); or visible text `add to cart/basket`; or a script src matching stripe/paypal/shopify/woocommerce. A bare `/shop` link is NOT commerce |
| `hasTracker` | bool | existing analytics test, regexes widened: SRC adds `cloudflareinsights\|clarity\.ms\|hotjar\|mixpanel\|posthog\|segment\.com\|connect\.facebook\.net`, CALL adds `\bfbq\(\|\b_hsq\b` |
| `internalLinks` | int | distinct same-origin `pathname+search` of `<a href>` excluding `#`, javascript:, mailto:, tel:, data: (move the loop out of `ux-internal-links` into a shared helper; same result) |
| `hasContactLink` | bool | any `<a href>` starting `tel:` or `mailto:` |
| `isSinglePageTool` | bool | see below |

Form classification (per counted form; fields = `input`/`textarea`/`select` tags located between the `<form>` tag and the next `</form` or next `<form`, whichever is first):
- visible field = not an `input` of type hidden/submit/button/reset/image.
- personal field = `textarea`, or input type email/tel/password/file, or `name|id|autocomplete` matching `/name|email|phone|tel|address|zip|postal|nimi|telefon|message|password|cc-/i`.
- **benign form** = at least 1 visible field and no personal field (search box, URL box, filter). Everything else (contact, signup, login, newsletter, empty `<form></form>`, hidden-only) is a lead form. Unknown stays strict: `<form></form>` and `<form action="/s"></form>` are lead forms.
- jsOnly form = no `action`, or action empty, `#`, or `javascript:`.

`isSinglePageTool` = ALL of: `!isAppShell`, `internalLinks === 0`, `!hasLeadForm`, `!hasCommerce`, `!hasContactLink`, and a positive tool signal: (JSON-LD type `WebApplication` or `SoftwareApplication`) OR (`formCount === 1`, that form benign and jsOnly). A tracker does NOT stop tool status (privacy handles it separately). No positive evidence means strict: a brochure with 0 links and no form is not a tool; example.com (1 external link, no form, no JSON-LD) stays strict.

Known ceiling (comment with `ponytail:`): a tool whose other pages exist but are unlinked on the scanned page is treated as single-page; evidence says "single-page tool" so the user can tell why.

> Update (reviewer round): the form classes, tool evidence, link rules and 403 handling in section 1 and the table below are superseded by the "Page-type signals" paragraph in SPEC.md section 6.6: forms are lead/search/auth/inert, tool status allows one real other page (legal/utility links, self and `/` ignored, www = apex), JSON-LD alone no longer suffices when promo links exist, and 403 is info only on a tool or a Cloudflare bot filter.

## 2. Rule table (owner A). "Unchanged" means byte-identical behaviour and evidence.

| id | applicability condition | NOT applicable result (status, evidence, fix '') | applicable / strict |
|---|---|---|---|
| ux-internal-links | `type.isSinglePageTool` (checked before counting) | `skipped`, `single-page tool: no other pages to link to` | unchanged: >=3 pass, 1-2 warn, 0 fail (SPA-shell note kept; an empty shell is NOT skipped: seo-spa-shell owns it and the existing assertion stays) |
| ux-cta-above-fold | `type.isSinglePageTool`; then (2026-10-07) `isAppShell` and `type.contentSignal` | `skipped`, `single-page tool: the on-page form is the primary action`; `empty client-rendered shell: no content in the raw HTML to judge (see seo-spa-shell)`; `content page (<signal>): a sales call to action is not expected` | warn when missing. Since 2026-10-07: window is the first 2000 characters of visible text (not 3000 raw characters), wider English/Estonian word list (SPEC 6.6). Contract change: docs/news/blog/wiki/forum pages with a `contentSignal` and empty shells are no longer strict for this rule; pages without a signal stay strict. Since 2026-10-10: strong signals (own JSON-LD article type, docs generator, content subdomain) beat shop markers unless the page's own JSON-LD is a Product/Offer/ItemList of Products; weak signals (og:type article, path, rel next/prev, `<article>` cards) yield to shop markers, a lead form and a pricing/services link; the label includes aria-label, title and img alt; href words count in path, query and fragment, not the host (SPEC 6.6) |
| ux-faq | `n >= 5` passes first; then `type.isSinglePageTool` | `skipped`, `single-page tool: FAQ content not expected` | unchanged warn 1-4 / info none. Extra rule for everyone: `details` count only when `>= 2` `<details>` (a lone `<details>` is a disclosure widget; else 0). Five `<details>` still pass, two still warn |
| ux-privacy-policy | only when NO privacy link is found (link branch untouched). `collects = type.hasLeadForm \|\| type.hasTracker \|\| type.hasCommerce` | no link, `!collects`, `isSinglePageTool`: `info`, `no personal-data form or tracker found in the raw HTML (single-page tool); add a policy if the server logs or stores user input` | `collects`: `fail` (evidence unchanged `no privacy policy link but page has a form or analytics`; commerce-only: `no privacy policy link but page has checkout/cart links`). No link, `!collects`, not a tool: `warn` `no privacy policy link` (this is where search-only pages move from fail to warn) |
| ux-thank-you (site.js) | `type && type.formCount > 0 && !type.hasLeadForm` (only benign forms), decided BEFORE the 4 path fetches | `skipped`, `no lead or conversion form: only search/tool form(s) on the page`, zero extra fetches | lead form: fetch 4 paths; found = `pass`; none = `warn` `form present but no thank-you page found` (condition is now `type.hasLeadForm`, fallback `/<form\b/i` when `type` is null). No counted form: unchanged `info` `no thank-you page and no form` (also covers noscript-only forms and `<form-field>`). All fetches error: unchanged `skipped` |
| ux-404-page (site.js) | status 404 with tiny/default body and `type?.isSinglePageTool`; OR status 401/403 on any site | tool: `info`, `real HTTP 404; a custom 404 page is not needed on a single-page tool`. 401/403: `info`, `unknown paths answer HTTP <n> (auth-gated or filtering host); custom 404 not assessable` | 200 = `fail` soft 404 (every site, tools and SPA shells too); 404 body >=300 not default = `pass`; tiny/default 404 on non-tool = `warn`; other status = `warn` (all unchanged) |
| ux-case-studies | link must be same-origin (relative or same host) AND its pathname match the segment regex `/(^\|\/)(case-stud(y\|ies)\|portfolio\|projects\|tood\|cases\|our-work)(\/\|$\|[-_.])/i` | no match: unchanged `info` `no case study / portfolio link` | match: `pass` as before. Fixes external links (HN, Wikipedia) and slug substrings (`eeltood-uute`). `/product/projects` still matches (known, documented) |
| ux-analytics | detection only (widened tracker list above) | none | `info` no tracker / `pass` tracker: unchanged wording |

Deliberately NOT changed (list in SPEC as known limits, do not touch): ux-response-time `\b24 ?h\b` regex (existing test requires "24h" to pass), seo-spa-shell Angular/Nuxt fingerprints, ux-alt-text noscript tracking pixels, ux-default-hostname list, the seven info-only marketing checks (breadcrumbs, maps, reviews, local-schema, team-photo, response-time stay `info`), docs/news/wiki page types (CTA stays strict there: a site-search form is not evidence of a non-marketing page), `err.ee`-style multiple `<details>` collapsibles (>= 2 still count).

## 3. Expected results per fixture (the contract for B's tests)

Fixtures in `test/fixtures/ux/` (final URL `https://example.test/`, tests use `fakeCtx`; site-level rows use the `site(routes)` helper with NO thank-you route and a 404 for unknown paths unless stated). Builders of fixtures: keep visible text > 200 chars (not a shell), no tracker unless stated; rows with cta `warn` must contain no CTA word (contact|book|get|buy|start|call|quote|kontakt|broneeri|telli|tel:|mailto:) in any a/button text or href.

| fixture | content | pageType | internal-links | cta | faq | privacy (no link) | thank-you | 404 (tiny 404) |
|---|---|---|---|---|---|---|---|---|
| `tool.html` | copy of the scanner's own page shape: WebApplication + Offer JSON-LD, prose, `<form id=scan-form novalidate><input type=text name=url id=url autocomplete=url><button>Scan</button></form>`, `<noscript>`, ONE `<details><summary>Raw JSON</summary>`, NO `<a href>` | isSinglePageTool true, hasLeadForm false | skipped | skipped | skipped | info | skipped (assert the 4 paths were NOT requested) | info |
| `tool-tracker.html` | tool.html + `<script async src="https://static.cloudflareinsights.com/beacon.min.js"></script>` | hasTracker true, still a tool | skipped | skipped | skipped | fail | skipped | info |
| `search-site.html` | 4 internal links, `<form role=search action="/search"><input type=search name=q></form>`, articles, no contact link | formCount 1, hasLeadForm false, tool false | pass | warn | info | warn (was fail) | skipped | warn |
| `leadgen.html` | LocalBusiness JSON-LD (address, telephone, hours), `tel:` link, "Contact us" link first in body, 3+ internal links, `<form action="/contact" method=post>` with `name`, `email` input and `<textarea>`, 3 `<details><summary>Q?</summary>` | hasLeadForm true | pass | pass | warn | fail | warn | warn |
| `shop.html` | Product JSON-LD, links `/cart`, `/checkout`, `/products`, a search form only, no policy link | hasCommerce true, tool false | pass | warn | info | fail | skipped | warn |
| `blog.html` | 5 internal links, `<article>`s, no form, no tracker, no policy link | no form, tool false | pass | warn | info | warn | info | warn |
| `spa-shell.html` | `<body><div id="root"></div><script type=module src=/a.js></script></body>` | isAppShell true, tool false | fail (SPA note) | warn (skipped since 2026-10-07: empty shell) | info | warn | info | soft-404 fail when the fetch returns 200 |

Also required (classifier unit tests on `pageType`): noscript-only form -> formCount 0; `<form-field>` -> formCount 0; `<form></form>` -> lead; `<form action="/s"></form>` -> lead; login (`type=password`) -> lead; newsletter (`type=email`) -> lead; single `type=search` form -> benign; hidden-only form -> lead; `WebApplication` JSON-LD plus 3 internal links -> not a tool; tool plus `mailto:` link -> not a tool; tool plus `/cart` link -> not a tool; `Offer` alone is not commerce; `/shop` link alone is not commerce.
Each changed id (ux-internal-links, ux-cta-above-fold, ux-faq, ux-privacy-policy, ux-thank-you, ux-404-page, ux-case-studies) needs a now-skipped/info case AND a still-flagged case, taken from the table. ux-case-studies: `<a href="https://news.example.org/projects/x">` -> info, `<a href="/eeltood-uute-1">` -> info, `<a href="/tood">` -> pass (existing), `<a href="/case-studies/acme">` -> pass. ux-404: 401 and 403 -> info on a marketing page, 200 -> fail on a tool page, 404 tiny on leadgen -> warn. Regression: run `public/index.html` (after build:ui) through `html.js`: none of the six main rules may be `fail`/`warn`; a `tool` row for `site.js` covers thank-you/404.
Existing tests must stay untouched and green (365 pass, 2 skip), including html.test.js:61 (empty shell internal-links `fail`), coverage-gaps ux-faq (2 details warn, 5 pass), review-fixes `<form></form>` privacy `fail` and thank-you `warn`, `/shop` "Cookies and cream" privacy `warn`. New total = 365 + new tests, 2 skip.

## 4. Score implications (lib/score.js, unchanged; skipped/info are not counted)

- Scanner's own site today: quality B 88 (local re-run of html.js on public/index.html: internal-links fail, privacy fail, cta warn, faq warn; site.js adds 404 warn sev 3 and thank-you warn). After: internal-links, cta, faq `skipped`, privacy, 404 `info`, thank-you `skipped`. The html findings alone go from 88 to 100 and, with the typical site.js pass set, a local simulation gives 100. The "any fail or warn sev>=3 caps at A" rule stops applying (0 fails, no sev>=3 warn), so expected grade is A+ (minimum A if some unrelated check still warns). Builder B records the real number in SPEC/README only if measured with `node` on the built page, never invented.
- Marketing fixtures (`leadgen.html`, `blog.html`, `spa-shell.html`): statuses of the six rules identical to today, so their quality score must be byte-identical before and after (B: assert `score()` equality using the old expected statuses listed in the table). Fixtures with only a search form improve: `search-site.html` privacy fail -> warn and thank-you warn -> skipped; `shop.html` thank-you warn -> skipped (privacy stays fail). That is the intended fix, not weakening.
- ux-analytics widening can turn `info` into `pass` (severity 1) on pages with Cloudflare/Hotjar/Clarity/etc; accepted.

## 5. File ownership (no overlap)

A (code): `lib/checks/html.js` (pageType, rules, widened regexes, shared internal-links helper), `lib/checks/site.js` (import, thank-you, 404; nothing else). Comments in English with `ponytail:` where a ceiling is accepted. Run `node --test "test/*.test.js"`; all 365 must pass before handing over.
B (tests + docs): `test/ux-applicability.test.js`, `test/fixtures/ux/{tool,tool-tracker,search-site,leadgen,shop,blog,spa-shell}.html`, SPEC.md rows for the 7 ids (sections 6.6/6.7: one applicability clause each, keep the existing P/W/F text, plus a short "Page-type signals" paragraph naming `pageType` and the "deliberately not changed" list), README.md (one line on applicability under the UX hygiene description). B may only edit other test files if a fixture path requires it; never loosen an existing assertion. B writes tests against this spec in parallel; if A's behaviour differs from the table, A fixes the code, the spec wins.
C (share image): copy `docs/og-candidate.png` (1200x630 PNG, 51880 bytes, already verified) to `public/og.png`; in `ui/src/index.template.html` set `og:image` to `https://header-scan.jakobmart4.workers.dev/og.png`, add `<meta property="og:image:width" content="1200">`, `og:image:height` `630`, `og:image:alt` (short description) and `<meta name="twitter:image" content="https://header-scan.jakobmart4.workers.dev/og.png">`; delete `public/og.svg` after `grep -rn "og.svg"` shows no remaining reference outside docs/ and dist/; run `npm run build:ui` then `npm run build` (dist/ regenerated, og.svg gone from dist). Do not touch `public/index.html` by hand. The CSP hash build picks up the template change automatically. Re-run the full suite, then confirm `<meta property="og:image"` in both `public/index.html` and `dist/index.html`.
Sequencing: C is independent. B and A run in parallel; C's `build:ui` must run after A is done only if the regression test on `public/index.html` is included (B runs that test last).

## 6. Changed check ids (return value)

ux-internal-links, ux-cta-above-fold, ux-faq, ux-privacy-policy, ux-thank-you, ux-404-page, ux-case-studies, ux-analytics (detection only). Unchanged but documented as known limits: ux-response-time, seo-spa-shell, ux-alt-text.
