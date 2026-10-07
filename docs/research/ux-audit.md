# UX check audit: applicability and page-type signals

Scope: every `ux-*` rule in `lib/checks/html.js` and `lib/checks/site.js`, plus the `ai-*` rules.
There is no `seo-breadcrumbs`; breadcrumbs are `ux-breadcrumbs`.
Method: read the code, then ran ad-hoc probes (scratch script, not committed) through `html.js run()` with `fakeCtx`.
Findings marked **[verified]** were reproduced that way; the rest come from reading the code.
The live 404 of the tool site was fetched once with a GET: HTTP 404, 30 bytes, `{"error":{"code":"NOT_FOUND"}}` **[verified]**.
Nothing in `site.js` was executed against the network beyond that one GET.

## 0. Why the tool site fails (root cause)

`public/index.html` is a real, server-rendered page (h1, prose, `<noscript>`, JSON-LD `WebApplication`), not an empty SPA shell.
It has one `<form id="scan-form" novalidate>` with a single `type=text` input (`name=url`, `autocomplete=url`) and **no `action`**; a JS handler calls `/api/*`.
There is one `<details id="raw">` (raw JSON viewer), no `<a href>` at all, no analytics.

Results on it today **[verified]**: `ux-internal-links` fail (0), `ux-cta-above-fold` warn, `ux-faq` warn (1 item, which is the raw-JSON `<details>`), `ux-privacy-policy` fail ("form or analytics"), `ux-404-page` warn (tiny body); `ux-thank-you` warn per the report (code path: `/<form\b/i` true, no thank-you URL).

Every misfire has the same cause: the rules test for the **presence of a construct** (`<form>`, `<details>`, anchors) and never ask **what kind of page** it is.
A `<form>` is treated as a lead form, a `<details>` as an FAQ item, and "0 links" as a missing navigation.

## 1. Shared input facts (what the rules actually see)

- `html.js` tokenizes the raw body (first 1 MiB): comments, `script/style/title` bodies are opaque; `<noscript>`, `<template>`, `<textarea>` content is **not** opaque. Closing tags are discarded, so there is no element nesting or "inside `<form>`" information, only tag positions.
- `site.js` uses `stripInert(page.body)` (comments and script/style bodies blanked) and plain regexes.
- Two different form detectors: `html.js` uses `d.count('form')` (tokenized, so `<form-field>` does not match); `site.js` uses `/<form\b/i` (`\b` matches before `-`, so a custom element `<form-field>`/`<form-builder>` is a false positive).
- No rule can see rendered DOM. Anything injected by JS (footer, privacy link, cookie banner, cards, FAQ accordion) is invisible. `d.isShell` (`text < 200 && <div id=root|app|__next>`) is the only "JS-rendered" signal and only `ux-internal-links` and `seo-h1` read it.
- `d.isShell` false negatives: only `div` ids `root|app|__next`; misses `__nuxt`, `svelte`, `___gatsby`, `<app-root>` (Angular), `<main id=app>` (the tool site's own `#app` is a `main`), and any shell that ships a long `<noscript>` message (noscript text counts as visible text).

## 2. Proposed classification signals (`lib/checks/pagetype.js`, pure, no network)

One function `pageType(html, finalUrl)` returns the object below. Default is **strict**: a page is treated as a marketing/lead-gen site unless there is positive evidence otherwise. Skips are only granted on evidence, never on absence.

Per-form pass (split the stripped HTML on `<form ...>` ... `</form>` or next `<form`; ignore forms inside `<noscript>...</noscript>`):

| Per-form field | Computed from |
|---|---|
| `personal` | any `<input type=email|tel|password>`, `<textarea>`, or name/id/autocomplete token in `name|first|last|email|phone|tel|address|zip|postal|nimi|telefon|cc-*|street-address|current-password|new-password` |
| `kind = 'login'` | has `type=password` (or `autocomplete=current-password`) |
| `kind = 'search'` | `role=search`, `type=search`, single text input named `q|s|query|search|url|link|domain|host|site`, or `action` path contains `search` |
| `kind = 'newsletter'` | email input and (`subscribe|newsletter|tellimus|liitu|mailchimp|mailerlite` in form text/action/class) |
| `kind = 'lead'` | `personal` and not login/newsletter: contact/quote/booking/order forms (email/tel/textarea plus submit text) |
| `jsOnly` | no `action`, `action="#"` or `javascript:` (submission by script: thank-you URL cannot be inferred) |
| `external` | `action` origin differs from the page origin (Formspree, Mailchimp, HubSpot...: thank-you lives off-site) |

Page-level signals:

| Signal | Definition | Used by |
|---|---|---|
| `isAppShell` | existing `isShell` widened: visible text < 200 and (`div` or `main` id in `root|app|__next|__nuxt|svelte|___gatsby`, or an `<app-root>`-style custom element) | internal-links, cta, faq, privacy, breadcrumbs, case-studies, reviews, maps, local-schema (skip, `seo-spa-shell` already reports it) |
| `hasLeadForm` | any form `kind = 'lead'` (or newsletter), or a third-party form embed iframe/script (`hsforms|typeform|jotform|tally.so|calendly|formspree`), or `mailto:`/`tel:` links | thank-you, cta, response-time |
| `hasSearchOnlyForm` | at least one form, and every form is `search` | thank-you, privacy |
| `collectsPersonalData` | any non-noscript form with `personal`, or `login`, or a tracker (see below) | privacy |
| `hasTracker` | existing `d.analytics` plus: `cloudflareinsights`, `clarity.ms`, `hotjar`, `mixpanel`, `posthog`, `segment`, `fbq(`, `_hsq`, `plausible` | privacy, analytics |
| `hasCommerce` | JSON-LD `Product|Offer`, `add[- ]to[- ]cart`, links to `/cart|/checkout|/shop|/pricing`, `stripe|paypal|shopify` scripts, currency-amount text | cta, thank-you, privacy (forces strict) |
| `isSinglePageTool` | **all** of: not `isAppShell`; 0 distinct same-origin non-anchor page links; at least one positive tool signal (JSON-LD `WebApplication|SoftwareApplication`, or exactly one `search`-kind/URL-input form that is `jsOnly` plus a `<noscript>` telling the user JS is required); and none of `hasLeadForm`, `hasCommerce`, `collectsPersonalData` | internal-links, cta, faq, 404, privacy |

Guard rails (keep genuine marketing pages strict):
- A brochure page with 0 links and no form is **not** a tool (no positive tool evidence), so `ux-internal-links` still fails.
- A SaaS landing page with `WebApplication` JSON-LD still has links/pricing/lead form, so `isSinglePageTool` is false.
- One signal flipping false re-enables the strict behaviour; the classifier never inspects rendered text claims ("this is a tool").

Cost: about 60 lines, reused by `html.js` (`d.type`) and `site.js` (called on its own `html`). `site.js` currently re-implements form detection with a regex; that one line becomes `type.hasLeadForm`.

## 3. Per-check audit

Notation: FP = false positive (flags something fine), FN = false negative (misses a real problem). Status names are the scanner's.

### ux-internal-links (sev 2): P >=3, W 1-2, F 0
Rule: distinct same-origin `<a href>` (pathname+search), excluding `#`, `javascript:`, `mailto:`, `tel:`, `data:`.
- FP: one-page tools and apps with no anchors **[verified tool site]**.
- FP: one-page brochure sites that only use `#section` links: all dropped, `/#c` collapses to `/`, so 3 anchor links count as 1 **[verified: warn 1]**.
- FP/FN: `www.` vs apex, `http` vs `https` are a different origin so real internal links count as external; `<base href>` ignored.
- FP: JS-rendered nav on non-shell pages (hydrated menu) reads as 0.
- FN: the page linking only to itself (`/`) counts as 1 internal link, and so does a logo link.
- Proposed: `isAppShell` -> `skipped` ("links rendered by JS; see seo-spa-shell"); `isSinglePageTool` -> `skipped` ("single-page tool, no other pages expected"). Still `fail` for 0 links on a brochure/lead-gen page; still `warn` for 1-2. Optional: count in-page `#anchor` links as navigation and downgrade `fail` to `warn` when >=3 section anchors exist (one-pager marketing site).

### ux-cta-above-fold (sev 1): P/W heuristic
Rule: any `<a>`/`<button>` whose text+href matches `contact|book|get|buy|start|call|quote|kontakt|broneeri|telli|tel:|mailto:` inside 3000 raw characters after `<body>`.
- FP (pass): "Get" / "Start" / "Call" in any label ("Start page", "Get help docs", "Call for papers"), or in an unrelated href.
- FN (warn): `<input type=submit value="Get a quote">` (not an `a`/`button`) **[verified]**; `aria-label`/`title` CTAs; image-only links; non-English CTA words (`sign up`, `try`, `demo`, `subscribe`, `download`, `order`, `request`).
- Window is raw characters, not visible position: inline SVG or data: URIs at the top of `<body>` push a real CTA out; a missing `<body>` tag uses position 0 and includes `<head>`.
- Tool site: its CTA is the form submit "Scan" (no word match) -> warn.
- Proposed: `isAppShell` -> `skipped`; `isSinglePageTool` -> `skipped` ("primary action is the on-page form"); add `input[type=submit|button]` value and `aria-label` to the match; keep strict otherwise. Do not extend the word list without a fixture.

### ux-breadcrumbs, ux-case-studies, ux-response-time, ux-maps, ux-reviews, ux-local-schema, ux-team-photo (all sev 1, only ever `pass`/`warn`/`info`)
These never `fail`; today they emit `info` ("no X"). Not misleading for scoring (info is excluded), but they are noise and read as a to-do list on a tool.
- `ux-case-studies`: regex matches `projects|cases|tood|portfolio` anywhere in any `href` (FP: `/showcases/`, `/projects-archive`). `info` only.
- `ux-response-time`: `\b24 ?h\b` and `vastame` match unrelated prose (FP pass). `info` only.
- `ux-maps`: `geo` key in JSON-LD (any `GeoCoordinates`) counts as a map. `info` only.
- `ux-reviews`: `review` key in any JSON-LD node (incl. a `Review` of a book on a blog) counts; presence only.
- `ux-local-schema`: only fires when a `LocalBusiness`-family type exists, otherwise `info`; `Store|Hotel` match any type containing those letters (`Storefront`?). Low risk.
- `ux-team-photo`: `team|about|staff` unanchored in `src`/`alt` (`/img/steam.png` matches). `info` only.
- Proposed: when `isSinglePageTool` (or `isAppShell`) return `skipped` ("not applicable to a single-page tool") instead of `info`, so the report does not list local-business ideas for a tool. Marketing behaviour unchanged (still `info`). Lowest priority: no score impact.

### ux-faq (sev 1): P >=5, W 1-4, I none
Rule: max of FAQPage JSON-LD `mainEntity` length, **every** `<details>`, and `?`-ending headings when a heading contains `FAQ|KKK|korduma`.
- FP (the reported bug): any `<details>` (raw-JSON viewer, "show more", legal disclosure, nav dropdown) counts as an FAQ item **[verified: `<details>` alone -> warn "1 FAQ items"]**.
- FP: a real FAQ with 3 items is warned ("aim for 5"); that is the SPEC rule (checklist item 27) and stays.
- FN: accordions built from `<button aria-expanded>` + `<div>` (no `<details>`), FAQ in a section with `id=faq` and `<dl>`/`<h3>` without `?`, FAQ rendered by JS.
- FN: `FAQPage` with `mainEntity` as a single object counts as 1 (handled), but `Question` nodes nested elsewhere are not counted.
- Proposed (smallest): count a `<details>` only if its `<summary>` text ends with `?` or an FAQ-named heading precedes it (`hs` already computed); otherwise 0 -> `info` "no FAQ content". Plus `isAppShell`/`isSinglePageTool` -> `skipped`. A real FAQ with 1-4 items stays `warn`.

### ux-privacy-policy (sev 2): link -> fetch; none -> `fail` if form or analytics else `warn`
Rule: first `<a href>` whose `href + elText` matches `PRIV` (`privacy|privaatsus|andmekaitse|cookie-policy|küpsis`); must be http(s), GET 200 non-empty.
- FP (fail, the reported bug): any `<form>` (search, tool URL box, login to a separate app, newsletter handled elsewhere) **[verified tool site, search form, noscript form]**.
- FP (fail): a `<form>` inside `<noscript>` (the tokenizer does not treat noscript as inert) **[verified]**.
- FP (pass): `PRIV` matches path/slug fragments: `/blog/privacy-preserving-ml` passes after a 200 fetch **[verified]**; `küpsis` matches "küpsise" recipe pages.
- FP (warn): `mailto:privacy@...` link -> "privacy link is not http(s)" **[verified]**; fine that it does not pass, but the evidence blames the wrong thing.
- FN (no `fail`): cookie-consent banners/CMP scripts (`cookiebot`, `onetrust`, `usercentrics`) are not treated as "needs policy"; `<button>` "Privacy settings" does not count as a link; footer injected by JS is invisible (the shell is already flagged elsewhere).
- FN (analytics not detected): Cloudflare Web Analytics beacon, Clarity, Hotjar, Mixpanel, PostHog, Segment, Meta pixel `fbq(`, HubSpot `_hsq` **[verified: cloudflareinsights beacon -> analytics `info`]**. `need` is therefore under-triggered on tracker-only sites.
- FP (analytics): `ANALYTICS_SRC` matches substring `plausible|fathom|umami|matomo` in any script URL (`/js/plausible-ui.js`, `fathom-ui`); `G-[A-Z0-9]{6,}` matches any token like `X-G-ABCDEFG`.
- Proposed: replace `d.count('form') > 0 || d.analytics` with `collectsPersonalData` (personal-input form, login, or tracker). When there is no link and `isSinglePageTool` (no personal form, no tracker): `info` ("no personal-data form or tracker found in the HTML; add a policy if server logs or stores user input"). Keep `fail` for lead/newsletter/login forms and trackers; keep `warn` for brochure pages with nothing. Do not skip when `hasCommerce`. Tighten `PRIV` to require a policy noun (`privacy[-_ ]?(policy|notice|statement)`, `privacy$`, `/privacy/?$`) only if a fixture shows the blog-slug FP; not needed for this task.

### ux-analytics (sev 1): `info` none, `pass` otherwise
- FN: providers listed above. FP: substring matches above. No status penalty either way. No change required; widening the tracker regex is shared with privacy (see signals).

### ux-alt-text (sev 3)
Not page-type related, but one **real FP**: `<noscript><img height=1 width=1 src="https://www.facebook.com/tr?...">` (tracking pixel, no alt) fails the check **[verified]**; `<img>` without `alt` inside `<noscript>` or 1x1 sizes should not count. Out of scope for this task (flag only).

### ux-thank-you (site.js, sev 1): GET 4 fixed paths
Rule: any of `/thank-you /thanks /aitah /tanks` returns 200 non-shell HTML -> pass; all fetches errored -> skipped; `/<form\b/` -> `warn`; else `info`.
- FP (warn, the reported bug): any form: search form, tool URL form, JS-only form (no `action`), login form, newsletter handled by AJAX, `<form-field>` custom element (`\b` before `-`) **[regex, verified by reading]**; form only inside `<noscript>`.
- FN: real lead form posting to `/contact` whose thank-you is `/contact/thank-you`, `/kiitos`, `/danke`, `/success`, `/order-confirmation`, `?sent=1`, or an on-page success message; none are in the list, so the lead form is flagged although a thank-you page exists (over-strict, acceptable).
- FN: comparison `r.body.slice(0,1024) === html.slice(0,1024)` compares the raw response with the **stripInert** page: equality fails whenever the first KB contains a comment or script, so the home-page fallback is only caught by the `nf` comparison. Works for true soft-404 SPAs (nf identical), does not for a per-route 200 page that merely shares the layout.
- Cost: it always spends 4 of the 60-request budget even when there is no form at all.
- Proposed: compute `hasLeadForm` first. Order: no lead form -> `skipped` ("no lead/conversion form: search, tool or login form only") and **do not fetch the 4 paths**; lead form that is `jsOnly` or `external` -> `info` ("submits via JS / off-site, thank-you page cannot be inferred"); lead form posting to a same-origin `action` -> current behaviour (probe paths, `warn` when none). Existing "no form" `info` becomes `skipped` only for search/tool forms; with no `<form>` at all keep `info`. Both the still-`warn` (same-origin `action="/contact"` lead form) and the new skipped (tool form) need tests.

### ux-404-page (site.js, sev 3)
Rule: GET random path: 200 -> `fail` (soft 404); 404 with body >=300 bytes and not default text -> pass; 404 with tiny/default body -> `warn`; other status -> `warn`.
- FP (warn, tool site): the worker/API answers 404 with a 30-byte JSON error **[verified]**; an HTML page is not the point for a single-page tool. JSON/plain-text 404s and CDN default 404 are a normal, correct response for assets-only hosting.
- FN (pass): body length >=300 is the only "custom page" test: any JSON error pretty-printed over 300 bytes, or a generic 404 with no navigation, passes; `DEFAULT_404` covers only nginx/Apache/Express texts (not IIS, Caddy, S3, CF default).
- FN: random `-nf` path tests only the root namespace; a per-section 404 is never tried.
- Proposed: keep `fail` for soft-404 (that is a real crawler problem on any site). For a real 404 with a non-HTML `content-type` (JSON/plain) **or** `isSinglePageTool`, return `info` ("real 404; no custom page needed for a single-page tool"). Keep `warn` for marketing/lead-gen pages with tiny or default 404 bodies. Needs `site.js` to run `pageType` on its `html` and to read `ct(nf)`.

### ux-favicon, ux-default-hostname, ux-js-bundle-size (applicable to every site)
- `ux-favicon`: rel token exact-match `icon`; data: URI icon is accepted (tool site). No issue.
- `ux-default-hostname`: `DEFAULT_HOSTS` previously lacked `.workers.dev`, `.fly.dev`, `.surge.sh`, `.glitch.me` (and other platform defaults), so the tool's own workers.dev site passed: a false negative by list. Fixed: list extended to 26 suffixes and reviewed (see SPEC 6.7); the tool's own report now warns on this check, which is correct.
- `ux-js-bundle-size`: inline-only pages give `info` ("no same-origin scripts"); correct.

### ux-theme-color, ux-console-errors, ux-sticky-mobile-cta
`theme-color` is `info`/`pass` only. `ux-console-errors` and `ux-sticky-mobile-cta` are constant `skipped` (need a browser). No change.

### ai-* (site.js)
- `ai-robots-blocks-all` (sev 5): `Disallow: /` in a `*` group -> `fail`. Correct for any public site; FP only for intentionally private/staging sites (evidence states it). Not page-type related.
- `ai-robots-blocks-bots`: `warn` when an AI crawler is blocked; evidence says "may be intentional". Opinionated, sev 2; unrelated to page type. No change.
- `ai-llms-txt`: `warn` when missing or HTML/short; the title already says optional. A tool/brochure/any site is treated the same; the SPA-fallback HTML case is handled ("HTML or too short"). No change; if noise matters, downgrade to `info` globally (separate decision).

## 4. Change list (smallest set that fixes the behaviour)

| Rule | New behaviour | Still strict when |
|---|---|---|
| ux-thank-you | `skipped` (no fetches) for search/tool/login-only forms; `info` for JS-only or off-site lead forms | same-origin `action` lead form with no thank-you page -> `warn` |
| ux-privacy-policy | no link + no personal-data form + no tracker + `isSinglePageTool` -> `info` | lead/newsletter/login form or tracker -> `fail`; brochure with nothing -> `warn` |
| ux-internal-links | `isAppShell` or `isSinglePageTool` -> `skipped` | 0 links on a brochure/lead page -> `fail`; 1-2 -> `warn` |
| ux-cta-above-fold | `isAppShell` or `isSinglePageTool` -> `skipped`; also read `input[type=submit]` value and `aria-label` | marketing page with no CTA -> `warn` |
| ux-faq | count `<details>` only when question-like or under an FAQ heading; tool/shell -> `skipped` | genuine FAQ of 1-4 items -> `warn` |
| ux-404-page | real 404 + non-HTML body or single-page tool -> `info` | soft 404 -> `fail`; marketing tiny/default 404 -> `warn` |
| ux-breadcrumbs/case-studies/response-time/maps/reviews/local-schema/team-photo | optional: `skipped` for tool/shell instead of `info` | marketing pages unchanged (`info`) |

IDs, severities, checklist numbers and the 144/119/25 counts in SPEC.md do not change; only the rule text in SPEC section 6.6/6.7 (rows for the six changed rules) needs a one-line applicability note each.

## 5. Test plan (both directions per changed rule)

Reuse `fakeCtx` (html.js) and the `site(routes)` helper (site.js) from existing tests.

| Rule | Now-skipped / info case | Still-flagged case |
|---|---|---|
| ux-thank-you | tool page (single `type=text` url input, no action) -> `skipped`, and assert the 4 paths were **not** fetched | `<form action="/contact"><input type=email><textarea>` and no thank-you route -> `warn`; route present -> `pass` |
| ux-privacy-policy | tool page (WebApplication JSON-LD + url form, no tracker) -> `info` | lead form -> `fail`; Cloudflare beacon only -> `fail`; brochure without form -> `warn`; link present -> unchanged `pass`/`warn` |
| ux-internal-links | single-page tool -> `skipped`; empty SPA shell -> `skipped` | brochure (0 links, no tool evidence) -> `fail`; 2 links -> `warn` |
| ux-cta-above-fold | tool page -> `skipped` | marketing page without CTA -> `warn`; `input type=submit value="Get a quote"` -> `pass` |
| ux-faq | page with one `<details><summary>Raw JSON</summary>` -> `info` | `<details><summary>How does it work?</summary>` x3 -> `warn`; 5 -> `pass`; FAQPage JSON-LD -> counted |
| ux-404-page | real 404 with 30-byte JSON body -> `info` | 200 soft 404 -> `fail`; 404 with `Cannot GET /x` on a marketing page -> `warn` |
| classifier | `pageType` unit tests: search-only, login, newsletter, lead, noscript-only form, `<form-field>`, anchor-only page, WebApplication + links -> not a tool | |

Also add a regression test that runs the real `public/index.html` through `html.js` and asserts none of the six rules is `fail`/`warn` (a fixture copy, not a live fetch).

## 6. Risks and open choices

1. `isSinglePageTool` from HTML only can be wrong for a site whose other pages exist but are not linked on the home page; the evidence string must say why it was skipped so the user can override by linking pages. Conservative default keeps marketing sites strict.
2. `collectsPersonalData` cannot see server-side logging; the `info` text for tools says so instead of claiming compliance.
3. Scanning an inner page (not the root) classifies only that page; site-level checks (thank-you, 404) then use that page's type. Acceptable; note in evidence.
4. Decision needed from the lead: include the optional "info -> skipped" relabel of the seven info-only marketing checks (no score impact, only cleaner report) or leave for later. Recommended: leave for later (smallest change).
