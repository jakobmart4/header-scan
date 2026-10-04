# UX / SEO applicability corpus

Real-site corpus for the page-type-dependent `ux-*` and `seo-*` checks. Date: 2026-09-30.

Method: local server on a random free port (`HEADERSCAN_ALLOW_PRIVATE` unset), passive `GET /api/scan?url=...` only, never deep, one site at a time. Spacing was 11 s instead of 3 s, because the server rate-limits scans to 6 per minute per IP. The server was stopped afterwards. Each verdict was checked against the real page HTML (fetched with curl or fetch). Rows marked "(not hand-verified)" rest on the scanner's own evidence only.

Verdicts: **correct**, **FP** (false positive: flagged but wrong or irrelevant), **FN** (false negative: passed but should not), **N/A** (check does not apply to this page type, so `skipped`/`info` is the right status).

Sites: excalidraw.com (single-page tool), developer.mozilla.org (docs), smashingmagazine.com (blog), allbirds.com (shop), err.ee (news), eesti.ee (gov portal, Angular SPA), notion.com (SaaS landing), summitdentalkamloops.ca (local business: a dental clinic; the search result `summitdentalclinic.ca` redirects there), news.ycombinator.com (forum), en.wikipedia.org (wiki), example.com (placeholder), header-scan.jakobmart4.workers.dev (our own one-page tool).

## Findings table

Rows where the status was a correct pass/info for the page type are not listed one by one; see "Rows omitted" at the end.

| site | check id | our status | verdict | why |
|---|---|---|---|---|
| excalidraw | ux-internal-links | fail (0, SPA-shell note) | FP / N/A | single-screen drawing tool, nothing to link to |
| excalidraw | ux-cta-above-fold | warn | FP / N/A | tool, not a conversion page; shell has 0 links/buttons in raw HTML |
| excalidraw | ux-privacy-policy | warn | N/A | no form, no analytics in raw HTML; the "no link" warn is advice for lead-gen sites |
| excalidraw | seo-spa-shell | fail | N/A (app) | empty shell is by design for an app; title/meta/OG are present. Correct for content sites |
| excalidraw | ux-404-page | fail (soft 404) | correct | random path returns 200 (SPA fallback); technically true |
| excalidraw | ux-js-bundle-size | fail (2174 KB) | correct | real size |
| excalidraw | seo-structured-data | warn | correct (low value) | no JSON-LD; a WebApplication block would be nice but not required |
| excalidraw | ux-thank-you | info | correct | no form |
| mdn | ux-cta-above-fold | warn | FP / N/A | docs site, no conversion goal |
| mdn | ux-thank-you / case-studies / faq / maps / reviews / local-schema / response-time | info | correct / N/A | nothing to find, info is right |
| mdn | ux-internal-links, ux-breadcrumbs, ux-404-page, ux-privacy-policy | pass | correct | all verified real (111 links, breadcrumbs, custom 404, /en-US/docs/Web/Privacy) |
| smashing | ux-cta-above-fold | warn | FP | blog; the real conversion is "subscribe/newsletter/membership", none in the CTA word list; nav items never match |
| smashing | ux-thank-you | pass | correct | `/thank-you/` is a real "Message sent!" page |
| smashing | seo-heading-order | warn (h2 to h4) | correct | real skip |
| smashing | seo-duplicate-titles | warn (dup meta desc) | correct (not hand-verified) | |
| smashing | ux-privacy-policy | pass | correct | `/category/privacy/` 200 |
| allbirds | ux-privacy-policy | fail | FP (likely) | no privacy link in raw HTML (footer is client-side), so a real shop is flagged "fail"; trigger is "form or analytics", and the only form is a contact form |
| allbirds | ux-thank-you | warn | N/A | shop; order confirmation lives behind checkout, unreachable passively. The guessed `/thank-you` paths are meaningless here |
| allbirds | ux-cta-above-fold | warn | FP | shop CTAs ("Shop ...") are beyond the first 3000 chars of body (98 KB of head/body markup noise) and "shop" is not a CTA word |
| allbirds | ux-alt-text | fail (3 of 42) | correct | real |
| err.ee | ux-privacy-policy | fail | FP | forms are search / feedback / word-suggest, not lead forms; consent UI exists; raw HTML has no privacy link text (client-rendered) |
| err.ee | ux-thank-you | warn | FP | same forms; none is a lead form |
| err.ee | ux-response-time | pass | FP (verified) | matched "24h uudised" (nav label "24h news") via `\b24 ?h\b` |
| err.ee | ux-faq | pass (8 items) | FP (verified) | 11 `<details>` elements, which are UI collapsibles (cookie consent / widgets); no FAQ/KKK text on the page |
| err.ee | ux-case-studies | pass | FP (verified) | matched substring `tood` inside the article slug `...eeltood-uute...`; news has no case studies |
| err.ee | ux-404-page | fail (soft 404) | correct (not hand-verified) | scanner evidence: 200 for random path |
| err.ee | seo-h1 | warn (8 h1) | correct (low value) | real multiple h1 on a news front page |
| err.ee | seo-duplicate-titles | fail | plausible (not hand-verified) | sample of 10 links; section pages may legitimately share titles |
| err.ee | seo-meta-desc-length | warn (12 chars) | correct | meta is literally "ERR uudised." |
| err.ee | ux-cta-above-fold | warn | FP / N/A | news site |
| eesti.ee | seo-spa-shell | pass (15 chars text) | FN (verified) | Angular shell (`<app-root>`, 15 chars visible text) passes; fingerprints cover Vite/CRA/Next only |
| eesti.ee | ux-internal-links | fail (0, no SPA note) | correct but misleading | 0 links in raw HTML because Angular renders them; evidence lacks the SPA-shell note that excalidraw got |
| eesti.ee | seo-h1 | fail | correct but misleading | no `<h1>` in raw HTML, same cause |
| eesti.ee | ux-privacy-policy | warn | N/A (unknowable) | raw HTML has no links at all, so absence proves nothing |
| eesti.ee | seo-duplicate-titles | fail | correct | every route returns the same shell and title "Eesti.ee" |
| eesti.ee | ux-404-page | fail (soft 404) | correct | SPA fallback returns 200 |
| eesti.ee | seo-title-length / seo-meta-desc-length | warn (8 chars) | correct | title and description are both just "Eesti.ee" |
| eesti.ee | ux-cta-above-fold | warn | N/A (unknowable) | shell, no content |
| notion | ux-cta-above-fold | warn | FP (verified) | "Get Notion free" exists but starts ~57 000 chars into the body (nav markup), far past the 3000-char window |
| notion | ux-case-studies | pass | FP | matched `/product/projects`, a product feature named "Projects" |
| notion | ux-404-page | warn (HTTP 401) | N/A | unknown paths 307 to an auth-gated app host; not a missing custom 404 page |
| notion | ux-privacy-policy | pass | correct outcome, weak | matched link is a help-page id (`/28ff...`), not the policy (`/trust/privacy-policy` exists) |
| notion | seo-duplicate-titles | fail (2) | plausible (not hand-verified) | |
| notion | ux-analytics | info | unknown | raw HTML shows none; tag managers may load dynamically |
| summit dental | ux-cta-above-fold | warn | FP (verified) | `tel:` first occurs at 5464 chars, "Request Appointment" at ~78 000; a local business clearly has a CTA |
| summit dental | ux-thank-you | warn | correct, low confidence | lead-gen form present, but it is AJAX (`onsubmit="return false"`); a thank-you may show inline. Keep strict for lead-gen |
| summit dental | ux-local-schema, ux-maps, ux-privacy-policy | pass | correct | Dentist JSON-LD, map, /site/privacy-policy all real |
| summit dental | seo-og-image / og-basic / twitter-card | fail / warn / warn | correct | missing on the real page |
| hacker news | ux-privacy-policy | fail | FP | the only form is a search form to hn.algolia.com; no analytics; "form present" is treated as data collection |
| hacker news | ux-thank-you | warn | FP | same search form |
| hacker news | ux-case-studies | pass | FP | matched an external story link `mattkeeter.com/projects/...`; the check is not limited to same-origin and user-submitted links trigger it |
| hacker news | ux-cta-above-fold | warn | FP / N/A | link aggregator |
| hacker news | ux-alt-text | fail (3 of 3) | correct (low value) | the images are spacer/vote gifs; technically missing alt |
| hacker news | ux-404-page | warn (tiny body "Unknown.") | correct (low value) | real tiny default 404 |
| hacker news | seo-h1 / seo-meta-description / seo-sitemap | fail / fail / warn | correct | none exist on the real page (irrelevant for a forum with its own discovery, but factual) |
| wikipedia | ux-thank-you | warn | FP | only the search form |
| wikipedia | ux-case-studies | pass | FP | external `wikimedia-projects` link |
| wikipedia | ux-cta-above-fold | warn | FP / N/A | encyclopedia |
| wikipedia | seo-meta-description | fail | correct | real tag missing (deliberate) |
| wikipedia | seo-viewport | warn (width=1120) | correct | real tag is `width=1120` |
| wikipedia | seo-sitemap | fail (robots lists it, HTTP 403) | unverified | may be a bot-UA block, not a missing sitemap |
| wikipedia | ux-privacy-policy | pass | correct | policy link resolves |
| example.com | ux-internal-links | fail (0) | FP / N/A | one-paragraph placeholder with a single external link |
| example.com | ux-privacy-policy | warn | N/A | no form, no analytics |
| example.com | ux-cta-above-fold | warn | FP | page has a "Learn more" link; "learn" is not a CTA word and the page is a placeholder anyway |
| example.com | seo-h1 / meta-description / og-* / robots | fail / fail / fail / warn | correct | real |
| header-scan | ux-internal-links | fail (0) | FP / N/A | one-page tool |
| header-scan | ux-privacy-policy | fail | FP / N/A | the "form" is the URL input of a JS-driven tool; no analytics, no data stored |
| header-scan | ux-thank-you | warn | FP / N/A | same form; JS renders results inline |
| header-scan | ux-cta-above-fold | warn | FP | primary action is a "Scan" button, not a CTA word |
| header-scan | ux-faq | warn (1 item) | FP / N/A | advice "aim for 5 questions" is marketing guidance; a tool with one Q&A block is fine |
| header-scan | ux-404-page | warn (tiny body) | correct (low value) | real plain 404 from the worker |

Rows omitted (correct and uninteresting): all `info` results for ux-breadcrumbs, ux-maps, ux-reviews, ux-local-schema, ux-team-photo, ux-response-time, ux-faq (where no FAQ), ux-analytics, ux-theme-color, ux-alt-text ("no images") on pages where the concept does not apply; all `pass` results for seo-title, seo-lang, seo-viewport, seo-canonical, seo-noindex, ux-favicon, ux-default-hostname.

## Systematic error classes

1. **"Has a `<form>`" is treated as "collects user data"** (ux-privacy-policy fail, ux-thank-you warn). Search boxes (HN, Wikipedia, err.ee, MDN), tool inputs (header-scan) and feedback widgets all count. 6 of 12 sites hit at least one wrong result. Only a real lead/contact/signup form (text/email/tel/textarea input, not `type=search`, not a `role=search` form, not a form whose action goes to a search endpoint) should count.
2. **Window too small for ux-cta-above-fold.** The first 3000 chars of body are mostly nav/SVG/script markup on modern pages; Notion and the dental clinic both have an obvious CTA 5 000 to 78 000 chars in. Word list is also narrow (no shop, learn, subscribe, sign up, try, submit, scan). This check fires a warn on all 12 sites, so it carries no signal at all.
3. **Marketing checks fire on non-marketing pages.** ux-cta-above-fold, ux-internal-links (single-page tools, placeholders), ux-faq "aim for 5", ux-privacy-policy "no link" warn, ux-thank-you: irrelevant for tools, docs, forums, wikis, news. Page type is not considered anywhere.
4. **Loose regexes.** `tood|projects|cases` in ux-case-studies matched article slugs ("eeltood"), a product feature, and external links (3 FPs on 3 of 12 sites; check is not limited to same-origin). `\b24 ?h\b` matched the nav label "24h uudised". ux-faq counts every `<details>` (err.ee: 11 collapsibles reported as 8 FAQ items).
5. **Raw-HTML limits presented as site defects.** Client-rendered footers/links (Allbirds, err.ee, eesti.ee) make ux-privacy-policy, ux-internal-links and seo-h1 fail; on eesti.ee the scanner even passes seo-spa-shell on a 15-char Angular shell (FN, only Vite/CRA/Next fingerprints). SPA-shell note on ux-internal-links is inconsistent (present on excalidraw, missing on eesti.ee).
6. **Shell/app sites double-count one root cause.** seo-spa-shell, seo-h1, ux-internal-links, seo-duplicate-titles (all routes same title), ux-404-page (soft 404) all fail together for excalidraw and eesti.ee. The soft-404 is technically true for an SPA fallback but not a separate defect. Acceptable to keep, but evidence should say "SPA fallback".
7. **Redirect/auth hosts misread as missing 404 page.** Notion's unknown path returns 401 after a 307 to an app host: reported warn "HTTP 401".
8. **Low-value strictness on minimal pages.** ux-alt-text fail on HN's spacer gifs, ux-404-page warn for tiny plain 404 bodies on HN and the worker. Correct, but noisy; leave as is unless the page-type work makes them skippable.

Checks that held up well on this corpus: ux-local-schema, ux-maps, ux-breadcrumbs, ux-favicon, ux-default-hostname, ux-js-bundle-size, ux-alt-text (as a fact), seo-title/meta/OG/twitter/lang/canonical/robots/sitemap (as facts).

## After the applicability work (rescan 2026-10-04)

Method: same as above. Local server on a random free port (`HEADERSCAN_ALLOW_PRIVATE` unset for the 11 public sites), passive `GET /api/scan?url=...`, 11 s apart (the 6 per minute rate limit makes 3 s impossible), each scan returned 119 findings and no module errors. The own-site row is the built `public/index.html` served by a throwaway static server on a free port with `HEADERSCAN_ALLOW_PRIVATE=1` (the live worker still serves the old build). Servers stopped afterwards. Verdicts below were checked against the scanner's evidence strings and, where noted, the raw HTML; they were not re-verified page by page.

Only rows whose status changed or that expose a new problem are listed. Everything not listed is unchanged from the table above.

| site | check id | before | after | verdict |
|---|---|---|---|---|
| header-scan (local build) | ux-internal-links | fail | skipped | fixed |
| header-scan (local build) | ux-cta-above-fold | warn | skipped | fixed |
| header-scan (local build) | ux-faq | warn | skipped | fixed |
| header-scan (local build) | ux-privacy-policy | fail | info (no personal-data form or tracker, single-page tool) | fixed |
| header-scan (local build) | ux-thank-you | warn | skipped | fixed |
| header-scan (local build) | ux-404-page | warn | info | fixed |
| header-scan (local build) | quality score | B 88 | A 90 (0 fail, ux 100); the remaining deductions are seo/ai warns, not ux | measured |
| err.ee | ux-thank-you | warn | skipped | fixed (search/feedback forms only) |
| err.ee | ux-case-studies | pass | info | fixed (slug substring no longer matches) |
| err.ee | ux-privacy-policy | fail | fail | now correct for a different reason: the page carries a gtag tracker and no policy link in raw HTML |
| err.ee | ux-faq (8 items) / ux-response-time | pass | pass | still FP: 11 `<details>` collapsibles still count (known limit, >= 2 count), `24h` regex untouched |
| hacker news | ux-thank-you | warn | skipped | fixed |
| hacker news | ux-case-studies | pass | info | fixed (external link) |
| hacker news | ux-privacy-policy | fail | pass (`/user`) | accidental pass: the link branch is unchanged, the match is a front-page username (`privacyisntdead`) in `user?id=`. Content-dependent, not caused by this work; a real FN |
| wikipedia | ux-thank-you | warn | skipped | fixed |
| wikipedia | ux-case-studies | pass | info | fixed |
| notion | ux-404-page | warn (HTTP 401) | info (auth-gated host) | fixed |
| notion | ux-case-studies | pass | pass (`/product/projects`) | still FP, documented limit |
| eesti.ee | ux-privacy-policy | warn | fail | regression-ish: Cloudflare injects `static.cloudflareinsights.com/beacon.min.js` for the scanner's Accept header, and the widened tracker list now counts it, so "tracker and no policy link" becomes fail. Consistent with the spec (tool-tracker.html expects fail) but the raw HTML has no links at all, so absence still proves little. Decision for the owner: keep (cookieless but third-party analytics) or treat a lone cloudflareinsights beacon as non-collecting |
| eesti.ee | ux-analytics | not listed (info) | pass | widened tracker list, expected |
| allbirds | ux-privacy-policy / ux-thank-you | fail / warn | fail / warn | unchanged by contract: the contact form is a real lead form and the commerce signal keeps it strict |
| summit dental | ux-thank-you | warn | warn | unchanged by contract (lead form) |
| example.com | ux-internal-links / ux-privacy-policy / ux-cta-above-fold | fail / warn / warn | fail / warn / warn | unchanged by contract: no tool signal, stays strict |
| excalidraw | ux-internal-links / ux-cta-above-fold / ux-privacy-policy | fail / warn / warn | fail / warn / warn | still FP/N/A: an empty app shell is never `isSinglePageTool` (seo-spa-shell owns it) |
| mdn, smashing, wikipedia, hacker news, err.ee, notion, eesti.ee | ux-cta-above-fold | warn | warn | unchanged: docs/news/forum/wiki page types deliberately stay strict, word list/window out of scope |

Irrelevant fail/warn results removed: the 6 own-site rows, 3 thank-you warns (err.ee, HN, Wikipedia; Allbirds and Summit stay), 3 false case-study passes (err.ee, HN, Wikipedia) and 1 Notion 404 warn. New or worse: eesti.ee privacy warn to fail. Still wrong and out of scope here: excalidraw (app shell), example.com, all cta warns on non-marketing pages, err.ee FAQ/response-time, Notion case-studies, HN privacy pass.
