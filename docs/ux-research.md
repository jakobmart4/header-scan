# UX checks: when do they apply?

Purpose: make the marketing-site heuristics (user checklist item 3) applicability-aware. A check that does not
apply returns `skipped` (or `info` with an explanation), never `fail`/`warn`. Marketing/lead-gen pages stay strict.
Dated 2026-09-30. Rules are for a passive scanner: only raw HTML, response headers and same-origin probes.

## Page-type signals (shared by all rules)

Default = treat as marketing (strict). Relax a check ONLY with positive evidence of a tool/app page AND no marketing signal.

- **Lead form**: `<form>` with `method=post` (or an `action` to a path/URL) holding an email/tel/name field, a
  `<textarea>`, or fields named like name|email|phone|message|kontakt. NOT a lead form: `role=search`, `type=search`,
  forms with no `action`/`method` (JS-driven), forms whose only fields are url/q/search/text/select.
- **Tool form**: a JS-driven form (no `action`, or only `type=url|search|text` inputs) and no lead form.
- **Marketing signals**: lead form; `tel:`/`mailto:` links; CTA words (contact, book, quote, buy, kontakt, broneeri);
  pricing/services/"our work" links; Organization/LocalBusiness JSON-LD with `contactPoint`/address.
- **Local signals**: LocalBusiness-family JSON-LD, a postal address, `tel:` plus opening hours, map embed.
- **Personal-data / tracking signals**: lead form; `type=password` (login/signup); analytics/ad/pixel script
  (existing `d.analytics`); non-essential cookies (Set-Cookie other than session/CSRF names).
- **Multi-page signals**: >= 3 distinct same-origin `<a href>`; `<nav>` with links; sitemap with > 1 `<loc>`.
- **Tool page** = tool form AND no marketing signals AND no local signals AND no multi-page signals.

## Per-check rules

### ux-privacy-policy (severity 2)
- Needed when personal data is collected or non-essential cookies/analytics are used: GDPR Art. 13 requires the
  controller to give identity, purposes, legal basis, retention and rights "where personal data ... are collected
  from the data subject" (https://gdpr-info.eu/art-13-gdpr/). ePrivacy Art. 5(3) requires consent for storing/reading
  non-essential cookies; only cookies strictly necessary for a requested service are exempt. Analytics cookies are
  generally not exempt (ICO); some DPAs (CNIL) exempt narrow, anonymous audience measurement
  (https://www.cookieyes.com/?p=10294, https://www.iubenda.com/en/help/23672-gdpr-cookie-consent-cheatsheet).
- A `<form>` alone is NOT a trigger: a URL/search box that sends nothing stored is not personal-data collection.
- Applies (keep `fail` when link missing): lead form, password field, analytics/pixel, non-essential Set-Cookie.
- Skip (`skipped`/`info`, "no personal-data collection detected"): tool page with no analytics and no tracking cookie.
  Missing link on a page without any of those signals stays `warn`/`info`, never `fail`.

### ux-thank-you (severity 1) (lib/checks/site.js)
- Convention, not a standard: a separate confirmation URL lets analytics/ads count a conversion and tells the user the
  message went through. It only makes sense after a lead/contact/newsletter/order submit (Google Ads/GA4 use the
  post-submit URL as a destination goal). Search, URL-analyser and other app forms return results inline: no thank-you page.
- Applies: a lead form (definition above) exists -> keep `warn` when no /thank-you, /thanks, /aitah, /tanks found.
- Skip (`info`/`skipped`, "no lead form: form is a search/tool form"): only tool/search/JS-driven forms.
- Caveat: JS-driven lead forms (fetch to an API) still count if they hold email/tel/message fields.

### ux-internal-links (severity 2)
- Google discovers pages through `<a href>` links; JS-inserted links count if they are real anchors
  (https://developers.google.com/search/docs/crawling-indexing/links-crawlable). Internal links matter when the site
  has more than one page to discover. A single-page tool has nothing to link to.
- Applies: multi-page signals, or marketing/local signals (a business site with 0 links is a real finding).
- Skip: tool page. Keep the existing SPA-shell wording when the raw HTML is an empty shell (links may be JS-only).

### ux-cta-above-fold (severity 1)
- Convention (conversion practice), no regulatory or Google source. Meaningful only when the page sells or collects leads.
- Applies: marketing signals or lead form. Skip: tool page (its primary action is the tool form, not a CTA).

### ux-faq (severity 1) and FAQPage schema
- 5 items is a rule of thumb, not a standard. Google limited FAQ rich results to well-known government/health sites in
  Aug 2023 and the docs now say the feature is no longer shown (https://developers.google.com/search/blog/2023/08/howto-faq-changes,
  https://developers.google.com/search/docs/appearance/structured-data/faqpage). Schema gives no ranking benefit for
  normal sites: do not demand it; keep "FAQ content" as a content hint.
- Applies (`warn` for 1-4 items): marketing/service pages. Skip/`info`: tool page, or no FAQ content (already `info`).
  A single FAQ entry on a tool page must not warn.

### ux-breadcrumbs, ux-case-studies, ux-sticky-mobile-cta (severity 1)
- Breadcrumbs show position in a hierarchy and can appear in results (https://developers.google.com/search/docs/appearance/structured-data/breadcrumb).
  Only useful with hierarchy depth. Already `info`-only; say "not applicable" for tool pages. Case studies = marketing only; sticky CTA stays `skipped`.

### ux-404-page (severity 3) (lib/checks/site.js)
- Applies to EVERY site, tool pages included. A missing page must return HTTP 404 (not 200): a 2xx with error-like
  content is a soft 404 that Search Console reports (https://developers.google.com/search/docs/crawling-indexing/http-network-errors).
  A friendly custom body is a UX bonus (navigation, search, home link), not required by Google.
- Keep `fail` for random path -> 200 (soft 404). Caveat: an SPA that serves its shell with 200 on every path is a true
  soft 404 and must still be flagged. Do not skip this check. The tiny/server-default-body `warn` may become `info`
  for tool pages (an API-style plain 404 is acceptable there), but the 200 case stays `fail`.

### ux-response-time (severity 1)
- Marketing convention ("we reply within 24 h"). Only relevant where visitors wait for an answer: lead form, contact
  page, `mailto:`/`tel:`. Currently `info`-only; add "not applicable" wording for tool pages.

### ux-maps, ux-reviews, ux-local-schema, ux-team-photo (severity 1, all `info`/`warn`)
- Local-business items. Google's LocalBusiness markup targets businesses shown in Search/Maps; `name` and `address` are
  required, `telephone`, `openingHoursSpecification`, `geo` recommended
  (https://developers.google.com/search/docs/appearance/structured-data/local-business). Reviews markup must be about
  the business's own real reviews, never self-serving invented ones. Team photo is a trust convention (low confidence).
- Applies: local signals (address, tel + hours, LocalBusiness type). Otherwise `info` with "not a local business";
  never `warn`. ux-local-schema keeps `warn` for missing fields ONLY when a LocalBusiness node exists (already true).

## Tests
Per changed rule: one case for the now-skipped page (tool form, no marketing/local/tracking signal) and one for the still-flagged
page (lead form, analytics, business page). ux-404-page: tool site serving 200 on unknown paths must still `fail`.

## Sources
GDPR Art. 13 https://gdpr-info.eu/art-13-gdpr/ . Cookie consent/analytics https://www.cookieyes.com/?p=10294 ,
https://www.iubenda.com/en/help/23672-gdpr-cookie-consent-cheatsheet . Soft 404
https://developers.google.com/search/docs/crawling-indexing/http-network-errors . Crawlable links
https://developers.google.com/search/docs/crawling-indexing/links-crawlable . FAQ change
https://developers.google.com/search/blog/2023/08/howto-faq-changes . LocalBusiness / breadcrumb docs as cited above.
Not verified first-hand: ICO/CNIL/EDPB pages (fetch returned 404); thank-you, CTA, response-time, team photo have no
normative source (conversion-practice conventions).
