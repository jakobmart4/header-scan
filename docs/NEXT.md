# header-scan: state and next steps

## Current state
- `main` = 5a7f1db; live (Render backend + Cloudflare Worker) runs 5a7f1db. The work below is in the working tree, reviewed and tested, not yet committed or deployed.
- `dist/` is git-ignored, rebuilt by `node scripts/build-pages.mjs`.
- Full suite: 660 tests, 0 failed on 2026-10-10 (`node --test "test/*.test.js"`); 602 at 5a7f1db.

## Built in this round
- `ux-cta-above-fold` redesign (`lib/checks/html.js`, `test/cta-above-fold.test.js`): window = first 2000 characters of visible text; label = aria-label, title, text without `<svg>`, `<img alt>`; wider English/Estonian word list (also Võta ühendust, päring, kandideeri, Sign&nbsp;up); href words in path, query and fragment, not host. Skipped on empty shells and on content pages (`contentSignal`: own JSON-LD article type incl. schema.org IRIs and NewsArticle subtypes, docs/wiki/forum generator, content subdomain; weak: og:type article, path, rel next/prev, 5+ `<article>`). `hasCommerce` cart paths also match `/view-cart`, `/shopping_cart`, `?page=cart`, not `/wiki/Food_cart`.
- Cold-start wake-up (`ui/src/app.js`): one `/api/health` on page load; "Waking up the scanner" after 5 s when the backend has not answered in 14 min; any backend JSON reply counts.
- Share link + Compare (`ui/src/share.js`): report in the URL fragment (never sent to a server), banner "not re-scanned, not verified"; Compare by file or link, by finding id; across scan depths probe findings are counted apart and the Security delta is withheld. `public/privacy.html` explains it.

## No-go decisions
- Headless browser for rendered pages: no. Render free has 512 MB; Cloudflare Browser Run is 10 min/day shared, has no IP pinning (SSRF guard) and would be the first npm dependency.
- Cron keep-warm: no. Staying awake 24/7 costs ~744 h, ~99% of Render's 750 free hours per month; one more service or restart would suspend the backend.

## Owner steps
1. Commit the working tree, then Render: Manual Deploy (needed, `lib/checks/html.js` changed).
2. `wrangler deploy` for the new UI (`public/index.html`, `dist/`), then the DEPLOY.md checks.
3. Nothing to change in the Render or Cloudflare dashboards. Keep exactly one free Render service.
4. Re-scan excalidraw and HN and add a dated line to `docs/research/ux-corpus.md`.

## Owner decisions (decided)
1. eesti.ee's `cloudflareinsights` beacon stays a tracker (`ux-privacy-policy` fails there).
2. `http://` on static pages is not redirected (`.dev` is HSTS-preloaded): accepted.
3. The workers.dev subdomain is kept; `ux-default-hostname` warns on our own report: accepted.
4. The repo is PUBLIC (Render needs it); new commits use the GitHub noreply address.

## Remaining limits
- CTA rule: only English and Estonian words; a blog post with only og:type article plus a comment form stays strict; a `#start-of-content` skip link counts as a CTA; JSON-LD types are matched as plain names or schema.org IRIs only.
- App shells keep the marketing rules (except the CTA rule); err.ee `ux-faq`, notion `ux-case-studies`, example.com `ux-404-page` false passes (`docs/research/ux-corpus.md`).
- Wake-up and file picker were tested with a mock server and DataTransfer, not a real Render cold start.

## Backlog
1. Percent-decode href paths before CTA matching if encoded slugs (`/k%C3%BCsi`) show up.
2. Strip schema.org IRI prefixes in `typesOf` for every JSON-LD rule, not only `contentSignal`, if prefixed types show up in scans.
