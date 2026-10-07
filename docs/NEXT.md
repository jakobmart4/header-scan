# header-scan: state and next steps

## Current state
- `main` = `origin/main` includes this run (hostile-input hardening, UI polish, docs); see git log.
- Live: unknown which commit is deployed; the owner deploys (Render redeploy + `wrangler deploy`, then the DEPLOY.md checks).
- Everything from this run is committed on main. `dist/` is git-ignored, rebuilt by `node scripts/build-pages.mjs`.

## Done in this run
- Fixer: linear generator-meta and CSP-bypass matching (max 1000 distinct sources), html.js tag cap (50,000 kept tags) and linear text of slices, JSON-LD `@type` non-strings ignored, `safeFetch` one growing buffer instead of one per chunk, oversized TXT records skipped in verify; 7 new hostile-input tests.
- UI: sample buttons in their own bar ("Try a sample", middot removed), shorter sample banner.
- Docs: SPEC/README/DEPLOY synced (minimal-page signals, privacy-link rule, `/privacy` and `/samples/*` are Worker assets only, /64 rate-limit limit).
- Corpus: regression run and 2026-10-06 re-check in `docs/research/ux-corpus.md`.
- Integrator: `build-ui` + `build-pages`, full suite green (516 tests, 0 failed); no e-mail or `mailto:` address in `public/` or `dist/` (only the generic `rua=mailto:...` in `samples/mixed.json`); one CSP rule in `dist/_headers`, its 2 script + 2 style hashes match the inline blocks of index.html and privacy.html; no node/msedge processes, ports 8811/87xx/88xx free.

## Regressions from the corpus run
- example.com: `ux-internal-links`, `ux-cta-above-fold`, `ux-privacy-policy`, `ux-faq` went fail/warn/warn/info instead of skipped/skipped/info/skipped, because the page now loads a first-party `/s.js`. Resolved by a197518 (one own script allowed on a link-free page with >= 60 chars of text); quality would go 67 D -> 70 C. Not yet re-run live.
- No other code-caused regressions.

## Confirmed vs refuted
- Confirmed improvements: err.ee `ux-privacy-policy` fail -> pass (real policy link found, article slug refused); eesti.ee `seo-spa-shell` pass -> fail (Angular `app-root` now recognised).
- Refuted as a fix: HN `ux-privacy-policy` pass -> warn is page drift; the old pass came from a user name, the false negative is still there.
- Refuted as a rule bug: the example.com regression was an owner decision (minimal page vs. own script), now taken.
- Confirmed remaining false verdicts: `ux-cta-above-fold` warns on 11 of 11 sites; app shells still get marketing rules. Older known limits: see the corpus doc. (The excalidraw robots.txt and HN duplicate-title false verdicts are fixed, see below.)

## Rule fixes (not yet committed)
- `ai-robots-blocks-all` / `ai-robots-blocks-bots`: RFC 9309 groups (CRLF/CR/LF, BOM, exact product tokens, same-name groups merged, Sitemap and unknown lines do not end a run). Whole-site block = a Disallow made of `*` and at most one `/` covers every path and no Allow matching `/` is as long as the longest Disallow matching `/`; Allow of a deeper path is an exception (`... except N Allow path(s)`). No path probes, so no collision with real paths. A bot without its own group falls back to `*` (`(N via User-agent: *)`). robots.txt is read up to 500 KB and a cut body drops its partial last line. Live re-scan 2026-10-07 (local code): excalidraw `ai-robots-blocks-all` pass (`not blocked`, was a false fail); quality 78.
- `seo-duplicate-titles`: same page = byte-identical home body, or same title + description as home and >= 90% of its own words (text outside `<a>`, `<nav>`, `<header>`, `<footer>`, digits dropped; a 256 KiB cut compared with the same home prefix), or a shared same-origin canonical (quote-aware attributes, `&amp;` decoded) or final URL; a page that is its own URL wins over aliases. Live re-scan 2026-10-07 (local code): HN `pass` (`9 pages, all unique`; `/news` merged into home, was a false fail).
- `ux-default-hostname`: 26 default-hostname suffixes (incl. `.workers.dev`), trailing dots ignored; the scanner's own workers.dev report now warns (severity 2).
- Tests: `test/robots.test.js`, `test/duptitles.test.js`, `test/hostname.test.js`; full suite 602 tests, 0 failed.
- Public sample `public/samples/mixed.json` still carries the old evidence `User-agent: * has Disallow: /` with blocks-bots pass, which the new rule no longer produces; update it in a samples step (the mixed score is pinned to 47..53, so check before changing blocks-bots).

## Open owner decisions
1. eesti.ee loads Cloudflare's `cloudflareinsights` beacon; by spec that is a tracker, so `ux-privacy-policy` fails there. Keep or allow-list?
2. `http://` on static pages (`/`, `/privacy`) is not redirected (platform serves assets, `.dev` is HSTS-preloaded). Accept, or custom domain with "Always Use HTTPS"?
3. The workers.dev subdomain contains the account name; publish under a custom domain instead? Until then the scanner's own report warns on ux-default-hostname (severity 2).
4. The repo is PUBLIC by the owner's choice (Render needs it); old commits carry the owner e-mail, accepted. New commits use the GitHub noreply address (repo-local git config).

## Backlog (priority order)
1. Deploy (Render redeploy for lib/, Cloudflare builds main), run the DEPLOY.md smoke checks (health, scan, headers, `/privacy`, `/samples/*.json`), re-scan example.com.
2. Commit the rule fixes above, deploy, re-scan excalidraw and HN from the live site; then add dated lines to `docs/research/ux-corpus.md` and update `public/samples/mixed.json`.
3. Decide items 1-3 above.
