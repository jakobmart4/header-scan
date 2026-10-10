# header-scan: state and next steps

## Current state
- `main` = 5a7f1db; live (Render backend + Cloudflare Worker) runs 5a7f1db. The owner deploys (Render redeploy + `wrangler deploy`, then the DEPLOY.md checks).
- `dist/` is git-ignored, rebuilt by `node scripts/build-pages.mjs`.
- Full suite: 602 tests at 5a7f1db; 640 tests, 0 failed with the uncommitted working tree on 2026-10-08 (`node --test "test/*.test.js"`).

## Done
- Rule fixes (6767cec): `ai-robots-blocks-all` / `ai-robots-blocks-bots` follow RFC 9309 groups and longest match; `seo-duplicate-titles` recognises the same page under another URL (identical body, same title + description + >= 90% of words, shared canonical or final URL); `ux-default-hostname` knows 26 default-hostname suffixes incl. `.workers.dev`. Tests: `test/robots.test.js`, `test/duptitles.test.js`, `test/hostname.test.js`.
- Minimal-page rule (a197518): one own script on a link-free text page stays minimal.
- Live re-check 2026-10-07 against the deployed 5a7f1db (`docs/research/ux-corpus.md`): example.com minimal again (quality 67 D -> 70 C), excalidraw `ai-robots-blocks-all` pass (70 D -> 78 D), HN `seo-duplicate-titles` pass (68 D -> 72 D).
- Samples: `public/samples/mixed.json` regenerated with the new robots rule; its fake site gained a favicon link and `twitter:card` so quality is back in range (security 51 E, quality 49 E, button "mixed 50/100"); `perfect.json` stays A+ 100 / A+ 100.

## Owner decisions (decided)
1. eesti.ee loads Cloudflare's `cloudflareinsights` beacon: stays a tracker, by spec (`ux-privacy-policy` fails there).
2. `http://` on static pages (`/`, `/privacy`) is not redirected (platform serves assets, `.dev` is HSTS-preloaded): accepted.
3. The workers.dev subdomain is kept; the scanner's own report warns `ux-default-hostname` (severity 2): accepted.
4. The repo is PUBLIC by the owner's choice (Render needs it); old commits carry the owner e-mail, accepted. New commits use the GitHub noreply address (repo-local git config).

## Known limits (from the corpus)
- App shells (excalidraw, eesti.ee) keep the marketing rules (except `ux-cta-above-fold`, skipped on an empty shell since 2026-10-07); `seo-spa-shell` already reports the root cause.
- err.ee `ux-faq` / `ux-response-time`, notion `ux-case-studies`, example.com `ux-404-page` false passes; short-link `ux-privacy-policy` FN. Details in `docs/research/ux-corpus.md`.

## Backlog
1. The working tree after 5a7f1db (`ux-cta-above-fold` redesign, share link, docs and samples) is not yet committed or deployed: live still runs the old CTA rule (2026-10-07 re-check: excalidraw and HN `ux-cta-above-fold` warn). Commit, redeploy, then re-scan both and add a dated line to `docs/research/ux-corpus.md`.
