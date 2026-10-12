# header-scan: state and next steps

## Current state
- `main` = ae36d8a, deployed (Render backend + Cloudflare Worker) and live-verified on 2026-10-12; MDN's `ux-cta-above-fold` is `skipped` there as a content page, as intended. Check `git log` for later commits.
- `dist/` is git-ignored, rebuilt by `node scripts/build-pages.mjs`.
- Full suite: 704 tests, 0 failed (`node --test "test/*.test.js"`); CI runs it on Linux (`.github/workflows/ci.yml`).
- Settled decisions (no-gos, public repo, workers.dev, ...): `docs/DECISIONS.md`.

## Built 2026-10-12 from the skill audit
- Checks: unreachable page gets Quality N/A; non-HTML pages skip html.js; session-cookie names (glued `.ASPXAUTH`/`SAPISID` count, `author_pref`/`inside_banner` do not); MTA-STS, TLS-RPT and DKIM looked up at parent domains; comma-joined CSP/XCTO; case-insensitive `lang`.
- Runtime: probes stop before the scan deadline; `/api/health` returns `commit`; the Worker refuses `Sec-Fetch-Site: cross-site` with 403.
- UI: overview rows keyboard-reachable, status/severity in toggle names, `aria-invalid` on empty fields, grades in the done message; `build-ui` strips comments (index.html ~184 KB).
- CI workflow (UI drift check + tests), `docs/DECISIONS.md`, DEPLOY rollback section, Node >= 22.

## Owner steps
1. Push, then Render Manual Deploy (lib/ and server.js changed); the Worker deploys on push.
2. After the deploy, `GET /api/health` must show the pushed `commit` (confirms Render sets `RENDER_GIT_COMMIT` at runtime).
3. Check the first CI run in the Actions tab (first Linux run); fix failures, do not skip tests.
4. Optional: turn on the free GitHub branch protection "require CI". Decide whether render.yaml gets `autoDeployTrigger: checksPass` (owner decision, not changed).
5. Re-scan excalidraw and HN and add a dated line to `docs/research/ux-corpus.md`.

## Remaining limits
- CTA rule: only English and Estonian words; a blog post with only og:type article plus a comment form stays strict; a `#start-of-content` skip link counts as a CTA; JSON-LD types are matched as plain names or schema.org IRIs only.
- App shells keep the marketing rules (except the CTA rule); err.ee `ux-faq`, notion `ux-case-studies`, example.com `ux-404-page` false passes (`docs/research/ux-corpus.md`).
- A JSON or feed root still gets site-level Quality findings (robots.txt, sitemap, 404, favicon); only html.js skips it.
- A deep scan can take up to 47 s (probes get 2 s of slack past the 45 s deadline).
- Wake-up and file picker were tested with a mock server and DataTransfer, not a real Render cold start.

## Backlog
1. Percent-decode href paths before CTA matching if encoded slugs (`/k%C3%BCsi`) show up.
2. Strip schema.org IRI prefixes in `typesOf` for every JSON-LD rule, not only `contentSignal`, if prefixed types show up in scans.
3. SIGTERM handling in server.js (finish running scans on Render restarts).
4. A smoke script for the live deploy (health, one scan, CSP header).
5. Worker cold-start logging (how often `BACKEND_UNREACHABLE` is hit).
6. THREAT-MODEL table (assets, boundaries, mitigations) and a CHANGELOG.
