# Brief B: awesome-codex-skills -> header-scan

Source: C:\Skills\Powers\awesome-codex-skills (composio-skills excluded). The repo is generic
(Composio CLI wrappers, office/comms helpers); little is scanner-specific. The value is in process patterns.

## 1. Read (all under C:\Skills\Powers\awesome-codex-skills\)
- README.md
- webapp-testing\SKILL.md (scripts\with_server.py and examples\*.py only listed, not read)
- theme-factory\SKILL.md, brand-guidelines\SKILL.md, canvas-design\SKILL.md (head)
- changelog-generator\SKILL.md, deploy-pipeline\SKILL.md, create-plan\SKILL.md
- mcp-builder\SKILL.md + mcp-builder\reference\mcp_best_practices.md (grepped: security/limits/errors)
- gh-fix-ci, pr-review-ci-fix, codebase-migrate, sentry-triage, datadog-logs (head)
- helium-mcp, agent-deep-links, internal-comms, notion-spec-to-implementation (head), skill-creator (head)
- Skipped as irrelevant (listed in README only): invoice, resume, raffle, meeting, lead, ads, video, gif, image, file-organizer.

## 2. Rules / patterns to follow

### Web app testing (webapp-testing)
- Decision tree: static HTML -> read the file to find selectors; dynamic -> start server, recon-then-act.
  Our UI is ONE static HTML page: read it directly. Playwright is NOT allowed (no npm deps); UI check =
  load page in the Browser pane once, screenshot, read console, then stop the server.
- Recon-then-action: screenshot/DOM first, discover selectors, then act. Wait for networkidle (or for the
  result element) BEFORE reading the DOM; our page fetches /api/scan, so wait for the result container.
- Capture console logs during the UI check: zero console errors is an acceptance gate.
- Server lifecycle helper pattern (with_server.py): start server, wait for port, run check, ALWAYS kill it.
  Re-implement in ~15 lines inside node:test: listen on port 0 (random), close in `after()`.
  Never fixed port, never 34872 (Rojo), never leave a dev server running (user rule).
- Treat helper scripts as black boxes: `--help` first. Our CLI must support `--help` too.

### Design / theme (theme-factory, brand-guidelines, canvas-design)
- A theme is a small token set (palette hex + heading/body font pair) applied consistently, with contrast checked.
  Use CSS custom properties on :root; light + dark via prefers-color-scheme. No theme picker (YAGNI).
- brand-guidelines palette shape is a good template: 4 neutrals (bg, surface, text, divider) + 2-3 accents.
  Do NOT reuse OpenAI branding; define own tokens. Fonts: system-ui/Arial; mono: ui-monospace/Menlo fallback.
- Text colour derives from background via tokens, not per-element overrides.
- Grades must not rely on colour alone (letter + text label) for accessibility.
- "Information lives in design, not paragraphs": result page = big grade, compact findings table, few words.

### Docs / plans (create-plan, notion-spec-to-implementation, skill-creator)
- Plan template: intent paragraph -> Scope In/Out -> 6-10 atomic verb-first checklist items ordered
  discovery -> changes -> tests -> rollout; include a test item and an edge-case/risk item; max 3 open questions.
- Concise is key: docs carry only what the reader does not already know; short README, details in docs/*.md,
  one table for the check catalogue (progressive disclosure).
- Size tasks to 1-2 days with acceptance criteria. Map: each check = id, severity, pass/fail rule, fix text.

### MCP (mcp-builder, helium-mcp)
- MCP is NOT in scope now (YAGNI). If ever added: ONE workflow tool `scan_url`, not many endpoint tools;
  concise vs detailed output; actionable errors ("domain not verified; add TXT record X");
  readOnlyHint=true for passive scan; active probing tool gets openWorldHint and requires verification.
- Same ideas for our JSON API: concise by default, `?detail=1` for full; explicit `truncated: true` when capped;
  always honour limits.
- Errors: no stack traces or internal resolved IPs to clients; log security-relevant errors; timeouts on all I/O;
  rate limit expensive calls; best-practices doc mentions DNS rebinding, which reinforces resolve-then-pin.
- Long-running servers hang the caller: test with timeout / random port and kill.
- Evaluation-driven development: ~10 independent, read-only, stable Q/A pairs -> our fixtures: ~10 local test
  servers (good site, no HSTS, bad CSP, weak cookies, ...) with known expected findings.

### Changelog / deployment (changelog-generator, deploy-pipeline, codebase-migrate, gh-fix-ci)
- CHANGELOG.md in user language, grouped New / Improvements / Fixes / Security; drop refactor/test noise.
  Add a "Checks added" list (new check ids): that is what users of a scanner care about.
- Conventional commit prefixes (feat/fix/security/docs) make the changelog mechanical.
- Deploy steps are serialized, each with a rollback (reverse order) and a post-deploy verify
  (`curl -fsS /health`). For us: `/health` endpoint + one smoke scan of a known-good local fixture.
- One transform per commit; small reviewable batches; roll back per batch.
- CI: reproduce locally first; pin Node version parity (.nvmrc / "engines").
- Never run parallel calls against the same rate-limited target: our probe scheduler serializes per host.
- Triage pattern (sentry/datadog): ranked digest by severity/frequency -> report sorts findings by severity.

## 3. Concrete check ideas for the scanner (derived; not literal in the skills)
1. Redirect hygiene: final URL stays https; report chain length and any http hop.
2. Scanner self-check: `/health` returns 200 + version (post-deploy verify pattern).
3. Console/CSP-violation errors: only if a browser is available; otherwise static parse. Do not claim otherwise.
4. Theme/UX hygiene: `<meta name="theme-color">`, `color-scheme`/prefers-color-scheme CSS, viewport meta, `lang`.
   Contrast is NOT computable statically: do not claim it.
5. Third-party origin inventory (scripts/styles/fonts/images) with SRI present/absent per resource;
   external font CDNs flagged (privacy + needs CSP font-src).
6. `/.well-known/security.txt` valid (Contact, Expires in future); `/.well-known/change-password` present (info).
7. `/changelog`, `/CHANGELOG.md` public: informational (version disclosure), not a fail.
8. Version disclosure: Server / X-Powered-By / generator meta with version numbers (low).
9. MCP exposure: `/.well-known/mcp*` (passive). `/mcp`, `/sse` unauthenticated reachability = ACTIVE, verified owners only.
   Missing Origin/Host validation (DNS rebinding) is only checkable actively.
10. Deploy leftovers (ACTIVE, verified only): /.git/HEAD, /.env, /.vercel, /.github/workflows/, /package.json,
    /wp-config.php.bak, /backup.zip, /debug, /server-status. Store status + <=16-byte signature match, never the body.
11. Health/metrics detail (ACTIVE, verified only): /health, /status, /metrics, /actuator/* returning version JSON.
12. Error-page leakage: 404 for one random path (a normal GET, passive) containing stack frames
    (`at Object.<anonymous>`, `Traceback`, absolute file paths) - sentry-style frame signatures.
13. Cache-Control on pages that set cookies (no `public`); `Clear-Site-Data` on logout (info).

## 4. Pitfalls
- Reading the DOM before the async result renders makes the UI test flaky: wait for the result element.
- Dev server left running violates the user rule: kill in `finally`/`after()`; random port; NEVER 34872.
- Windows: use `py` not `python`; Git Bash vs PowerShell quoting; write files in place (Rojo watches; no `sed -i` rename).
- The skills' scripts are Python + Playwright + Composio CLI: unusable here (no deps, needs accounts/OAuth).
  Only patterns transfer. Never enter credentials into any `composio link` flow.
- Do not parallelize probes on one host; honour rate limit and an overall time budget.
- Rollback ethos: never delete/mutate (Stripe note) -> our probes are GET-only, enforced by a code allowlist,
  because MCP annotations/hints are not security guarantees.
- Unbounded response bodies = memory DoS: cap bytes when reading target bodies; cap redirects; truncate with a flag.
- Errors should tell the user which TXT record to add but must not leak internal resolver results.
- Do not copy OpenAI colours/branding; theme-factory showcase is a PDF and not needed; write own tokens.
- Changelog/docs/logs must never contain secret values seen during probes.
- README of the repo advertises external installs (npx, curl | bash): do not run any of them.
