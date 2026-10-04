export const meta = {
  name: 'header-scan-build',
  description: 'Build header-scan (SecurityHeaders++ site scanner) using C:\\Skills\\Powers skills: 5 briefs, 1 architect, 7 builders, 1 integrator, 4 reviewers, 1 fixer (19 agents)',
  phases: [
    { title: 'Briefs', detail: '5 agents sweep all of Powers + checklist' },
    { title: 'Architect', detail: 'SPEC.md contract' },
    { title: 'Build', detail: '7 parallel builders, disjoint files' },
    { title: 'Integrate', detail: 'wire, run tests, fix' },
    { title: 'Review', detail: '4 adversarial reviewers' },
    { title: 'Fix', detail: 'apply confirmed findings' },
  ],
}

const ROOT = 'C:\\Skills\\õppused\\header-scan'
const POWERS = 'C:\\Skills\\Powers'
const CHECKLIST = 'C:\\Users\\PC\\Downloads\\40 asja hea projekti tegemiseks.txt'
const REVIEW_GUIDE = 'C:\\Skills\\Juhendid\\Ohutus ja Review.md'

const COMMON = `
PROJECT: "header-scan" in ${ROOT} — a SecurityHeaders.com-style website scanner that checks MUCH more: security headers (CSP parsed), cookies, TLS, DNS/mail (CAA, SPF, DMARC, DNSSEC), CORS, mixed content, SRI, security.txt, plus the SEO/AI-visibility/UX-hygiene checklist at ${CHECKLIST}.
DECISIONS (fixed by the user): Node (ESM, NO npm dependencies, node:test for tests) + one static HTML page. Passive scanning for any URL; ACTIVE probing (/.git/, /.env, /admin, backup files, etc.) ONLY after the domain owner is verified via DNS TXT record. SSRF protection is mandatory (block private/loopback/link-local/metadata IPs AFTER DNS resolution, pin the resolved IP for the connection, redirect/size/time limits).
Security posture: probes are read-only GETs, never exploit, never store/show secret file contents (only status + a tiny signature match), rate-limited.
Windows 11; use "py" not "python". Do NOT leave any dev server running (stop it after checks). NEVER use port 34872 (Rojo). Write code and comments in English. Keep code small and boring (ponytail mode: no speculative features).
Reply language for your final return value: English, brief.`

// ---------- Phase 1: briefs over ALL of Powers ----------
const BRIEF_SCHEMA = { type: 'object', properties: { summary: { type: 'string' }, files_read: { type: 'number' } }, required: ['summary'] }
const BRIEFS = [
  { k: 'A-agent-skills', t: `Read ALL 25 SKILL.md files under ${POWERS}\\agent-skills. Extract the rules/process/checklists that apply to building this scanner (spec-driven, security-and-hardening, frontend-ui-engineering, performance, testing, shipping, doubt-driven, constraint-driven).` },
  { k: 'B-codex-skills', t: `Read every top-level SKILL.md under ${POWERS}\\awesome-codex-skills (NOT composio-skills). Extract anything useful for: web app testing, design/theme, docs, MCP, changelog, deployment. Also read its README.` },
  { k: 'C-openai-skills', t: `Read all SKILL.md files under ${POWERS}\\openai-skills\\skills (.curated and .system), especially security-best-practices, security-threat-model, security-ownership-map, cloudflare-deploy. Extract threat-model items (SSRF, DNS rebinding, abuse of the scanner as a proxy) and deploy hints.` },
  { k: 'D-composio', t: `In ${POWERS}\\awesome-codex-skills\\composio-skills (~600 dirs) find with Grep/Glob every skill relevant to: DNS, WHOIS, TLS/SSL, certificates, domains, SEO, sitemap, robots, security scanning, threat intel (securitytrails, virustotal, urlscan, shodan, dnsfilter, nextdns, ravenseotools, similarweb...). Read those SKILL.md files. Report which data points/checks they suggest that we could implement with plain Node (no API keys).` },
  { k: 'E-ua-and-guides', t: `Read ${POWERS}\\Skills-Guide.md, ${REVIEW_GUIDE}, ${POWERS}\\ua-marketplace and ${POWERS}\\Understand-Anything (README, CLAUDE.md, SECURITY.md, docs; skip node_modules). Then read the checklist ${CHECKLIST} and convert its items 2 and 3 into a precise, numbered list of AUTOMATABLE checks (what to fetch, how to detect, pass/warn/fail rule); mark which need a headless browser (skip) vs plain HTTP.` },
]

phase('Briefs')
const briefs = await parallel(BRIEFS.map(b => () =>
  agent(`${COMMON}\n\nTASK: ${b.t}\nWrite a dense brief (max ~150 lines) to ${ROOT}\\docs\\briefs\\brief-${b.k}.md with: (1) skills you read (paths), (2) concrete rules/patterns to follow, (3) concrete check ideas for the scanner, (4) pitfalls. Return a 5-line summary.`,
    { label: `brief:${b.k}`, phase: 'Briefs', schema: BRIEF_SCHEMA })))
log(`briefs done: ${briefs.filter(Boolean).length}/${BRIEFS.length}`)

// ---------- Phase 2: architect ----------
phase('Architect')
const arch = await agent(`${COMMON}

Read all ${ROOT}\\docs\\briefs\\brief-*.md, the checklist, and the skill ${POWERS}\\agent-skills\\spec-driven-development\\SKILL.md and ${POWERS}\\agent-skills\\api-and-interface-design\\SKILL.md.
Write ${ROOT}\\SPEC.md: the single contract 7 parallel builders will code against WITHOUT talking to each other. It MUST fix exactly:
- File layout (Node ESM): server.js, lib/ssrf.js (safeFetch + assertPublicHost), lib/verify.js (DNS TXT ownership: token, challenge name "_headerscan-verify.<host>", HMAC-signed stateless token), lib/scan.js (orchestrator), lib/score.js, lib/checks/headers.js, cookies.js, csp.js, tls.js, dns.js, html.js (head/SEO/a11y/structured data), site.js (robots/sitemap/llms.txt/security.txt/404/favicon/source maps), probes.js (ACTIVE, gated by ctx.verified), public/index.html, test/*.test.js, test/fixture-server.js, package.json (scripts: start, test), README.md.
- Exact exported function signatures. Every check module exports: async function run(ctx) -> Finding[].
- ctx shape: {target:{url,host,origin}, verified:boolean, fetch(url,opts)->{status,headers,body,finalUrl,timingMs} (SSRF-safe), page:{status,headers,body,finalUrl,redirects[]}, resolve:{a,aaaa,txt(name),caa,mx,dnssec?}, allowPrivate:false (true only via env HEADERSCAN_ALLOW_PRIVATE=1 for local tests)}.
- Finding shape: {id:'kebab-id', category:'headers|cookies|tls|dns|mail|content|seo|ai|ux|exposure', title, status:'pass|warn|fail|info|skipped', severity:1-5, evidence:string(max 300 chars, never secrets), fix:string, ref?:url, checklist?:number}.
- Scoring (lib/score.js): letter grade A+..F with explicit rule; category sub-scores; how 'skipped' and 'info' are treated.
- HTTP API: GET /api/scan?url=… (passive), POST /api/verify/start {host} -> {token, txtName, txtValue}, POST /api/verify/check {host} -> {verified}, POST /api/scan {url, deep:true} (active probes only if verified). JSON result shape. Rate-limit rule (per-IP, in-memory). Timeouts/size limits (numbers).
- Complete list of check IDs, each owned by exactly ONE module (map checklist items 2 and 3 + security checks; aim for 60+ checks). Give the pass/warn/fail rule for each in one line.
- Probe list for probes.js (max 25 paths, read-only GET, signature-only matching, no content echo).
- Test strategy: fixture-server.js serves a deliberately bad site on a random localhost port; tests run with HEADERSCAN_ALLOW_PRIVATE=1.
Be precise and short (<400 lines). Return the list of check IDs per module as structured output.`,
  { label: 'architect', phase: 'Architect', schema: { type: 'object', properties: { modules: { type: 'object' }, total_checks: { type: 'number' } }, required: ['total_checks'] } })
log(`SPEC.md written; checks planned: ${arch && arch.total_checks}`)

// ---------- Phase 3: 7 builders ----------
const BUILDERS = [
  { k: 'core', files: 'server.js, lib/ssrf.js, lib/verify.js, lib/scan.js, package.json', extra: 'CRITICAL security code. safeFetch must resolve DNS itself, reject every non-public range (IPv4, IPv6, IPv4-mapped IPv6, decimal/octal/hex host forms, localhost aliases, 169.254.169.254, CGNAT, multicast), connect to the pinned IP (defeat DNS rebinding), re-validate on every redirect (max 5), cap body (2 MB) and time (10 s), only http/https, only ports 80/443/8080/8443. Verification token must be HMAC-signed with a server secret generated at start (or env). Include in-memory per-IP rate limit. server.js serves public/ statically and the API.' },
  { k: 'headers', files: 'lib/checks/headers.js, lib/checks/cookies.js, lib/checks/csp.js', extra: 'Real CSP parser (directives, sources, nonce/hash, unsafe-inline/eval, wildcard, data:, missing object-src/base-uri/frame-ancestors, report-only). HSTS (max-age>=1y, includeSubDomains, preload), COOP/COEP/CORP, Permissions-Policy, Referrer-Policy, XCTO, XFO vs frame-ancestors, info-leak headers (Server/X-Powered-By versions), cache-control on HTML, CORS misconfig (ACAO * with credentials, reflected origin via a test Origin header), cookie flags (Secure, HttpOnly, SameSite, __Host-/__Secure- prefixes).' },
  { k: 'tls-dns', files: 'lib/checks/tls.js, lib/checks/dns.js', extra: 'Use node:tls and node:dns only. TLS: protocol versions accepted (probe TLS1.0/1.1 rejected, 1.2/1.3 ok), cert validity/expiry days/chain/hostname/key size/sig alg, OCSP stapling if feasible, HTTP->HTTPS redirect, www/non-www consistency. DNS/mail: CAA, SPF (parse, -all, lookups<=10), DMARC (p=, rua), DKIM common selectors best-effort, MTA-STS, DNSSEC (best-effort via DoH is NOT allowed to third parties by default -> use node:dns and mark info if unavailable), dangling CNAME hint.' },
  { k: 'html', files: 'lib/checks/html.js', extra: 'Dependency-free HTML parsing (tokenizer-lite, not naive regex on whole doc where avoidable). Implement checklist item 2/3 HTML checks: empty view-source/CSR shell (react/vite root div with no content), title present/unique-length, meta description, og:image/og:title, canonical, H1 count, lang attr, viewport, favicon link, alt text on img, structured data JSON-LD (+ LocalBusiness), breadcrumbs, FAQ schema, mixed content, SRI on cross-origin script/link, inline handlers, target=_blank without rel, forms over http, JS bundle size hints (script src sizes via HEAD/GET capped), source map comments, analytics presence, privacy-policy link, CTA above the fold heuristic, tel:/maps links, vercel.app/netlify.app default host check.' },
  { k: 'site', files: 'lib/checks/site.js, lib/checks/probes.js', extra: 'site.js (passive, allowed for any target): robots.txt (exists, AI crawlers blocked? GPTBot/ClaudeBot/CCBot/Google-Extended, Sitemap directive), sitemap.xml (valid, urls count), llms.txt, security.txt (RFC 9116, Expires), custom 404 (request a random path: must be 404 status and not soft-404), source maps reachable (.js.map referenced), humans.txt info. probes.js (ACTIVE): runs ONLY if ctx.verified===true else returns a single "skipped" finding explaining DNS TXT verification; read-only GET to the max-25 path list from SPEC.md; detect via status + tiny signature (e.g. "[core]" for .git/config, "DB_PASSWORD=" pattern present -> only say "looks like env file", NEVER echo contents); concurrency 3; 200ms gap.' },
  { k: 'ui-score', files: 'lib/score.js, public/index.html', extra: 'score.js: implement the grading exactly per SPEC.md with a tiny self-check. public/index.html: ONE file (inline CSS+JS, no external requests, no CDN), read ' + POWERS + '\\agent-skills\\frontend-ui-engineering\\SKILL.md. Big grade badge, category sub-scores, findings grouped by category with pass/warn/fail filter, fix text and severity, "Verify ownership" flow (shows TXT name/value, Check button) that unlocks "Deep scan", copy/download JSON report, strict CSP-compatible (no inline event handlers; use a nonce-free approach by serving script from /app.js? NO — keep single file but the server sets CSP with a hash: compute it at startup in server.js is core-agent territory, so instead put JS in public/app.js and CSS in public/style.css and keep index.html tiny). Dark/light via prefers-color-scheme, keyboard accessible, mobile friendly. Escape ALL scanned data (use textContent, never innerHTML with scan data). Files you own: public/index.html, public/app.js, public/style.css, lib/score.js.' },
  { k: 'tests', files: 'test/fixture-server.js, test/*.test.js, README.md', extra: 'Read ' + POWERS + '\\agent-skills\\test-driven-development\\SKILL.md. fixture-server.js: a deliberately bad site (no security headers, weak CSP, bad cookies, no title/meta, 2 H1s, robots blocking GPTBot, exposed /.env returning fake "DB_PASSWORD=fake") on a random localhost port, plus a "good" mode. Tests (node:test): SSRF unit tests (all bypass forms, redirects to private IP, rebinding simulation with injected resolver), CSP parser, score.js, each check module against the fixture (findings present with expected status), probes skipped when unverified and run when verified, verify token tamper test. README.md: usage, API, safety model, how ownership verification works. Tests run with HEADERSCAN_ALLOW_PRIVATE=1. Do not run the whole suite until integrator — but do run what already exists to sanity check your own file syntax with node --check.' },
]

phase('Build')
const built = await parallel(BUILDERS.map(b => () =>
  agent(`${COMMON}

Read ${ROOT}\\SPEC.md FIRST and follow it literally (signatures, ids, shapes), plus the briefs in ${ROOT}\\docs\\. You own ONLY these files: ${b.files}. Do not touch other files. If the SPEC is ambiguous, choose the simplest reading and note it in your return value.
${b.extra}
Run "node --check" on every file you wrote. Return: files written, deviations from SPEC, open questions.`,
    { label: `build:${b.k}`, phase: 'Build', schema: { type: 'object', properties: { files: { type: 'array', items: { type: 'string' } }, deviations: { type: 'string' } }, required: ['files'] } })))
log(`builders done: ${built.filter(Boolean).length}/${BUILDERS.length}`)

// ---------- Phase 4: integrator ----------
phase('Integrate')
const integ = await agent(`${COMMON}

Builders' notes:\n${JSON.stringify(built.filter(Boolean))}\n
You are the integrator. In ${ROOT}: make everything consistent with SPEC.md (imports, ids, shapes), fix cross-module mismatches, run "node --test" with HEADERSCAN_ALLOW_PRIVATE=1 (PowerShell: $env:HEADERSCAN_ALLOW_PRIVATE=1), and iterate until green. Then start the server on a free port (not 34872), scan the fixture server end-to-end via /api/scan, confirm the JSON has 60+ findings and a grade, confirm that a scan of http://127.0.0.1 and http://169.254.169.254 is REJECTED without HEADERSCAN_ALLOW_PRIVATE. STOP every server/process you started. Return honest results: tests passed/failed counts, what is untested.`,
  { label: 'integrator', phase: 'Integrate', schema: { type: 'object', properties: { tests_passed: { type: 'number' }, tests_failed: { type: 'number' }, findings_count: { type: 'number' }, notes: { type: 'string' } }, required: ['tests_passed', 'tests_failed', 'notes'] } })
log(`integrator: pass=${integ && integ.tests_passed} fail=${integ && integ.tests_failed}`)

// ---------- Phase 5: adversarial review ----------
const FIND = { type: 'object', properties: { findings: { type: 'array', items: { type: 'object', properties: { file: { type: 'string' }, severity: { type: 'string' }, problem: { type: 'string' }, repro: { type: 'string' }, fix: { type: 'string' } }, required: ['file', 'problem'] } } }, required: ['findings'] }
const REVIEWERS = [
  { k: 'ssrf-abuse', t: `Try to BREAK lib/ssrf.js, lib/verify.js, server.js: SSRF bypass (IPv6 forms, ::ffff:, decimal/octal/hex IPs, userinfo@ tricks, redirect to private, DNS rebinding, port allowlist, protocol smuggling), verification forgery (token tamper/replay/cross-host reuse), rate-limit bypass (X-Forwarded-For), response splitting, reflected data into JSON/HTML, path traversal in static serving, unbounded memory. Write and run small scripts as proof (with HEADERSCAN_ALLOW_PRIVATE unset). Follow ${REVIEW_GUIDE} and ${POWERS}\\agent-skills\\security-and-hardening\\SKILL.md.` },
  { k: 'probes-safety', t: `Review lib/checks/probes.js and its gating: can it run unverified? does it ever echo secret file contents? is it strictly read-only, rate-limited, path-list-bounded? can a verified-domain check be spoofed for another host (e.g. redirect from verified host to a victim host — probes must stay same-origin, no cross-host redirects)? Also review whether the ownership-verification design is sound (DNS TXT, stateless HMAC token, expiry). Follow ${POWERS}\\openai-skills\\skills\\.curated\\security-threat-model\\SKILL.md if present.` },
  { k: 'coverage-vs-checklist', t: `Compare implemented check IDs against EVERY item of items 2 and 3 in ${CHECKLIST} (and SPEC.md's list). Produce a table: checklist item -> check id -> tested? Flag missing items, checks whose pass/warn/fail logic is wrong or produces false positives (run the scanner against the fixture "good" and "bad" modes and against 2 hand-made edge HTML files). Follow ${POWERS}\\agent-skills\\doubt-driven-development\\SKILL.md.` },
  { k: 'ui-e2e', t: `Run the server (free port, not 34872), open public/index.html with the built-in browser tools (mcp__Claude_Browser__*), do a full flow against the fixture server (needs HEADERSCAN_ALLOW_PRIVATE=1 for the server process): scan, filter, verify-ownership UI, JSON download. Check console errors, XSS via scanned data (fixture title containing <img onerror>), keyboard nav, contrast, mobile width 375. Then STOP the server and close/reset the browser viewport. Follow ${POWERS}\\agent-skills\\browser-testing-with-devtools\\SKILL.md and ${POWERS}\\agent-skills\\frontend-ui-engineering\\SKILL.md.` },
]
phase('Review')
const reviews = await parallel(REVIEWERS.map(r => () =>
  agent(`${COMMON}\n\nYou are an ADVERSARIAL reviewer of ${ROOT}. Do NOT modify source files; only report. Only report REAL, reproduced problems (default to dropping doubtful ones).\n${r.t}\nReturn findings ranked most severe first.`,
    { label: `review:${r.k}`, phase: 'Review', schema: FIND })))
const all = reviews.filter(Boolean).flatMap(r => r.findings)
log(`review findings: ${all.length}`)

// ---------- Phase 6: fixer ----------
phase('Fix')
const fixed = await agent(`${COMMON}

Apply fixes in ${ROOT} for these reviewer findings (verify each is real before changing; skip false ones and say so):\n${JSON.stringify(all, null, 1)}\n
Then re-run "node --test" (HEADERSCAN_ALLOW_PRIVATE=1) until green, add a regression test for every security fix, update README.md/SPEC.md if behaviour changed, stop any process you started. Return: fixed list, skipped list with reasons, final test counts, what remains untested.`,
  { label: 'fixer', phase: 'Fix', schema: { type: 'object', properties: { fixed: { type: 'array', items: { type: 'string' } }, skipped: { type: 'array', items: { type: 'string' } }, tests_passed: { type: 'number' }, tests_failed: { type: 'number' }, untested: { type: 'string' } }, required: ['fixed', 'tests_passed', 'tests_failed'] } })

return { briefs: briefs.filter(Boolean).length, checks_planned: arch && arch.total_checks, integrator: integ, review_findings: all.length, fixer: fixed }
