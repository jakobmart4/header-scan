export const meta = {
  name: 'header-scan-hardening',
  description: 'Parallel to the UX workflow: real-TLS tests for the 2 skipped checks, black-box security review of the live Worker+Render deployment, memory/perf profile for the free Render plan, then one fixer (4 agents)',
  phases: [
    { title: 'Audit', detail: '3 independent auditors on disjoint areas' },
    { title: 'Fix', detail: 'apply confirmed findings with regression tests' },
  ],
}

const ROOT = 'C:\\Skills\\õppused\\header-scan'
const LIVE = 'https://header-scan.jakobmart4.workers.dev'
const BACKEND = 'https://header-scan-backend.onrender.com'

const COMMON = `
PROJECT: ${ROOT} (header-scan, Node ESM, no npm deps, node:test). Read SPEC.md, README.md, DEPLOY.md, server.js, worker/index.js, wrangler.toml first.
DEPLOYMENT (live, the user's own infrastructure): UI+proxy Worker ${LIVE} -> Render backend ${BACKEND} (free plan, 512 MB, sleeps when idle; /api/* other than /api/health needs a shared proxy key that you do NOT have and must NEVER try to obtain, guess or brute-force).
ANOTHER WORKFLOW is running concurrently and owns: lib/checks/html.js, test/ux-applicability.test.js, test/fixtures/ux/*, public/og.*, ui/src/index.template.html (og tags), docs/ux-*. Do NOT touch those. Do not commit (the lead commits). Never use port 34872 (Rojo); never leave servers/processes/browser tabs open; no secrets in any output or file.
LIMITS for anything touching the LIVE deployment: black-box, read-only style requests only, at most ~80 requests in total, >= 1 s apart, no load/DoS tests, no attempts to bypass the proxy key, no scanning of third-party hosts except what a scan request legitimately targets (use https://example.com). Code/comments English; final reply English, brief.`

const NOEDGE = "\n\nBROWSER RULE (user instruction): do NOT use Microsoft Edge in any way: never start msedge.exe, never use a CDP/remote-debugging connection to Edge, never launch Playwright/Puppeteer/Selenium or any browser binary yourself. If a browser is truly needed use only the built-in Browser pane tools (mcp__Claude_Browser__*) with your own tab; otherwise report what could not be checked. Kill any server you start by PID when done."
const FIND = { type: 'object', properties: { findings: { type: 'array', items: { type: 'object', properties: { area: { type: 'string' }, severity: { type: 'string' }, problem: { type: 'string' }, evidence: { type: 'string' }, fix: { type: 'string' } }, required: ['area', 'problem'] } }, notes: { type: 'string' } }, required: ['findings'] }

const AUDITORS = [
  { k: 'tls-real', t: `Real-TLS tests for the two checks currently skipped in test/coverage-gaps.test.js: tls-legacy-protocols and tls-alpn-h2 (see lib/checks/tls.js). Write test/tls-real.test.js that, at test time, generates a throwaway self-signed certificate with the system "openssl" binary into an os.tmpdir() folder (skip the whole file with a clear reason if openssl is missing — NEVER commit a key/cert file), starts node:tls servers on 127.0.0.1:0 with (a) minVersion TLSv1 / ciphers DEFAULT@SECLEVEL=0 accepting TLS1.0/1.1, (b) TLS1.2+ only, (c) ALPNProtocols ['h2','http/1.1'] vs http/1.1 only, and runs the real check functions against them (HEADERSCAN_ALLOW_PRIVATE=1 for the test process). Also cover cert problems the module claims to detect (expired, hostname mismatch, self-signed chain) if feasible with openssl. If the tests reveal real bugs in lib/checks/tls.js, fix them minimally (you own lib/checks/tls.js and the new test file; update the two skipped tests in coverage-gaps.test.js to remove the stubs only if the new tests cover them). Keep the whole suite green ("node --test \\"test/*.test.js\\""; other workflow may add tests concurrently). Return findings = bugs found (even if fixed), with evidence.` },
  { k: 'live-blackbox', t: `Black-box security review of the LIVE deployment (read docs in worker/index.js first). Probe with curl (respect LIMITS): method tunnelling (HEAD/OPTIONS/PUT/DELETE/TRACE on each route), path tricks (//api/scan, /api/scan/, /api/%73can, /API/SCAN, /api/scan;x, encoded slashes, dot segments), query abuse (url= with CRLF, very long urls, userinfo, file:// gopher:// ftp://, IDN, IPv6/decimal/octal hosts that must be blocked), request body abuse on POST routes (oversize, wrong content-type, invalid JSON), header injection/forwarding (does the Worker pass X-Forwarded-For/Host/cookies to the backend? can a client spoof x-headerscan-client / x-headerscan-key?), caching (are API responses cache-control: no-store; can /api/* be cached by Cloudflare or poisoned via query/headers?), CORS on /api (should be same-origin only), error-message information leaks (stack traces, backend URL, versions), the rate limiter behaviour (does a burst of ~10 scans of https://example.com get 429 with Retry-After, and is the limit per real client IP rather than shared for everyone behind the Worker?), direct Render access without the key (must be 403 except /api/health), HTTP->HTTPS and TLS/header posture of BOTH hosts, the static assets (robots.txt, sitemap, llms.txt, og image, _headers applied on every path incl. 404 pages and /api errors). Also review wrangler.toml run_worker_first semantics: is anything under /api/* ever served from assets, and does the Worker handle all methods safely? Report only evidenced problems with the exact request and response.` },
  { k: 'mem-perf', t: `Memory/performance profile for the Render free plan (512 MB RAM, 0.1 CPU). Locally (free random port, HEADERSCAN_ALLOW_PRIVATE unset) run server.js in a child process, and passively scan ~10 heavy real public sites one after another (e.g. https://www.bbc.com, https://en.wikipedia.org, https://www.notion.com, https://www.allbirds.com, https://www.err.ee, https://developer.mozilla.org, https://news.ycombinator.com, https://github.com, https://www.smashingmagazine.com, https://stripe.com; >= 11 s apart because of the 6/min limiter) while sampling the child's RSS/heap (process.memoryUsage via a /proc-less approach: use PowerShell Get-Process WorkingSet64) and request durations; then do a local stress within limits: MAX_ACTIVE concurrency (server.js), 4 parallel scans of different public hosts, and confirm the 5th gets the documented 429/503 instead of memory growth. Check for memory leaks (hits Map pruning, rawHeaders, body buffers: 2 MB cap x concurrency), timeouts (server.requestTimeout 15000 vs scan deadline 45 s: do long scans get cut off mid-response behind Render/Cloudflare? Cloudflare Workers subrequest/HTTP timeout for the proxy fetch is also relevant), and the cold-start path (first request after sleep: what does the UI show; is 502 BACKEND_UNREACHABLE retried or explained?). Report numbers (peak RSS MB, p50/p95 duration) and concrete problems only. Stop the server and all child processes afterwards.` },
]

phase('Audit')
const audits = await parallel(AUDITORS.map(a => () =>
  agent(`${COMMON}${NOEDGE}\n\nTASK (${a.k}): ${a.t}`, { label: `audit:${a.k}`, phase: 'Audit', schema: FIND })))
const all = audits.filter(Boolean).flatMap(r => r.findings)
log(`audit findings: ${all.length}`)

phase('Fix')
const fixed = all.length === 0 ? null : await agent(`${COMMON}${NOEDGE}

Findings from the three auditors (the tls-real auditor may already have fixed lib/checks/tls.js — re-check before touching it):\n${JSON.stringify(all, null, 1)}\n
Verify each is real before changing anything; skip false ones with a reason; fix in worker/index.js, server.js, lib/ (NOT lib/checks/html.js), wrangler.toml, _headers generation (scripts/build-pages.mjs), README/DEPLOY.md; add a regression test per code fix; keep the whole suite green; do not deploy or change anything in the live Cloudflare/Render accounts — list what needs a manual dashboard change as a TODO for the user. Return fixed/skipped/todo-for-user lists and final test counts.`,
  { label: 'fixer', phase: 'Fix', schema: { type: 'object', properties: { fixed: { type: 'array', items: { type: 'string' } }, skipped: { type: 'array', items: { type: 'string' } }, todo_for_user: { type: 'array', items: { type: 'string' } }, tests_passed: { type: 'number' }, tests_failed: { type: 'number' } }, required: ['fixed', 'tests_passed', 'tests_failed'] } })

return { findings: all.length, notes: audits.filter(Boolean).map(a => a.notes).filter(Boolean), fixer: fixed }
