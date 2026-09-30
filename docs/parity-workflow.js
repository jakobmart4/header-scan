export const meta = {
  name: 'header-scan-parity',
  description: 'Backend parity+superset vs SecurityHeaders.com: research, spec, 4 builders, integrator, 3 reviewers (incl. real public sites), fixer (13 agents)',
  phases: [
    { title: 'Research', detail: '3 researchers: CSP evaluator rules, header catalogue, parity gap' },
    { title: 'Spec', detail: 'PARITY-SPEC.md contract' },
    { title: 'Build', detail: '4 builders on disjoint files' },
    { title: 'Integrate', detail: 'suite green, wiring' },
    { title: 'Review', detail: 'accuracy vs standards, real public sites, diff security' },
    { title: 'Fix', detail: 'apply confirmed findings' },
  ],
}

const ROOT = 'C:\\Skills\\õppused\\header-scan'
const POWERS = 'C:\\Skills\\Powers'
const FIXTURE = `${ROOT}\\test\\fixtures\\securityheaders-com.json`

const COMMON = `
PROJECT: ${ROOT} (header-scan, Node ESM, no npm deps, node:test). Read SPEC.md, README.md and the existing lib/checks/*.js + test/*.test.js style first.
GOAL: be a strict SUPERSET of SecurityHeaders.com. Reference case: ${FIXTURE} = the real response headers of securityheaders.com (it scores A+ there). Our current checks flag real extra issues (cookie flags, x-powered-by, missing object-src/base-uri/frame-ancestors) but have GAPS found by comparison:
 1. COOP/COEP/CORP are reported "absent" although the site sends cross-origin-opener-policy-report-only / cross-origin-embedder-policy-report-only -> must say "report-only, not enforced".
 2. style-src 'unsafe-inline' is not flagged (only script-src is).
 3. script-src allowlists hosts known to enable CSP bypass (JSONP/AngularJS/open redirect gadgets: e.g. *.googletagmanager.com is fine-ish but www.google.com/recaptcha/, ajax.googleapis.com, cdnjs.cloudflare.com, cdn.jsdelivr.net, unpkg.com, *.cloudfront.net, *.appspot.com …) -> new check.
 4. Deprecated/harmful headers only get no comment: X-XSS-Protection (should be 0 or absent), Expect-CT, Public-Key-Pins, Feature-Policy, X-Download-Options, X-Permitted-Cross-Domain-Policies handling.
 5. ACAO:* deserves a nuanced finding (public CDN vs authenticated content), report-to/NEL/report-uri presence should be reported as info.
 6. The JSON result should include the raw response headers so a UI can show a raw-headers table; Set-Cookie VALUES MUST BE REDACTED (name + attributes only), long values truncated.
RULES: dependency-free; passive only; no secrets in findings evidence; keep existing IDs/behaviour stable unless SPEC-approved; every new check id needs a pass AND a non-pass test; score weights must be updated so grades stay meaningful; keep "node --test \\"test/*.test.js\\"" green; never leave servers running; never use port 34872; the UI workflow is running concurrently and owns ui/, public/, scripts/build-ui.mjs — do NOT touch those. Ponytail: minimal code, no speculative features. Code/comments in English; final reply English, brief.`

// ---------- Research (3, parallel) ----------
const RES_SCHEMA = { type: 'object', properties: { summary: { type: 'string' } }, required: ['summary'] }
const RESEARCH = [
  { k: 'csp-rules', t: `Research how Google CSP Evaluator, MDN and W3C CSP3 judge policies. Use WebSearch/WebFetch to verify (cite URLs). Produce: (a) an exact, sourced list of script-src hosts/host-patterns known to allow CSP bypass (JSONP / Angular / open-redirect) with a one-line reason each — only entries you can source; (b) rules for style-src / style-src-elem / style-src-attr / default-src fallback and unsafe-inline (nonce/hash neutralises unsafe-inline for that directive; strict-dynamic ignores host lists); (c) missing-directive rules (object-src, base-uri, frame-ancestors, form-action), trusted-types, report-uri/report-to. Write ${ROOT}\\docs\\research-csp.md (<=120 lines) incl. edge cases that cause false positives.` },
  { k: 'header-catalogue', t: `Build the catalogue of response headers relevant to a security scan: recommended (HSTS, CSP, XFO, XCTO, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP incl. -report-only variants, Cache-Control for sensitive pages, Clear-Site-Data), deprecated/harmful (X-XSS-Protection, Expect-CT, Public-Key-Pins, Feature-Policy, X-Download-Options, P3P), fingerprinting (Server, X-Powered-By, X-AspNet-Version, X-Generator, Via, X-Envoy-*, cf-ray etc. — decide which are worth reporting), reporting (Report-To, Reporting-Endpoints, NEL, CSP report-uri), CORS/Timing-Allow-Origin. Verify against MDN and the OWASP Secure Headers Project via WebFetch. Output a table (header | category | rule | severity | fix text) in ${ROOT}\\docs\\research-headers.md (<=150 lines). Invoke Skill "dataviz" NOT needed. Read ${POWERS}\\openai-skills\\skills\\.curated\\security-best-practices\\SKILL.md for tone.` },
  { k: 'parity-gap', t: `Compare our current output on ${FIXTURE} with what securityheaders.com would report (A+; it lists Additional Information for server, x-powered-by, ACAO, CSP, HSTS, referrer, XFO, x-xss-protection, XCTO, expect-ct, permissions-policy, report-to, nel, COEP/COOP report-only, plus "Upcoming headers" COEP/COOP/CORP). Run our modules against the fixture (see how test/headers.test.js builds ctx via fakeCtx from test/fixture-server.js) and produce a table: securityheaders item -> our check id -> our status -> gap? Also list ANY further item from the securityheaders.com report format we lack. Write ${ROOT}\\docs\\research-parity.md (<=100 lines).` },
]
phase('Research')
const res = await parallel(RESEARCH.map(r => () =>
  agent(`${COMMON}\n\nTASK: ${r.t}\nReturn a 5-line summary.`, { label: `research:${r.k}`, phase: 'Research', schema: RES_SCHEMA })))
log(`research: ${res.filter(Boolean).length}/${RESEARCH.length}`)

// ---------- Spec ----------
phase('Spec')
const spec = await agent(`${COMMON}

Read docs/research-*.md, SPEC.md, lib/score.js, lib/scan.js, lib/checks/headers.js, csp.js. Write ${ROOT}\\docs\\PARITY-SPEC.md, the single contract 4 parallel builders code against WITHOUT talking:
- exact new/changed check IDs per module (owner module for each), pass/warn/fail/info rule each in one line, severity, fix text guidance, checklist mapping; changed behaviour of hdr-coop/hdr-coep/hdr-corp (report-only states), how deprecated headers are judged;
- data file lib/data/csp-bypass-hosts.js export shape (array of {pattern, reason, ref}) and matching semantics (host-source matching per CSP rules incl. wildcards and paths, ignored when 'strict-dynamic' present with nonce/hash);
- score.js weight table additions (exact numbers) and the expected grades for: test/fixtures/securityheaders-com.json (headers scoring), good and bad fixture;
- JSON result addition: result.rawHeaders = [{name, value}] (lowercase names, order preserved, Set-Cookie values redacted to "<name>=<redacted>; attrs", values truncated to 512 chars, max 80 headers) — where it is built (lib/scan.js) and the exact field path;
- file ownership: (A) lib/checks/csp.js + lib/data/csp-bypass-hosts.js, (B) lib/checks/headers.js (+cookies.js only if needed), (C) lib/scan.js + lib/score.js, (D) tests: test/parity-securityheaders.test.js (asserts expected id->status for the fixture headers, incl. cookie fails and CSP warns, COOP/COEP report-only info), test/parity-new-checks.test.js, plus appending new IDs to SPEC.md section lists (D owns SPEC.md edits).
<=250 lines. Return the list of new IDs.`,
  { label: 'spec', phase: 'Spec', schema: { type: 'object', properties: { new_ids: { type: 'array', items: { type: 'string' } } }, required: ['new_ids'] } })
log(`new ids: ${spec && spec.new_ids && spec.new_ids.length}`)

// ---------- Build (4 parallel) ----------
const BUILDERS = [
  { k: 'A-csp', files: 'lib/checks/csp.js, lib/data/csp-bypass-hosts.js' },
  { k: 'B-headers', files: 'lib/checks/headers.js (and lib/checks/cookies.js only if PARITY-SPEC says so)' },
  { k: 'C-scan-score', files: 'lib/scan.js, lib/score.js' },
  { k: 'D-tests', files: 'test/parity-securityheaders.test.js, test/parity-new-checks.test.js, SPEC.md (append new IDs only)' },
]
phase('Build')
const built = await parallel(BUILDERS.map(b => () =>
  agent(`${COMMON}

Read ${ROOT}\\docs\\PARITY-SPEC.md and docs/research-*.md FIRST and follow the contract literally. You own ONLY: ${b.files}. If ambiguous choose the simplest reading and report it. Run "node --check" on files you write; run the relevant existing tests for your area (other builders are editing sibling files concurrently, so transient failures in their areas are expected — do not fix their files). Return files + deviations.`,
    { label: `build:${b.k}`, phase: 'Build', schema: { type: 'object', properties: { files: { type: 'array', items: { type: 'string' } }, deviations: { type: 'string' } }, required: ['files'] } })))
log(`builders: ${built.filter(Boolean).length}/${BUILDERS.length}`)

// ---------- Integrate ----------
phase('Integrate')
const integ = await agent(`${COMMON}

Builders' notes:\n${JSON.stringify(built.filter(Boolean))}\n
You are the integrator: make everything consistent with docs/PARITY-SPEC.md, run the FULL suite until green (the UI workflow may have added/changed ui tests; do not edit ui/ or public/), confirm result.rawHeaders appears in /api/scan output of the fixture server (server on a free port, then stop it) with cookie values redacted, confirm the securityheaders fixture yields the expected findings and that the SPEC check-count line is right. Report honestly: counts, what is unverified.`,
  { label: 'integrator', phase: 'Integrate', schema: { type: 'object', properties: { tests_passed: { type: 'number' }, tests_failed: { type: 'number' }, notes: { type: 'string' } }, required: ['tests_passed', 'tests_failed', 'notes'] } })
log(`integrator: pass=${integ && integ.tests_passed} fail=${integ && integ.tests_failed}`)

// ---------- Review (3) ----------
const FIND = { type: 'object', properties: { findings: { type: 'array', items: { type: 'object', properties: { file: { type: 'string' }, severity: { type: 'string' }, problem: { type: 'string' }, evidence: { type: 'string' }, fix: { type: 'string' } }, required: ['file', 'problem'] } } }, required: ['findings'] }
const REVIEWERS = [
  { k: 'accuracy', t: `Verify every new/changed check against the standards (MDN, W3C CSP3, OWASP Secure Headers, Google CSP Evaluator) with WebSearch/WebFetch: false positives/negatives in CSP host matching (wildcards, paths, schemes, 'strict-dynamic', nonces, 'self'), style-src fallback, report-only handling, deprecated header rules. Write throwaway node scripts (scratchpad, not the repo) with adversarial header sets: multiple CSP headers, comma-joined policies, uppercase names, duplicate headers, empty values, huge values, unicode, malformed directives.` },
  { k: 'real-sites', t: `First real-world test. Start the server on a free random port (HEADERSCAN_ALLOW_PRIVATE NOT set), passively scan (GET /api/scan?url=…, NOT deep) about 10 well-known public sites (e.g. https://github.com, https://www.mozilla.org, https://www.cloudflare.com, https://www.wikipedia.org, https://news.ycombinator.com, https://www.bbc.com, https://stripe.com, https://example.com, https://securityheaders.com, https://www.google.com) with ~3 s between requests. For each: did it crash/time out, are grades sane, are any findings clearly wrong when you check the site's real headers with curl -sI? Report only concrete false positives/negatives/crashes with the URL and evidence. Stop the server afterwards. Do not scan anything that is not a large public site.` },
  { k: 'diff-security', t: `Security review of the whole diff since commit 2b353a0 (git diff 2b353a0 -- lib test SPEC.md): rawHeaders redaction really covers set-cookie in every case (multiple set-cookie, case, folded values, cookie names with '=' in the value), no secrets or full cookie values in findings evidence, output-size limits (DoS via 10k headers, 1 MB header values), prototype-pollution keys as header names (__proto__, constructor), regex ReDoS in new code (test with pathological input and timing), JSON serialisation safety. Follow ${ROOT}\\..\\..\\Juhendid\\Ohutus ja Review.md.` },
]
phase('Review')
const reviews = await parallel(REVIEWERS.map(r => () =>
  agent(`${COMMON}\n\nYou are an ADVERSARIAL reviewer. Do NOT modify repo files; only report REAL, evidenced problems (drop doubtful ones), most severe first.\n${r.t}`,
    { label: `review:${r.k}`, phase: 'Review', schema: FIND })))
const all = reviews.filter(Boolean).flatMap(r => r.findings)
log(`review findings: ${all.length}`)

// ---------- Fix ----------
phase('Fix')
const fixed = await agent(`${COMMON}

Fix these reviewer findings (verify each is real first; skip false ones with a reason). Add a regression test for each fix, keep the whole suite green, update README.md/SPEC.md/PARITY-SPEC.md if behaviour changed, stop any process you started:\n${JSON.stringify(all, null, 1)}`,
  { label: 'fixer', phase: 'Fix', schema: { type: 'object', properties: { fixed: { type: 'array', items: { type: 'string' } }, skipped: { type: 'array', items: { type: 'string' } }, tests_passed: { type: 'number' }, tests_failed: { type: 'number' }, unverified: { type: 'string' } }, required: ['fixed', 'tests_passed', 'tests_failed'] } })

return { new_ids: spec && spec.new_ids, integrator: integ, review_findings: all.length, fixer: fixed }
