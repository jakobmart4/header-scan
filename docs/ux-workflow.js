export const meta = {
  name: 'header-scan-ux-og',
  description: 'Refine ux-* heuristics (applicability gating, corpus-tested on real sites) and make a JPEG/PNG share image: 4 analysts, 1 spec, 3 builders, 1 integrator, 2 reviewers, 1 fixer (12 agents)',
  phases: [
    { title: 'Analyze', detail: '4 analysts: real-site corpus, code audit, best-practice rules, share-image options' },
    { title: 'Spec', detail: 'docs/UX-SPEC.md contract' },
    { title: 'Build', detail: 'html.js, tests, share image in parallel' },
    { title: 'Integrate', detail: 'suite green, rescan corpus' },
    { title: 'Review', detail: 'false-positive/negative corpus review + regression/security' },
    { title: 'Fix', detail: 'apply confirmed findings' },
  ],
}

const ROOT = 'C:\\Skills\\õppused\\header-scan'

const COMMON = `
PROJECT: ${ROOT} (header-scan, Node ESM, no npm deps, node:test). Read SPEC.md, README.md, lib/checks/html.js, lib/checks/site.js and test/*.test.js style first.
BACKGROUND: The scanner's own site (https://header-scan.jakobmart4.workers.dev, a single-page TOOL with one JS-driven URL form and no backend pages of its own) gets false/irrelevant UX findings: ux-thank-you ("form present but no thank-you page found"), ux-privacy-policy ("no privacy policy link but page has a form or analytics"), ux-internal-links (0 internal links), ux-cta-above-fold, ux-faq (1 FAQ item), ux-404-page. These heuristics were written for marketing/local-business sites (the user's checklist item 3: CTA above the fold, internal links, thank-you page, breadcrumbs, case studies, 5 FAQs, response-time promises, sticky mobile CTA, privacy page, maps, reviews, team photo, local schema). They must become APPLICABILITY-AWARE: when the page type makes a check irrelevant, return status 'skipped' (or 'info' with an explanation), never a misleading fail/warn; when relevant they stay strict. Do not weaken checks for genuine marketing/lead-gen pages.
RULES: dependency-free, passive only, keep existing IDs stable (no renames/removals; counts in SPEC.md must stay true or be updated), every changed rule needs tests for BOTH the now-skipped case and the still-flagged case, keep "node --test \\"test/*.test.js\\"" green (currently 365 pass / 2 skip), never leave servers/processes running, never use port 34872 (Rojo), no secrets in evidence, no commits (the lead commits). Code/comments English; final reply English, brief. Ponytail: smallest change that fixes the behaviour.`

// ---------- Analyze (4) ----------
const SUM = { type: 'object', properties: { summary: { type: 'string' } }, required: ['summary'] }
const ANALYSTS = [
  { k: 'corpus', t: `Build a real-site corpus test. Start the server locally (free random port, HEADERSCAN_ALLOW_PRIVATE NOT set) and passively scan (GET /api/scan?url=…, ~3 s apart, never deep) 12 varied PUBLIC sites: a single-page web tool (e.g. https://excalidraw.com), a docs site (https://developer.mozilla.org), a blog (https://www.smashingmagazine.com), a shop (https://www.allbirds.com), a news site (https://www.err.ee), a government portal (https://www.eesti.ee), a SaaS landing (https://www.notion.com), a small local business page you find (any public restaurant/dentist/plumber homepage), a forum (https://news.ycombinator.com), a wiki (https://en.wikipedia.org), https://example.com and https://header-scan.jakobmart4.workers.dev. For EVERY ux-* and related seo-* check that could be page-type dependent record the status + evidence and judge it by looking at the real page (curl the HTML): correct / false positive / false negative / not applicable. Write ${ROOT}\\docs\\ux-corpus.md as a table (site | check id | our status | verdict | why) and a summary of systematic error classes. Stop the server afterwards.` },
  { k: 'code-audit', t: `Audit every ux-* check (and seo-breadcrumbs/ai-* if relevant) in lib/checks/html.js and lib/checks/site.js: exact detection logic, regex pitfalls, inputs used, failure modes on SPAs (empty HTML shell rendered by JS), search forms, login forms, newsletter forms, JS-only forms (no action), forms inside noscript, pages with no internal links because they are one-page tools, cookie banners, 'privacy' matched in unrelated words, FAQ detection, CTA heuristics. Write ${ROOT}\\docs\\ux-audit.md: per check the rule, its false-positive/negative classes, and a proposed page-type classification signal (e.g. isAppShell, hasLeadForm, hasSearchOnlyForm, collectsPersonalData, isSinglePageTool, hasCommerce) computable from the HTML without a browser.` },
  { k: 'best-practice', t: `Research (WebSearch/WebFetch, cite URLs) when each of these practices is actually required or useful, to define applicability: privacy policy (GDPR Art. 13/ePrivacy: needed when personal data or non-essential cookies/analytics are used — NOT merely because a <form> exists), thank-you/confirmation page (only for lead/contact/newsletter POST forms, not search/app forms), internal links, CTA above the fold, FAQ with 5 items (+ FAQPage schema), breadcrumbs, custom 404 (Google soft-404 guidance), response-time promise, local schema/maps/reviews/team photo (only for local businesses). Write ${ROOT}\\docs\\ux-research.md (<=100 lines) with a concise applicability rule + what evidence on the page proves applicability, per check. Also read the user's checklist via memory file C:\\Users\\PC\\.claude\\projects\\C--Skills\\memory\\web-projekti-kontrollnimekiri.md.` },
  { k: 'share-image', t: `Decide how to produce the site's share image (1200x630) without npm dependencies. Currently public/og.svg exists but Facebook/X/LinkedIn do not render SVG og:image. Options to test in practice: (1) render an HTML page 1200x630 in a real browser and save a screenshot to disk — the Claude-in-Chrome tools (mcp__claude-in-chrome__*, load via ToolSearch; the user's Brave is connected; screenshot action has save_to_disk) and the built-in browser (mcp__Claude_Browser__*); (2) a pure-node PNG writer (zlib) with a small embedded bitmap font. Try (1) first: actually produce a file, check its real pixel size and format (PNG/JPEG magic bytes, width x height from the header) and view it. Report what works, the exact recipe, and the resulting file path under ${ROOT}\\docs\\og-candidate.* . Do NOT edit the repo's ui/src or public/ (the build agent does that). Close any browser tab you open.` },
]
phase('Analyze')
const analysis = await parallel(ANALYSTS.map(a => () =>
  agent(`${COMMON}\n\nTASK (${a.k}): ${a.t}\nReturn a 5-line summary.`, { label: `analyze:${a.k}`, phase: 'Analyze', schema: SUM })))
log(`analysts: ${analysis.filter(Boolean).length}/${ANALYSTS.length}`)

// ---------- Spec ----------
phase('Spec')
const spec = await agent(`${COMMON}

Read docs/ux-corpus.md, docs/ux-audit.md, docs/ux-research.md and the current code. Write ${ROOT}\\docs\\UX-SPEC.md, the contract for 3 parallel builders:
1. Page-type signals (exact names, detection rules from HTML only, where computed — one shared helper exported from lib/checks/html.js) and the exact new rule table per affected check id: applicability condition -> status/evidence when NOT applicable ('skipped' or 'info'; choose per check, with the evidence text), and unchanged strict behaviour when applicable. Include ux-thank-you, ux-privacy-policy, ux-internal-links, ux-cta-above-fold, ux-faq, ux-404-page and any other id the corpus shows is wrong.
2. Score implications: skipped/info are not counted (see lib/score.js) — state expected quality grade changes for the scanner's own site (expect better than B 88) and that genuine marketing fixtures must still score the same.
3. File ownership: (A) lib/checks/html.js (+ lib/checks/site.js only if the spec says so), (B) tests: test/ux-applicability.test.js (+ fixtures under test/fixtures/ux/*.html: single-page tool, search-form site, lead-gen local business, shop, blog, SPA shell), plus SPEC.md/README.md rule text updates, (C) share image: public/og.jpg or og.png (whatever the share-image analyst proved works), update ui/src/index.template.html og:image/twitter:image to the new file and remove public/og.svg if unused, run npm run build:ui and npm run build.
<=200 lines. Return the list of changed check ids.`,
  { label: 'spec', phase: 'Spec', schema: { type: 'object', properties: { changed_ids: { type: 'array', items: { type: 'string' } } }, required: ['changed_ids'] } })
log(`changed ids: ${spec && spec.changed_ids && spec.changed_ids.join(', ')}`)

// ---------- Build (3) ----------
const BUILDERS = [
  { k: 'A-html', t: 'Implement the page-type signals and new rules in lib/checks/html.js exactly per docs/UX-SPEC.md. Files you own: lib/checks/html.js (and lib/checks/site.js only if the spec says so).' },
  { k: 'B-tests', t: 'Write test/ux-applicability.test.js and fixtures under test/fixtures/ux/ per docs/UX-SPEC.md (both the skipped/info case and the still-flagged case for every changed id), and update rule text in SPEC.md/README.md. Other builders edit sibling files concurrently: transient failures in their areas are expected; do not edit lib/. Files you own: test/ux-applicability.test.js, test/fixtures/ux/*, SPEC.md, README.md, and existing tests ONLY where an assertion encodes the old behaviour the spec changes (list each one).' },
  { k: 'C-share-image', t: 'Produce the share image and wire it in per docs/UX-SPEC.md section 3C and docs/og-candidate.* (re-run the analyst recipe if needed, using Claude-in-Chrome or the built-in browser; close tabs, stop servers). Verify the final file really is a valid 1200x630 PNG/JPEG (magic bytes + header dimensions, file size < 600 KB) and looks right (view it). Files you own: public/og.*, ui/src/index.template.html (only the og:image / twitter:image tags), generated public/index.html + dist via the build scripts.' },
]
phase('Build')
const built = await parallel(BUILDERS.map(b => () =>
  agent(`${COMMON}\n\nRead ${ROOT}\\docs\\UX-SPEC.md first and follow it literally.\nTASK (${b.k}): ${b.t}\nRun node --check on JS you write. Return files + deviations.`,
    { label: `build:${b.k}`, phase: 'Build', schema: { type: 'object', properties: { files: { type: 'array', items: { type: 'string' } }, deviations: { type: 'string' } }, required: ['files'] } })))
log(`builders: ${built.filter(Boolean).length}/${BUILDERS.length}`)

// ---------- Integrate ----------
phase('Integrate')
const integ = await agent(`${COMMON}

Builders' notes:\n${JSON.stringify(built.filter(Boolean))}\n
You are the integrator: make everything consistent with docs/UX-SPEC.md; run the FULL suite until green (npm run build:ui first; adapt tests only where they encode the old behaviour, list them); check SPEC.md check counts are still true (119 passive + 25 deep = 144 unless the spec changed ids); rescan the 12-site corpus from docs/ux-corpus.md through a local server (free port, passive only, 3 s apart) and append an 'after' column/verdict to docs/ux-corpus.md; confirm the scanner's own page (scan https://header-scan.jakobmart4.workers.dev, it is live and current main may not be deployed yet — instead scan the local public/index.html by serving it with a tiny static server on a free port and HEADERSCAN_ALLOW_PRIVATE=1) no longer gets the irrelevant ux fails. Stop every server. Report honest counts and what is unverified.`,
  { label: 'integrator', phase: 'Integrate', schema: { type: 'object', properties: { tests_passed: { type: 'number' }, tests_failed: { type: 'number' }, notes: { type: 'string' } }, required: ['tests_passed', 'tests_failed', 'notes'] } })
log(`integrator: pass=${integ && integ.tests_passed} fail=${integ && integ.tests_failed}`)

// ---------- Review (2) ----------
const FIND = { type: 'object', properties: { findings: { type: 'array', items: { type: 'object', properties: { file: { type: 'string' }, severity: { type: 'string' }, problem: { type: 'string' }, evidence: { type: 'string' }, fix: { type: 'string' } }, required: ['file', 'problem'] } } }, required: ['findings'] }
const REVIEWERS = [
  { k: 'false-pos-neg', t: 'Adversarially try to make the new applicability logic WRONG in both directions: (1) genuine lead-gen/local-business/shop pages that are now wrongly skipped (hide a contact form behind a search-like input, a newsletter form with method=get, a page with a login form + analytics, a form inside an SPA shell, privacy link text in other languages such as Estonian "privaatsuspoliitika"/"andmekaitse", German "Datenschutz"), (2) tool/app pages that are still wrongly flagged. Write throwaway HTML cases in the scratchpad (not the repo), run the html module on them, and also rescan 6 fresh real public sites (not in the corpus; passive, 3 s apart, local server on a free port) and judge the ux-* results by looking at the HTML. Report only evidenced problems.' },
  { k: 'regression-security', t: 'Review the whole diff since commit 431869f (git diff 431869f -- lib test SPEC.md README.md ui public scripts): regex ReDoS/perf on large or hostile HTML (1-5 MB, 100k nested tags, unclosed comments/attributes; time it), prototype-pollution or crashes on odd input, evidence fields echoing page content safely (length caps, no HTML), score/grade regressions for the bad/good fixtures and the securityheaders fixture, the share image file (valid, size, no metadata leaks such as absolute local paths/usernames in PNG text chunks or EXIF), og tags correct in public/index.html and dist, tests really fail on the old behaviour (mutation-check two of them by temporarily reverting a rule in a scratch copy, NOT in the repo).' },
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

Fix these reviewer findings (verify each is real first; skip false ones with a reason; add a regression test per fix; keep the suite green; update SPEC.md/README.md/UX-SPEC.md if behaviour changed; rebuild public/index.html with npm run build:ui if you touch ui/src; stop any process you started):\n${JSON.stringify(all, null, 1)}`,
  { label: 'fixer', phase: 'Fix', schema: { type: 'object', properties: { fixed: { type: 'array', items: { type: 'string' } }, skipped: { type: 'array', items: { type: 'string' } }, tests_passed: { type: 'number' }, tests_failed: { type: 'number' }, unverified: { type: 'string' } }, required: ['fixed', 'tests_passed', 'tests_failed'] } })

return { changed_ids: spec && spec.changed_ids, integrator: integ, review_findings: all.length, fixer: fixed }
