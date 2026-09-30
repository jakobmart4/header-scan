# CSP research: Google CSP Evaluator, MDN, W3C CSP3 (fetched 2026-09-30)
Input for PARITY-SPEC.md. `(inf)` = my inference, not stated by a source. Caveat: WebFetch returns model-made summaries; the W3C page
is too long to read whole, so W3C algorithm wording was cross-checked only via section anchors + MDN + Evaluator, not read verbatim.

## Sources
- [E] Google CSP Evaluator (Apache-2.0) https://github.com/google/csp-evaluator : checks/security_checks.ts, checks/strictcsp_checks.ts, evaluator.ts, csp.ts, utils.ts, allowlist_bypasses/{jsonp,angular,flash}.ts
- [C] CSPBypass gadget list (domains from Common Crawl script-src) https://github.com/renniepak/CSPBypass (data.tsv)
- [H] HackTricks https://github.com/HackTricks-wiki/hacktricks/blob/master/src/pentesting-web/content-security-policy-csp-bypass/README.md
- [B] cdnjs + AngularJS write-up https://blog.huli.tw/2022/09/01/en/angularjs-csp-bypass-cdnjs/
- [P] Google paper "CSP Is Dead, Long Live CSP" https://research.google/pubs/csp-is-dead-long-live-csp-on-the-insecurity-of-whitelists-and-the-future-of-content-security-policy/ (94.72% of policies bypassable; 14 of the 15 most allowlisted script hosts have unsafe endpoints)
- [W] W3C CSP3 https://www.w3.org/TR/CSP3/ : #allow-all-inline (6.7.3.2), #effective-directive-for-inline-check (6.8.2), #directive-fallback-list (6.8.3), #strict-dynamic-usage (8.2)
- [M] MDN https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy (+ /default-src /style-src /style-src-elem /style-src-attr /frame-ancestors /trusted-types /report-uri /report-to) and .../Guides/CSP
- [G] https://web.dev/articles/strict-csp  [O] https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
- [S] https://scotthelme.co.uk/can-you-get-pwned-with-css/  [L] https://lists.w3.org/Archives/Public/public-webappsec/2015Jul/0026.html (path ignored after redirect)

## A. script-src hosts known to allow CSP bypass
Matching semantics ([E] utils.ts + [M] host-source rules):
- Judge only the EFFECTIVE script directive: script-src-elem, else script-src, else default-src [W 6.8.2/6.8.3]. Never style-/font-/img-/connect-/frame-src.
- Skip keywords (`'...'`), bare schemes, entries without a dot. Drop scheme and port. `*.x.com` matches any host ending `.x.com`; no wildcard = exact host.
- Path: none = any path; trailing `/` = prefix; no trailing `/` = exact file [M, E]. Flag only if the allowed path covers a gadget path below.
- Ignore the whole list when the directive has `'strict-dynamic'` (host sources are dropped) [W 8.2, M, E effective CSP].
- Path restriction does not stop open redirects: browsers ignore the source path after a redirect [L, H] -> report path-restricted hits at most `info`.

| pattern | class | one-line reason | src |
|---|---|---|---|
| `cdnjs.cloudflare.com` | AngularJS | serves AngularJS 1.2.16 (`/ajax/libs/angular.js/`) and prototype-polluting libs -> template-injection XSS | E,C,B |
| `cdn.jsdelivr.net`, `*.jsdelivr.com` | AngularJS, htmx, any npm/GitHub file | E lists AngularJS 1.1.2 and the bare host; H: code execution | E,C,H |
| `unpkg.com` | AngularJS, htmx | serves any npm package; NOT in E, only C | C |
| `ajax.googleapis.com` | AngularJS + JSONP | `/ajax/libs/angularjs/1.2.0rc1/`, `/ajax/services/search/news`, `/ajax/services/feed/find?callback=` | E,H,C |
| `code.angularjs.org` | AngularJS | official AngularJS 1.x host | C |
| `www.gstatic.com`, `gstatic.com`, `ssl.gstatic.com` | AngularJS | `/fsn/angular_js-bundle1.js` (www. and bare in E; ssl. in C); path `/recaptcha/releases/` is not a hit | E,C |
| `cdn.shopify.com` | AngularJS / script injection | user asset path serves angular-animate.min.js | E,C |
| `www.google.com`, `google.com` | JSONP | `/tools/feedback/escalation-options` | E,C |
| `www.google.com/recaptcha/` (dir path) | AngularJS gadget | `/recaptcha/about/js/main.min.js`; exact `.../recaptcha/api.js` does not cover it | H |
| `accounts.google.com` | JSONP | `/o/oauth2/revoke?callback=` | E,H,C |
| `apis.google.com` | JSONP + onload callback | | C |
| `*.googleapis.com` | JSONP | translate., maps., mts0/mts1/mt1., cbks0., www.googleapis.com endpoints in E | E |
| `translate.`/`maps.`/`clients1.`/`cse.`/`books.google.com` | JSONP | `/translate_a/l`, `/maps/vt`, `/complete/search`, `/books` | E |
| `*.blogspot.com`, `www.blogger.com` | JSONP | Blogger `/feeds/...` endpoints | E |
| `api.github.com`, `gist.github.com` | JSONP | | C |
| `*.github.io` | user-hosted AngularJS | E has two `*.github.io` angular files; any account can publish (inf) | E |
| `*.cloudfront.net` | JSONP + user-hosted | E: `d1f69o4buvlrj5.cloudfront.net/.../optout_check`; H: exfil+exec; C: angular gadget | E,H,C |
| `*.amazonaws.com` | user-hosted | E angular: `*.s3.amazonaws.com`, `s3-eu-west-1.amazonaws.com`; H: exfil+exec | E,H |
| `*.appspot.com` | user-hosted AngularJS | E angular: `prb-resume.appspot.com`; anyone can deploy there (inf) | E |
| `*.herokuapp.com` | user-hosted | E angular: `eternal-sunset.herokuapp.com`; H | E,H |
| `*.azurewebsites.net`, `*.azurestaticapps.net`, `*.firebaseapp.com` | user-hosted code | H: exfil+exec | H |
| `*.blob.core.windows.net` | user-hosted AngularJS | E angular: `inno.blob.core.windows.net` | E |
| `polyfill-fastly.io`, `jquery.com`, `wordpress.org`, `recaptcha.net`, `www.recaptcha.net` | JSONP / onload callback | | C |
| eval-gated: `googletagmanager.com`, `www.googletagmanager.com`, `google-analytics.com`, `www.google-analytics.com`, `ssl.google-analytics.com`, `www.googleadservices.com` | JSONP needing eval | hit ONLY if the same directive has `'unsafe-eval'` [E NEEDS_EVAL]; C lists GTM without that condition, follow E (else `*.googletagmanager.com` false-positives) | E |
- ~100 more single-purpose JSONP hostnames sit in E jsonp.ts (syndication.twitter.com, graph.facebook.com, api.vk.com, mc.yandex.ru, vimeo.com ...). Copy from that file verbatim if wanted; add none from memory.
- E's list dates from 2016 and some endpoints are dead (inf): word it "is known to host ... (CSP Evaluator list)", severity warn, never fail.

## B. style-src, fallback, unsafe-inline
- Fallback [W 6.8.3, M]: script-src-elem / script-src-attr -> script-src -> default-src; style-src-elem / style-src-attr -> style-src -> default-src; object-src, connect-, img-, font-, media-, manifest-src -> default-src; worker-src -> child-src -> script-src -> default-src; frame-src -> child-src -> default-src.
- NO default-src fallback [M]: base-uri, form-action, frame-ancestors, report-to, report-uri, sandbox, require-trusted-types-for, trusted-types, upgrade-insecure-requests. (`default-src 'none'` still lets anyone frame the page [M frame-ancestors].)
- Inline checks use the element/attr variants [W 6.8.2]: `<script>` -> script-src-elem, `on*=` -> script-src-attr, `<style>` -> style-src-elem, `style=""` -> style-src-attr.
- `'unsafe-inline'` allows all inline only when the same source list has NO nonce-source and NO hash-source [W 6.7.3.2, M]; with `'strict-dynamic'` it is also ignored, for script types only [W 8.2 scope; MDN page for style-src does not mention it] (inf: strict-dynamic never neutralises style).
- Nonce cannot tag a `style=""` attribute: with a nonce/hash in style-src, style attributes are blocked unless `'unsafe-hashes'`+hash or a separate `style-src-attr 'unsafe-inline'` (inf from W 6.7.3.2 + M style-src-attr).
- [E] never inspects style-src at all (unsafe-inline check covers script-src, script-src-attr, script-src-elem only). Flagging style is our superset; risk is CSS injection: attribute selectors and @font-face unicode-range exfiltrate data via url() [S], lower than script injection (inf).
- Proposal: `style-src-elem` effective `'unsafe-inline'` (no nonce/hash) = warn; only `style-src-attr` effective `'unsafe-inline'` = info (cannot run script).
- Script side: effective `'unsafe-inline'` in script-src-elem OR script-src-attr = high [E checkScriptUnsafeInline]; `'unsafe-eval'` and `'unsafe-hashes'` = medium-maybe, evaluated on the raw policy so strict-dynamic does not hide them [E].

## C. Missing directives, trusted types, reporting
- object-src [E checkMissingObjectSrcDirective]: fine if object-src present, else fine if default-src present with >=1 value; finding only when both absent. So `default-src 'self'` passes in [E]; [G]/[O] still recommend `object-src 'none'`. Our csp-object-src warns on `default-src 'self'`: stricter than [E], keep or relax = SPEC decision.
- base-uri [E checkMultipleMissingBaseUriDirective]: required only when the policy has script nonces, or script hashes together with strict-dynamic (base tag can redirect relative nonce/hash-protected loads). [G]/[O] recommend `base-uri 'none'` for every strict policy. A host-allowlist policy passes [E]; our csp-base-uri warns always (superset).
- script-src missing and no default-src = high [E checkMissingScriptSrcDirective].
- frame-ancestors: no [E] check; [M] supports only via header (not `<meta>`), no default-src fallback; [O]: X-Frame-Options is ignored by browsers when frame-ancestors is present. XFO-only stays a valid protection for hdr-frame-protection.
- form-action: no [E] check; no default-src fallback [M, O]; restricts form submit targets (phishing via injected forms) [O]. Any new check: warn only if the page has a `<form>` (inf).
- trusted types: `require-trusted-types-for 'script'` missing = INFO only [E checkRequiresTrustedTypesForScripts]; `trusted-types` without `require-trusted-types-for` does nothing [M]; valid values: `'none'`, `'allow-duplicates'`, policy names, `*` [M, E checkInvalidKeyword]. MDN marks Trusted Types Baseline since Feb 2026 [M]. Never above info.
- reporting [E checkHasConfiguredReporting]: report-uri present ok; only report-to = INFO (limited support); neither = INFO. [M]: report-uri deprecated, ignored where report-to is supported, use both during transition; report-to holds an endpoint NAME defined in `Reporting-Endpoints` or a group of the legacy `Report-To` header; neither works in `<meta>`.
- Deprecated directives = INFO [E checkDeprecatedDirective]: reflected-xss, referrer, disown-opener, prefetch-src. Unknown directive / missing semicolon / unquoted keyword (`unsafe-inline`, `nonce-...` without quotes) = syntax findings [E parser_checks]. Nonce of 8 or fewer base64 chars is flagged [E checkNonceLength].

## D. Edge cases that cause false positives
1. Bypass list must not touch style-src/font-src: the reference fixture has `cdnjs.cloudflare.com` in style-src and font-src (harmless there).
2. Fixture script-src `www.google.com/recaptcha/api.js` (exact file) and `www.gstatic.com/recaptcha/releases/` (dir, no gadget in E) = NOT hits; `*.googletagmanager.com` = not a hit without `'unsafe-eval'`. Expected result for the fixture: no bypass finding.
3. `'strict-dynamic'`: host sources, `'self'`, `'unsafe-inline'` and bare `https:`/`http:` are ignored by CSP3 browsers [M, W 8.2, G]; [E checkAllowlistFallback] and [G] even RECOMMEND adding `https: http:` and `'unsafe-inline'` as legacy fallback. Current csp-wildcard fails `'nonce-x' 'strict-dynamic' https:`: false positive, skip `https:`/`http:` when strict-dynamic is present (`*` too). `'strict-dynamic'` without nonce/hash blocks all scripts = INFO [E].
4. `'unsafe-inline'` beside a nonce/hash is a recommended fallback [E checkUnsafeInlineFallback] and is ignored by browsers [M] -> never flag (current hasEffectiveUnsafeInline is right).
5. Wildcard/scheme rules apply only to script-src, script-src-attr, script-src-elem, object-src, base-uri [E DIRECTIVES_CAUSING_XSS]; `data:` `http:` `https:` and bare `*` in img-src/connect-src/font-src are not XSS findings; `*.example.com` is not `*`.
6. Current code reads only script-src||default-src: it misses `script-src-elem`/`script-src-attr` overrides. Judge elem = script-src-elem||script-src||default-src, attr = script-src-attr||script-src||default-src.
7. Several CSP headers (or comma-joined): all are enforced, a resource must pass every policy, strictest wins [M]. Current code evaluates only the first `split(',')[0]`: a directive missing there but present in policy 2 is a false warn, and unsafe-inline in policy 2 is masked. Proposal: a directive counts as present if ANY enforced policy has it; a weakness is real only if EVERY policy has it.
8. `<meta>` CSP: frame-ancestors, sandbox, report-uri, report-to and Report-Only are ignored there [W, M]; do not credit them (current frame-ancestors handling is right; apply same to reporting).
9. Report-only policy is never evaluated for weaknesses; it only feeds csp-report-only (SPEC 6.3) [M: both headers honoured, only the enforced one blocks].
10. Parsing: names and keywords are case-insensitive, first duplicate directive wins [W] (parseCsp ok); unquoted `unsafe-inline` is a host name, not the keyword.
11. `'self'` in script-src is medium-maybe in [E] ("problematic if you host JSONP, AngularJS or user uploads"): never fail.
12. `report-to default` with only the legacy `Report-To` header (fixture) is valid; do not demand `Reporting-Endpoints`.
13. csp-unsafe-eval: with strict-dynamic still counts [E raw policy]. Flash `object-src` bypass list [E flash.ts: vk.com/swf/video.swf, ajax.googleapis.com yui charts.swf] is obsolete, skip.
