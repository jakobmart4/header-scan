# PARITY-SPEC: superset of SecurityHeaders.com (contract for 4 parallel builders A/B/C/D)

Adds 6 check IDs, changes 3 (`hdr-coop`, `hdr-coep`, `hdr-corp`), extends 1 (evidence only) and adds `result.rawHeaders`. Everything else in SPEC.md stays as is (IDs, severities, cookie rules, scoring formula). Rules of SPEC.md apply: dependency-free, passive only, one Finding per ID always, no secrets/cookie values/URL paths in evidence, `finding()` from `lib/score.js`. Inputs: `docs/research-{csp,headers,parity}.md`. Where the research docs disagree this file decides (marked "decision").

## 1. Ownership (disjoint files, no builder edits another's files)
| Builder | Files |
|---|---|
| A | `lib/checks/csp.js`, `lib/data/csp-bypass-hosts.js` (new dir `lib/data/`) |
| B | `lib/checks/headers.js` (`cookies.js` is NOT touched: no cookie change is needed) |
| C | `lib/scan.js`; `lib/score.js` is expected to stay unchanged (see 5) |
| D | `test/parity-securityheaders.test.js`, `test/parity-new-checks.test.js`, `SPEC.md`, `README.md` (count line + rawHeaders line only), the 3 numeric assertions in `test/scan.test.js` |

Not touched by anyone here: `ui/`, `public/`, `scripts/build-ui.mjs`, `server.js`, `functions/`, `lib/checks/{cookies,dns,html,site,probes,tls}.js`, `lib/{ssrf,verify}.js`. `server.js` serialises the scan result unchanged, so `rawHeaders` reaches `/api/scan` with no server edit.
Checklist mapping: none of the new IDs carries `checklist` (the 40-item list has no header items; its item 1 "securityheaders.com" is what this work implements). Omit the field.

## 2. New and changed IDs
Category is `headers` for all. `sev` = weight when W/F; P/I/S carry the same number. Status letters: P pass, W warn, I info, S skipped. Every rule below is the complete rule.

### 2.1 csp.js (owner A). Append to `IDS` after `csp-upgrade-insecure`: `csp-style-unsafe-inline`, `csp-script-bypass-hosts`
The policies evaluated: every comma-separated element of the enforced header (empty ones skipped), else the meta policy (round 2, section 10). No existing csp-* rule changes.
Helper (internal): `eff(csp, ...names)` = source list of the first directive in `names` that is PRESENT in the policy (present-but-empty counts), else `[]`. Tokens are compared lowercase.

| id | sev | rule | fix text guidance |
|---|---|---|---|
| `csp-style-unsafe-inline` | 2 | Directive list = `eff(csp,'style-src-elem','style-src','default-src')`, with `'strict-dynamic'` removed from the list (it never neutralises styles), then the existing `hasEffectiveUnsafeInline(list)`. W if true (evidence `<directive> allows 'unsafe-inline' without nonce/hash`, naming the directive actually used); P otherwise (also when no style-src/default-src at all: that is `csp-default-src`'s job); S "no CSP". `style-src-attr` is only evaluated as in section 10 (I when it is absent and `style-src`/`default-src` still allows inline attributes). | "Put a nonce or hash on <style> elements and move style attributes into classes instead of allowing 'unsafe-inline'." |
| `csp-script-bypass-hosts` | 3 | List = `eff(csp,'script-src-elem','script-src','default-src')`. If it contains `'strict-dynamic'` -> P, evidence "host allowlist ignored (strict-dynamic)" (decision: ignored whenever `'strict-dynamic'` is present, not only with nonce/hash: without them nothing loads anyway). Else `hits = bypassHits(list)` (section 3): any hit with `level:'host'` -> W; else any hit with `level:'path'` -> I; else P. Evidence: first 5 hits as `<source> (<reason>)` joined by `; `, plus `+N more`. Finding `ref` = `ref` of the first hit. S "no CSP". Only the script directive chain is judged: `cdnjs.cloudflare.com` in style-src/font-src must never hit. | "Replace host allowlists with nonces plus 'strict-dynamic', or self-host the script; allowlisted hosts that serve JSONP/AngularJS/user content defeat the policy." |

Also export (for tests): `export function bypassHits(sources)` (section 3).
Out of scope (decision, do not build): `script-src-elem` fallback for the OLD checks (`csp-unsafe-inline`, `csp-wildcard` keep `script-src||default-src`), `csp-wildcard` strict-dynamic false positive, form-action, trusted-types, CSP-syntax linting.

### 2.2 headers.js (owner B). Append to `IDS`: `hdr-xss-protection`, `hdr-legacy-headers`, `cors-wildcard-public`, `hdr-reporting`
All read `page.headers` (lowercase keys). The early `!page.status` skip branch already covers new IDs via `IDS.map`.

| id | sev | rule | fix text guidance |
|---|---|---|---|
| `hdr-xss-protection` | 2 | P header absent, or first token (text before `;`, trimmed) is `0`; W any other value (`1`, `1; mode=block`, `...; report=`). Evidence `X-XSS-Protection: <first token>` only (never the rest: it can hold a report URL). | "Remove X-XSS-Protection or send X-XSS-Protection: 0; the legacy filter can introduce XSS. Rely on CSP." |
| `hdr-legacy-headers` | 1 | LEGACY = `expect-ct`, `public-key-pins`, `public-key-pins-report-only`, `feature-policy`, `x-download-options`, `p3p`. W iff `x-permitted-cross-domain-policies` first token is `all`; else I iff any LEGACY header present (evidence lists present names, lowercase); else P ("none present"). If W, evidence also lists present LEGACY names. Values are never echoed (Expect-CT `max-age=0` is just listed). Other X-Permitted-Cross-Domain-Policies values and absence are not reported. | "Remove obsolete headers (Expect-CT, Public-Key-Pins, Feature-Policy, X-Download-Options, P3P); send X-Permitted-Cross-Domain-Policies: none or omit it." |
| `cors-wildcard-public` | 2 | `wild` = `page.headers['access-control-allow-origin']==='*'` OR the evil-origin CORS probe's `acao==='*'` (reuse the existing probe result; a probe error just drops that half). Not `wild` -> P (evidence `no ACAO` or `ACAO: <value>`; an echoed origin is `cors-reflected-origin`'s job). `wild` and personalised (page has any Set-Cookie, OR `vary` contains `cookie` or `authorization`, OR `cache-control` contains `private`) -> W; `wild` otherwise -> I ("public wildcard, fine for public assets/CDN"). Overlap with `cors-wildcard-credentials` F is accepted (no special case). | "Allowlist the origins that need cross-origin reads and add Vary: Origin; keep ACAO: * for public static files only." |
| `hdr-reporting` | 1 | ALWAYS `info` (never counted). Channels found: `Report-To` (header `report-to`), `Reporting-Endpoints`, `NEL`, `CSP report-uri`, `CSP report-to` (directive present in the enforced OR report-only CSP HEADER, regex `(^\|;)\s*report-uri\s` / `report-to\s`; meta CSP ignored). Evidence `channels: <comma list>; endpoint hosts: <up to 3>`; hosts come from `/https?:\/\/([a-z0-9.-]+)/gi` over `report-to`, `reporting-endpoints` and the `report-uri` value, deduplicated, host only (NEVER paths/query: they can carry tokens). None found -> evidence "no reporting configured (optional)", fix "Optional: add Reporting-Endpoints and CSP report-to to receive violation reports."; found -> fix ''. | (see rule) |

Extended evidence only (no status change): `hdr-permissions-policy` W case appends "; Feature-Policy is deprecated (different syntax)" when `feature-policy` is present and `permissions-policy` is absent.

### 2.3 Changed: hdr-coop / hdr-coep / hdr-corp (owner B; sev stays 1; never W/F)
`tok(h)` = first token before `;`, trimmed, lowercased. `enforced` = `h['cross-origin-…-policy']`, `ro` = `h['cross-origin-…-policy-report-only']` (COOP and COEP only; CORP has no report-only variant, do not invent one).

| id | P when | else |
|---|---|---|
| `hdr-coop` | `tok(enforced)` in {`same-origin`, `same-origin-allow-popups`, `noopener-allow-popups`} | I |
| `hdr-coep` | `tok(enforced)` in {`require-corp`, `credentialless`} | I |
| `hdr-corp` | `tok(enforced)` in {`same-site`, `same-origin`, `cross-origin`} | I |

I evidence, first match wins: (1) COOP/COEP and `ro` present -> `report-only, not enforced: <ro value>` (also when `enforced` is `unsafe-none` or unrecognised); (2) `enforced` present -> `<hdr>: <value> (not an enforcing value)`; (3) absent -> `header absent (optional hardening)`. Enforced wins over report-only (enforced valid + ro present -> P, evidence is the enforced value). Fix text (I only): COOP "Watch the report-only reports, then send Cross-Origin-Opener-Policy: same-origin (same-origin-allow-popups if you use OAuth/payment popups)."; COEP "Send Cross-Origin-Embedder-Policy: require-corp once third-party embeds send CORP/CORS (credentialless is easier)."; CORP "Send Cross-Origin-Resource-Policy: same-site (cross-origin only for assets meant to be embedded)." Existing tests keep passing (they use `same-origin`/`require-corp`).

Deprecated/harmful summary: X-XSS-Protection is judged by `hdr-xss-protection` (P `0`/absent, W else); Expect-CT, Public-Key-Pins(-Report-Only), Feature-Policy, X-Download-Options, P3P are only listed (I) by `hdr-legacy-headers`; X-Permitted-Cross-Domain-Policies `all` is W there. Nothing else is judged. Not adopted (decision): extending the `Server`/`X-Powered-By` lists, `Via`, Clear-Site-Data, Timing-Allow-Origin, X-DNS-Prefetch-Control, infra headers (`cf-ray`, `x-envoy-*`): they appear in `rawHeaders` only.

## 3. lib/data/csp-bypass-hosts.js (owner A)
```js
export const BYPASS_HOSTS = [ { pattern, reason, ref }, ... ];   // pattern: lowercase "host" or "host/gadget-path"; "*.domain" allowed as host; ref: https URL
```
Constants for `ref` (one of these three strings): E = `https://github.com/google/csp-evaluator/tree/master/allowlist_bypasses`, C = `https://github.com/renniepak/CSPBypass`, H = `https://github.com/HackTricks-wiki/hacktricks/blob/master/src/pentesting-web/content-security-policy-csp-bypass/README.md`. `reason` is <= 80 chars. This is the COMPLETE seed list (28 entries since round 2) (only entries sourced in research-csp.md A; add none from memory; tests rely on it). Eval-gated hosts (`*.googletagmanager.com`, google-analytics) are deliberately omitted: they only bypass with `'unsafe-eval'`, which `csp-unsafe-eval` already reports, and the fixture must have no hit.

| pattern | reason | ref |
|---|---|---|
| `cdnjs.cloudflare.com` | hosts AngularJS 1.x and prototype-pollution libraries | E |
| `cdn.jsdelivr.net` | serves any npm/GitHub file incl. AngularJS | E |
| `unpkg.com` | serves any npm package incl. AngularJS | C |
| `ajax.googleapis.com` | hosts AngularJS 1.x and JSONP endpoints | E |
| `code.angularjs.org` | official AngularJS 1.x host | C |
| `cdn.shopify.com` | serves AngularJS builds and user-supplied assets | E |
| `www.gstatic.com/fsn/angular_js-bundle1.js` | AngularJS bundle (sandbox-escape gadget) | E |
| `www.google.com/tools/feedback/escalation-options` | JSONP callback endpoint | E |
| `www.google.com/recaptcha/about/js/main.min.js` | AngularJS gadget under /recaptcha/ | H |
| `accounts.google.com/o/oauth2/revoke` | JSONP callback endpoint | E |
| `apis.google.com` | JSONP endpoints | C |
| `*.googleapis.com` | JSONP endpoints (translate., maps., mts*.) | E |
| `maps.googleapis.com` | JSONP callback endpoints (Maps API) | E |
| `translate.googleapis.com` | JSONP callback endpoints (Translate) | E |
| `mts0.googleapis.com` | JSONP callback endpoints (map tiles) | E |
| `mts1.googleapis.com` | JSONP callback endpoints (map tiles) | E |
| `*.blogspot.com` | Blogger JSONP feeds | E |
| `www.blogger.com` | Blogger JSONP feeds | E |
| `api.github.com` | JSONP endpoints | C |
| `*.github.io` | anyone can publish scripts (AngularJS copies exist) | E |
| `*.cloudfront.net` | JSONP and attacker-hostable scripts | E |
| `*.amazonaws.com` | attacker-hostable scripts (S3) | E |
| `*.appspot.com` | attacker-hostable scripts | E |
| `*.herokuapp.com` | attacker-hostable scripts | E |
| `*.azurewebsites.net` | attacker-hostable scripts | H |
| `*.azurestaticapps.net` | attacker-hostable scripts | H |
| `*.firebaseapp.com` | attacker-hostable scripts | H |
| `*.blob.core.windows.net` | attacker-hostable AngularJS | E |

### 3.1 `bypassHits(sources: string[]) -> [{source, level:'host'|'path', pattern, reason, ref}]` (owner A, exported from csp.js)
One result per source token, in source order; a token matching several entries yields the best level (`host` beats `path`), ties -> first entry in list order.
1. Skip tokens: starting with `'` (keywords, nonces, hashes), ending with `:` (bare scheme), exactly `*` (that is `csp-wildcard`'s job), and tokens without a `.`.
2. Normalise a source: lowercase; strip `^[a-z][a-z0-9+.-]*://`; cut at first `/` into `host` and `path`; drop `?...`/`#...` from path; strip `:port` (`:443`, `:*`) from host. `whole` = path is empty or `/`. No percent-decoding (ponytail: ceiling, add if needed).
3. Host match, with `S`/`E` = source/entry host without a leading `*.`, `sW`/`eW` = has leading `*.`:
   - source exact, entry exact: `s === e`.
   - source exact, entry wildcard: NO match (a concrete host under a shared domain is that tenant's own site).
   - source wildcard: entry exact -> `E.endsWith('.'+S)`; entry wildcard -> `E === S || E.endsWith('.'+S)`.
4. Path/level, entry `gp` = the part of `pattern` from the first `/` (or none):
   - source `whole` -> `host` (whole untrusted host or the gadget itself is loadable).
   - source has a path and entry has `gp` -> `host` only if the source path covers `gp` (`sp` ending in `/`: `gp.startsWith(sp)`; else `sp === gp`), otherwise NO match.
   - source has a path and entry has no `gp` -> `path` (still risky via open redirects: CSP ignores the path after a redirect, so info only).
5. Expected: `www.google.com/recaptcha/api.js` and `www.gstatic.com/recaptcha/releases/` -> no hit; `www.google.com` -> host (gadget entry, whole host); `www.google.com/recaptcha/` -> `host` (covers the `/recaptcha/about/js/main.min.js` entry); `cdn.jsdelivr.net/npm/x@1/a.js` -> `path`; `*.cloudfront.net` -> host; `d111.cloudfront.net` -> none; `*.googleapis.com` -> host (via `ajax.googleapis.com`, first in list order among entries that match, since it precedes `*.googleapis.com`).

## 4. Fixture reference (`test/fixtures/securityheaders-com.json`, run with ctx of 6)
Statuses expected from headers.js + cookies.js + csp.js (all ids not listed are `pass`):
- fail: `cookie-secure`.
- warn: `hdr-powered-by`, `hdr-cache-control-html`, `cookie-httponly`, `cookie-samesite`, `cookie-cache-control`, `csp-object-src`, `csp-base-uri`, `csp-frame-ancestors`, `csp-style-unsafe-inline`, `hdr-xss-protection`, `cors-wildcard-public`.
- info: `hdr-coop` (report-only, not enforced), `hdr-coep` (report-only, not enforced), `hdr-corp` (absent), `cookie-prefix`, `csp-upgrade-insecure`, `hdr-legacy-headers` (lists expect-ct), `hdr-reporting` (channels Report-To, NEL, CSP report-uri, CSP report-to; host `scotthelme.report-uri.com`, no path).
- pass includes `csp-script-bypass-hosts` (no hit: recaptcha paths do not cover a gadget, `*.googletagmanager.com` is not listed, `cdnjs` is style-src only), `hdr-server-leak`, `hdr-hsts*`, `hdr-referrer-policy`, `hdr-permissions-policy`.

## 5. Scoring (lib/score.js, owner C: NO code change)
Weight = `finding.severity`; nothing in score.js is keyed by id, so the table below is realised entirely by the `sev` argument of each new finding. `info`/`skipped` stay uncounted, so `hdr-reporting`, COOP/COEP/CORP report-only, `hdr-legacy-headers` I and `cors-wildcard-public` I never move a grade.

| id | weight | counted statuses |
|---|---|---|
| `csp-style-unsafe-inline` | 2 | P, W |
| `csp-script-bypass-hosts` | 3 | P, W (I = path-scoped, uncounted) |
| `hdr-xss-protection` | 2 | P, W |
| `hdr-legacy-headers` | 1 | P, W (I uncounted) |
| `cors-wildcard-public` | 2 | P, W (I uncounted) |
| `hdr-reporting` | 1 | none (always I) |

Existing severities do not change. Effect: +9 counted weight in `headers` for the fixture (3 earned in full, three 2-weight warns earn half), a `csp-script-bypass-hosts` W (sev 3) blocks A+ (max A) by the existing cap; a W on the 2-weight items only costs score. Do not add per-category letters or new caps (YAGNI).
Predicted numbers (computed by re-scoring the current module output with the new findings added by hand, NOT yet produced by builder code; integrator must confirm, and report any difference instead of tweaking the formula):
| input | before | after |
|---|---|---|
| fixture ctx of 6 (headers+cookies+csp findings) | security 85 / C, `categories.headers` 91 (20P 5W 0F 4I) | security **84 / C** (B by score, capped to C by `cookie-secure` F sev 4), `headers` **88** (21P 8W 0F 6I 0S), `cookies` 58 (3P 3W 1F 1I) unchanged |
| `good` fixture via `scan()` (plain http) | security 88 / D, quality 100 / A+, `headers` 93 | security **90 / D** (cap: `tls-https` F sev 5), quality 100 / A+ unchanged, `headers` **94**; fails still exactly `hdr-hsts`, `tls-https` |
| `bad` fixture via `scan()` | security 40 / E, quality 55 / D, `headers` 21 | security **44 / E**, quality 55 / D unchanged, `headers` **31**; new csp ids are S (no CSP), the other new ones P |
The fixture grade (C) is intentionally lower than SecurityHeaders' A+: the extra findings (cookie flags, X-Powered-By, CSP gaps) are real.

## 6. result.rawHeaders (lib/scan.js, owner C)
Field: top-level `result.rawHeaders` (array), placed right after `deep` in the object returned by `scan()`; `[]` when the page fetch failed. Nothing else in the Result changes. Built by an exported pure function `buildRawHeaders(headers)` in `lib/scan.js`, called as `rawHeaders: buildRawHeaders(ctx.page.headers)`. Source is `ctx.page.headers` (already lowercase; order = arrival order, and `set-cookie` keeps its key position, so the order is preserved without extra work).
```js
const RAW_MAX_HEADERS = 80, RAW_MAX_VALUE = 512, RAW_MAX_NAME = 128;   // one constant each, easy to raise
buildRawHeaders(headers) -> [{ name: string, value: string }]          // exactly these 2 fields, nothing else
```
Algorithm (iterate `Object.entries(headers || {})`; never index a plain object by header name):
1. `name = key.toLowerCase().slice(0, RAW_MAX_NAME)`.
2. `set-cookie` and `set-cookie2` (value array or string): ONE entry per cookie line, value = `redactCookie(line)`: split on `;`; first part `pair`; cookie name = text before the first `=` in `pair` (whole `pair` if none), trimmed; result `"<cookiename>=<redacted>"` followed by each remaining attribute (trimmed, original text and casing, joined with `; `) whose attribute name (text before `=`, lowercase) is in {`expires`, `max-age`, `domain`, `path`, `secure`, `httponly`, `samesite`, `partitioned`, `priority`}; every other attribute is dropped. Example from the fixture: `anti_forgery_cookie=<redacted>; expires=Wed, 30 Sep 2026 13:12:15 GMT; Max-Age=7200; path=/`. The cookie value never appears (also not partially, also for values containing `=` or `;`-free junk).
3. Any other header whose NAME matches `/token|secret|csrf|xsrf|api[-_]?key|jwt|passw|session|^(proxy-)?authorization$/i` gets value `<redacted>` (decision: response headers can carry tokens; cheap safeguard; `www-authenticate` is public challenge data and stays). Otherwise `value = Array.isArray(v) ? v.join(', ') : String(v)`.
4. Truncate: if `value.length > RAW_MAX_VALUE` then `value = value.slice(0, RAW_MAX_VALUE - 3) + '...'` (so length is at most 512; the fixture CSP, 713 chars, is cut. Known trade-off: findings evaluate the full header, only the raw view is cut).
5. Stop after `RAW_MAX_HEADERS` entries (each cookie line counts as one).
Also add the two-line comment update at the top of the `scan()` return (SPEC 2.6 mentions the new field). No new I/O, no new dependency.
Fixture expectation: 25 header keys -> 25 entries, `rawHeaders[0].name === 'content-type'`, names all lowercase, `JSON.stringify(result)` contains neither `3ca967900934bcbf8d24e9d95ea5a267` nor `sessionid=abc` (bad fixture) but does contain `Max-Age=7200`.

## 7. Tests (owner D)
Style: `node:test`, `process.env.HEADERSCAN_ALLOW_PRIVATE='1'` first line, `fakeCtx` from `test/fixture-server.js`, `by = fs => Object.fromEntries(fs.map(f=>[f.id,f.status]))`. Keep `node --test "test/*.test.js"` green; every new ID has a P and a non-P test.
1. `test/parity-securityheaders.test.js`: build the ctx of the fixture (url `https://securityheaders.com/`, headers = fixture headers with `set-cookie` wrapped in an array, `content-type` already present, body a minimal HTML page, `fetch` stub returning `{status:200, headers:{...fixture}, body:'', finalUrl, timingMs:1, redirects:[], truncated:false}`); run headers, cookies and csp modules; assert section 4 statuses for EVERY id in the three modules (the unlisted ones `pass`); evidence: coop/coep contain `report-only, not enforced`, reporting contains `scotthelme.report-uri.com` and not `/r/d/csp/enforce`, no finding evidence contains the cookie value; `score([...all])`: security `{score:84, grade:'C'}` and `categories.headers` `{score:88, pass:21, warn:8, fail:0, info:6, skipped:0}`; `buildRawHeaders` as in section 6.
2. `test/parity-new-checks.test.js` matrix (P and non-P each): coop/coep (enforced P; report-only only I; both P; `unsafe-none` I; absent I) and corp (`same-site` P, `bogus` I); `hdr-xss-protection` (absent P, `0` P, `1; mode=block` W); `hdr-legacy-headers` (none P, `expect-ct` I, `x-permitted-cross-domain-policies: all` W, `none` P); `cors-wildcard-public` (no ACAO P, `*` with no cookie I, `*` + set-cookie W, `*` + `vary: Cookie` W, `*` + `cache-control: private` W); `hdr-reporting` (none -> I "no reporting", present -> I with channels/hosts, never a path); `csp-style-unsafe-inline` (`style-src 'self'` P, `style-src 'unsafe-inline'` W, with nonce P, only `default-src 'unsafe-inline'` W, `style-src-elem 'self'` overriding `style-src 'unsafe-inline'` P, no CSP S); `csp-script-bypass-hosts` via `bypassHits` (all expectations of 3.1 item 5) and via `run` (W `script-src cdnjs.cloudflare.com`; W `default-src *.cloudfront.net` fallback; W `script-src-elem ajax.googleapis.com`; I `cdn.jsdelivr.net/npm/x@1/a.js`; P `'self'`; P `'nonce-x' 'strict-dynamic' cdnjs.cloudflare.com`; P `script-src 'self'; style-src cdnjs.cloudflare.com`; S no CSP); data-file shape (non-empty lowercase `pattern`, `reason` <= 80, `ref` starts `https://`, no duplicate patterns, exactly the 28 entries of section 3); `buildRawHeaders` (cookie redaction incl. value with `=`, multiple cookies, attribute whitelist, `__proto__`/`constructor` header names, 10 000 headers -> 80 entries, 1 MiB value -> 512 chars, token-name masking, empty/undefined input -> `[]`); one `scan()` run against the `bad` fixture asserting `result.rawHeaders` exists and has no `abc` cookie value.
3. Existing-file edits by D: `test/scan.test.js` counts `113 -> 119`, `114 -> 120`, `138 -> 144`; test titles say `119 findings`. No other existing test should need changes; if one does, only the intended behaviour change (sections 2.3) may be reflected.
4. `SPEC.md` (D): 6.1 header `- 22` and rules for the 4 new headers ids (one line each, same style) and the changed coop/coep/corp lines; 6.3 `- 16` and 2 new csp lines; section 7 index lists; section 2.6 Result JSON gets `"rawHeaders":[{"name":"...","value":"..."}]`; totals line `22+8+16+11+15+31+16+25 = 144 findings (119 passive, 25 deep)`; add a pointer to `docs/PARITY-SPEC.md`. `README.md` line 5 `138 findings in total: 113 passive` -> `144 ... 119 passive`, plus one line that the result carries `rawHeaders` (cookie values redacted).

## 8. New IDs (6)
`csp-style-unsafe-inline`, `csp-script-bypass-hosts` (csp.js, A); `hdr-xss-protection`, `hdr-legacy-headers`, `cors-wildcard-public`, `hdr-reporting` (headers.js, B). Changed behaviour: `hdr-coop`, `hdr-coep`, `hdr-corp` (B). New result field: `rawHeaders` (C). New export: `bypassHits` (A), `buildRawHeaders` (C), data `BYPASS_HOSTS` (A).

## 9. Known limits (document, do not fix here)
bypass list is a 2016-era subset (Google list + CSPBypass + HackTricks), wording says "known to host", never F; tenant-style hosts (`s3.amazonaws.com`, `storage.googleapis.com`) and eval-gated hosts are not covered; no percent-decoding in path matching; `hdr-cache-control-html` and `cookie-cache-control` still double-count one cause; raw values are cut at 512 chars.

## 10. Round 2 (review fixes; these override the sections above where they differ)
- CSP, several policies: the header is split on `,` (Node joins duplicate headers), empty elements dropped. Each policy yields the 11 policy-level findings; per check the best status (pass > info > warn > fail) among the policies that have a directive deciding that check wins, all policies when none does. So a problem is reported only if every policy has it, and a `frame-ancestors`-only add-on policy cannot vouch for another policy's script rules. `csp-present` evidence names the policy count when > 1. A header with no non-empty policy counts as absent.
- `csp-style-unsafe-inline`: W as before for the `style-src-elem` chain; I when that chain is clean, `style-src-attr` is absent and `style-src`/`default-src` still allows an effective `'unsafe-inline'` (style attributes fall back to `style-src`, not `style-src-elem`).
- `csp-script-bypass-hosts`: path matching is case-sensitive (only the host is lowercased); bare-TLD wildcards (`*.com`, `*.net`) are never hits and count as `csp-wildcard` failures; evidence for `level:'path'` hits says "path-limited, open-redirect risk only" instead of the entry's reason; the four concrete Google API hosts of section 3 are entries (a concrete host under `*.googleapis.com` is Google's own, not a tenant).
- `cors-wildcard-credentials`: `*` + credentials is W (browsers reject it), a reflected origin + credentials stays F; `cors-wildcard-public` evidence mentions the credentials header.
- `hdr-reporting` hosts come from `new URL(token).hostname` (userinfo dropped, IDN as punycode); `hdr-referrer-policy`: `origin` is a known weak value (W, "value: origin").
- `cookies.js`/`rawHeaders`: a cookie line without `=` is a nameless cookie (RFC 6265bis): name `''`, shown as `(unnamed)` in evidence and `=<redacted>` in `rawHeaders`. `redactCookie` keeps `Secure`/`HttpOnly`/`Partitioned` (name only), `SameSite` (strict|lax|none), `Priority` (low|medium|high), `Path` only when `/`, `Max-Age` only when an integer, `Expires` only as an IMF date; `Domain` and any other value show as `<redacted>`. Cookie lines are capped at 20, and when anything is dropped the last of the 80 slots is a `{name:'(truncated)', value:'N more header/cookie line(s) not shown'}` row. Non-cookie values stay verbatim except token-named headers (documented, not changed).
- `mail-mx`: null MX (Node `exchange ''` or `.`) is P "null MX present, no mail expected" and still counts as no MX for SPF/DMARC severity. `dns-ns-count` climbs to parent names like CAA/MX (`ctx.resolve.ns(name)`). `seo-viewport`: W "viewport lacks width=device-width" when the tag exists. `tls-http-redirect`: I "HTTP responds <status>, no redirect, no content served" for any non-redirect, non-200 answer; "no HTTP listener" only for connection errors.
- No severity changed, so the scoring weights are untouched. Tests: `test/review-round2.test.js`.
