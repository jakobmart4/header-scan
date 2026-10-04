# Parity research: header-scan vs SecurityHeaders.com

Date 2026-09-30. Fixture: `test/fixtures/securityheaders-com.json` (real headers of securityheaders.com, grade A+ there).

## Method (reproducible)

- Built `ctx` with `fakeCtx()` from `test/fixture-server.js` (url `https://securityheaders.com/`, body = empty HTML page). `set-cookie` wrapped in an array exactly as `lib/scan.js` does.
- `ctx.fetch` stub returns the fixture headers for the compression refetch and both CORS probes (server does not reflect Origin, no `ACAC`).
- Ran `headers.js`, `cookies.js`, `csp.js` (40 findings) and `score()`. Existing suite: 277 pass, 0 fail, 2 skipped.
- SecurityHeaders.com itself answered 403 to WebFetch. Report layout was verified on a saved copy of a real report (webscore.eea.europa.eu, securityheaders-results). The "Warnings" section is NOT in that sample; its content below is from memory (unverified).

Report layout (verified): Summary (grade + tick badges for HSTS, XFO, CSP, XCTO, Referrer-Policy, Permissions-Policy) -> Missing Headers -> Raw Headers -> Upcoming Headers (COEP, COOP, CORP) -> Additional Information (one blurb per header actually sent).

## Our result on the fixture

40 findings: 26 pass, 8 warn, 1 fail, 5 info. Security grade **C** (score 85; capped from B by `cookie-secure` fail, severity 4). `categories.headers` = 91 (20 pass / 5 warn / 4 info), `categories.cookies` = 58. So we grade the A+ site lower than SecurityHeaders does, because of things it does not test (cookie flags, CSP gaps, X-Powered-By). That is intended.

## Parity table

| SecurityHeaders item | Our check id(s) | Our status on fixture | Gap? |
|---|---|---|---|
| Badge: Strict-Transport-Security | hdr-hsts, hdr-hsts-subdomains, hdr-hsts-preload | pass, pass, pass | no |
| Badge: Content-Security-Policy | csp-present | pass | no |
| Badge: X-Frame-Options (SAMEORIGIN) | hdr-frame-protection | pass | no |
| Badge: X-Content-Type-Options | hdr-xcto | pass | no |
| Badge: Referrer-Policy | hdr-referrer-policy | pass | no |
| Badge: Permissions-Policy | hdr-permissions-policy | pass (presence only, same as SH) | no |
| Upcoming: Cross-Origin-Opener-Policy | hdr-coop | info "header absent" | **YES (1)** site sends `-report-only` |
| Upcoming: Cross-Origin-Embedder-Policy | hdr-coep | info "header absent" | **YES (1)** site sends `-report-only` |
| Upcoming: Cross-Origin-Resource-Policy | hdr-corp | info "header absent" | no (CORP has no report-only variant; absent is correct) |
| Info: Server `cloudflare` | hdr-server-leak | pass (only versions are flagged) | no (SH lists it, we stay quiet unless versioned) |
| Info: X-Powered-By `PHP/8.5.9` | hdr-powered-by | warn | no (we are stricter) |
| Info: Access-Control-Allow-Origin `*` | cors-wildcard-credentials, cors-reflected-origin, cors-null-origin | pass, pass, pass (evidence just `ACAO: *`) | **YES (5)** no finding says what `*` means |
| Info: CSP directive breakdown | csp-unsafe-inline / -eval / -wildcard / -data-uri / -default-src | pass x5 (script-src has a sha256 hash, no `*`) | see CSP rows |
| Info: HSTS, Referrer-Policy, XFO, XCTO, Permissions-Policy blurbs | (same ids as badges) | pass | no |
| Info: X-XSS-Protection `1; mode=block; report=https://x` | none | not evaluated | **YES (4)** should be `0`/absent; value also carries a `report=` URL |
| Info: Expect-CT `max-age=0` | none | not evaluated | **YES (4)** deprecated; `max-age=0` is the harmless opt-out |
| Info: Report-To (JSON, group `default`) | none | not evaluated | **YES (5)** info: reporting configured |
| Info: NEL (JSON) | none | not evaluated | **YES (5)** info: network error logging on |
| Info: `-report-only` COEP/COOP | hdr-coep / hdr-coop | see rows above | **YES (1)** |
| Raw Headers table | none (result has no headers) | n/a | **YES (6)** |

## CSP detail on the fixture (where we already see more than SecurityHeaders)

| Observation | Our id | Status | Gap? |
|---|---|---|---|
| no `object-src` (default-src is `'self'`, not `'none'`) | csp-object-src | warn | no (superset) |
| no `base-uri` | csp-base-uri | warn | no (superset) |
| no `frame-ancestors` (XFO covers clickjacking) | csp-frame-ancestors | warn | no (superset) |
| `upgrade-insecure-requests` absent | csp-upgrade-insecure | info | no |
| `style-src 'self' 'unsafe-inline' ...`, no nonce/hash | none: `hasEffectiveUnsafeInline` is only called with script-src | not flagged | **YES (2)** |
| script-src hosts: js.stripe.com, static.cloudflareinsights.com, www.google.com/recaptcha/api.js, www.gstatic.com/recaptcha/releases/, *.googletagmanager.com, j.6sc.co | none | not evaluated | **YES (3)** allowlist-bypass check missing |
| `report-uri` + `report-to default` inside CSP | none | not evaluated | **YES (5)** reporting presence not reported |
| `form-action 'self'`, `frame-src`, `connect-src` | none | not evaluated | no (SecurityHeaders does not test them either; `form-action` missing is a Google CSP Evaluator item, decide in PARITY-SPEC) |

Edge cases the bypass check must get right on THIS fixture (false-positive traps):
- `www.google.com/recaptcha/api.js` and `www.gstatic.com/recaptcha/releases/` are path-restricted. A host-only pattern (`www.google.com`) must not match them unless the path also matches (CSP host-source path semantics).
- `cdnjs.cloudflare.com` appears here only in `style-src` / `font-src`, never in script-src. The bypass check must look at script-src (falling back to default-src) only, otherwise it flags a source that cannot run script.
- `*.googletagmanager.com` is a wildcard host; whether it is a listed bypass is a research-csp.md question (not verified here).

## Cookies (SecurityHeaders does not test these; all supersets, no parity gap)

`anti_forgery_cookie=<32 hex>; expires=...; Max-Age=7200; path=/` -> `cookie-secure` **fail**, `cookie-httponly` warn (name is not session-like, so warn not fail), `cookie-samesite` warn, `cookie-cache-control` warn (Cache-Control `public, max-age=60`), others pass/info. Evidence lists the cookie NAME only, never the value (checked in run output).

Observation for the spec: `hdr-cache-control-html` (warn) and `cookie-cache-control` (warn) fire on the same cause (Set-Cookie + public cache) and both count. Existing behaviour; keep stable, only be aware it double-counts.

## Further SecurityHeaders report items we lack (beyond the numbered gaps)

1. **Raw Headers table**: `Result` has no headers field (confirms gap 6). Set-Cookie value in the fixture (`3ca96790...`) must be redacted, `expires`/`Max-Age`/`path` kept.
2. **Public-Key-Pins** (HPKP) and **Feature-Policy**: no id owns them (gap 4). Sending only Feature-Policy today yields `hdr-permissions-policy` warn "header missing" with no hint that Feature-Policy is obsolete. Not exercised by the fixture.
3. **Summary block "IP address"**: SecurityHeaders shows the resolved IP; we expose only `url`, `host`, `scannedAt`. Skip (no need, and resolved IPs of a target are not something the API should publish by default).
4. **Per-header tick badges**: derivable from finding ids by the UI; nothing to build backend-side.
5. **"Warnings" section** (unverified sample): our per-check `warn`/`fail` with `fix` text covers it; HTTP-only sites are covered by `hdr-hsts` fail + `tls-http-redirect`.
6. **Headers-only grade**: SecurityHeaders grades headers alone (A+..F). We have only `categories.headers.score` (91 on the fixture), no per-category letter. UI can show the score; adding a letter is optional, not needed for superset.
7. **Missing Headers blurbs / CSP directive-by-directive explanation**: our `fix` text serves the first; the second is presentation (UI can parse `rawHeaders`). No backend work.

## Summary of confirmed gaps (mapped to the six known ones)

| # | Gap | Evidence in this run |
|---|---|---|
| 1 | COOP/COEP report-only reported as "absent" | hdr-coop / hdr-coep `info`, `header absent` while both `-report-only` headers exist |
| 2 | style-src `'unsafe-inline'` unflagged | fixture has it, no check reads style-src |
| 3 | script-src bypass hosts | no check inspects hosts; see false-positive traps above |
| 4 | deprecated headers silent | X-XSS-Protection `1; mode=block`, Expect-CT `max-age=0` present, zero findings |
| 5 | ACAO `*`, report-to, NEL, CSP report-uri | ACAO `pass` with bare `ACAO: *`; Report-To/NEL/report-uri produce nothing |
| 6 | raw headers in JSON | absent from `Result` |

No additional parity gap was found beyond these six plus Public-Key-Pins/Feature-Policy (folded into 4).
