# Brief C - OpenAI skills: threat model + deploy hints for header-scan

Source: C:\Skills\Powers\openai-skills\skills (.curated, .system). Distilled for a Node ESM, no-deps scanner + static page.

## 1. Skills read
Fully read:
- .curated\security-best-practices\SKILL.md
- .curated\security-threat-model\SKILL.md (+ references\prompt-template.md, references\security-controls-and-assets.md)
- .curated\security-ownership-map\SKILL.md (git bus-factor tool; needs python+networkx; NOT relevant to a scanner - skip)
- .curated\cloudflare-deploy\SKILL.md (+ references\pages\gotchas.md, pages\configuration.md grep, workers\gotchas.md)
- .curated\netlify-deploy\SKILL.md, .curated\render-deploy\SKILL.md, .curated\vercel-deploy\SKILL.md
Reference sections read:
- security-best-practices\references\golang-general-backend-security.md (GO-SSRF-001, GO-HTTPCLIENT-001, GO-HTTP-001/003/004/005, CORS)
- security-best-practices\references\javascript-express-web-server-security.md (EXPRESS-SSRF-001, rate limit, body limits)
Listed only (by name, other 40 SKILL.md files under .curated/.system are unrelated: figma, notion, imagegen, etc.):
- Not relevant: aspnet-core, chatgpt-apps, cli-creator, define-goal, gh-*, jupyter-notebook, linear, playwright*, screenshot, sentry, speech, transcribe, winui-app, yeet, pdf, openai-docs, plugin-creator, skill-creator, skill-installer, imagegen, migrate-to-codex, hatch-pet.
Note: skills give only generic SSRF guidance ("resolve DNS, enforce IP ranges, with care for DNS rebinding"). Concrete rebinding/pinning design below is my synthesis, not from the skills.

## 2. Rules and patterns to follow

### Process (from security-threat-model)
- Threat model must be repo-grounded: every claim gets an evidence anchor (file + symbol). No invented controls.
- Separate runtime / CI / tests. Separate attacker-controlled input (URL, target headers, HTML, DNS answers, redirects) from operator-controlled (env, config).
- Keep threats few and high quality; rank by likelihood x impact with stated assumptions; state non-capabilities.
- Never output secrets: if a probe finds something like .env, redact; describe presence and location only. Matches our "status + tiny signature" rule.
- Mitigation phrasing pattern: "Rate limit <endpoint> by <key> and apply burst caps." "Enforce schema at <boundary> before <component>."
- Write docs/threat-model.md (name convention `<dir>-threat-model.md`) with a compact Mermaid flowchart (flowchart TD, quoted labels, plain -->, no style/title).

### Scanner as attacker target (threat list, priority)
1. HIGH SSRF: attacker submits URL/host -> server fetches internal/metadata (127.0.0.1, 10/8, 172.16/12, 192.168/16, 169.254.169.254, fd00::/8, ::1, fe80::/10, ::ffff:x mapped v4, 0.0.0.0/8, 100.64/10 CGNAT, 192.0.0.0/24, 198.18/15, 224/4 multicast, 240/4, decimal/octal/hex IP literals).
2. HIGH DNS rebinding / TOCTOU: validate hostname resolves public, then connect re-resolves to private. Fix: resolve once, validate ALL A/AAAA answers, connect to the pinned IP (custom `lookup` or connect by IP with `servername`+`Host` header), re-validate on every redirect hop.
3. HIGH Scanner as proxy / abuse: used to hit third parties (DoS, port scan, vuln recon). Fix: passive-only default, active probes only after DNS TXT ownership proof, per-IP + per-target rate limits, global concurrency cap, fixed port allowlist (80/443 only), fixed path allowlist for probes, static UA with contact URL.
4. MED Ownership-proof bypass: token guessable/reused/cached across domains. Fix: 128-bit random token bound to (domain, requester session), TTL, TXT looked up at `_header-scan.<domain>`, check via own resolver at scan time, re-check before each active batch, never trust user-supplied "verified" flag.
5. MED Resource exhaustion: huge bodies, slow-loris responses, endless redirects, compression bombs, giant header sets. Fix: below.
6. MED Response reflection / stored XSS in our own report page: target headers/HTML echoed into the UI. Fix: render via textContent only, ship strict CSP on our page, escape everything, JSON responses with `nosniff`.
7. MED Secret exposure: probing /.env or /.git/config then displaying content. Fix: read first N bytes, match tiny signature (e.g. `^\[core\]`, `=` key pattern), report status+signature name only, discard body, never log it.
8. LOW Info leaks in our own errors (stack traces, resolved internal IPs in messages). Return generic "blocked target" without revealing why-IP.
9. LOW Scan-result cache poisoning / cross-user leakage if results are cached by URL.

### Outbound HTTP hardening (GO-SSRF-001 + GO-HTTPCLIENT-001 adapted to node)
- Scheme allowlist http/https only; reject userinfo (`user:pw@host`), reject non-80/443 ports (or explicit allowlist), normalize with `new URL()`, reject IDN oddities via punycode conversion, lowercase, strip trailing dot.
- Timeouts: connect, total (e.g. 10s per request, 45s per scan), AbortSignal on everything.
- Redirects: manual, max 5, re-run full SSRF validation per hop, scheme downgrade https->http recorded as a finding, never forward cookies.
- Body cap: stream and abort at e.g. 1 MB (HTML) / 64 KB (probes); do not `await res.text()` unbounded. Header count/size cap.
- Always consume/destroy response bodies (leaked sockets).
- Accept-Encoding: identity (or cap decompressed size) to defeat zip bombs.
- Do not disable TLS verification for normal fetch. For the TLS check use a separate socket with `rejectUnauthorized:false` ONLY to inspect the cert, never to fetch content.
- Node `fetch` (undici) cannot easily pin IP: use `node:https`/`node:http` with custom `lookup`, or undici `Agent({connect:{lookup}})`. `node:dns` `resolve4/resolve6` + own validate; do not use `dns.lookup` result from a separate call.
- Server side (our own HTTP server, GO-HTTP-001 analogue): set `headersTimeout`, `requestTimeout`, `maxHeadersCount`, body limit on POST (e.g. 1 KB), `keepAliveTimeout`. Do not trust `X-Forwarded-For` unless behind a known proxy (GO-HTTP-003) - key rate limits on socket address or a configured trusted-proxy header.
- No `child_process`, no shell, no `eval`. `nslookup`/`dig` shell-outs are forbidden; use `node:dns/promises` (Resolver supports TXT, CAA, MX, NS; DNSSEC needs DO-bit -> not available in node:dns, see pitfalls).

### Our own site security (dogfooding; GO-HTTP-004)
- Serve static page with: CSP (`default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`. No inline scripts/styles so CSP stays strict.
- Skills advise against blind HSTS recommendation for dev projects; for a security scanner's scoring, still report HSTS, but our own dev server on localhost must not send it.
- Secure cookie caveat (security-best-practices note): our app needs no cookies; if any, set Secure only when TLS is on.
- CORS: none needed (same-origin). Never `*` + credentials.

### Deploy hints
- Split: static page (any static host) vs Node scanner backend (needs raw DNS/TLS sockets + long-ish requests).
- Cloudflare Workers/Pages Functions: NOT suitable for the backend. Workers lack node:tls raw cert inspection, `dns.resolve*` for CAA/DNSKEY (nodejs_compat is partial), have 10-30 ms CPU limit, and subrequest limits; outbound fetch also cannot pin IPs. Cloudflare Pages is fine for the static page only; `_headers` file gives CSP/nosniff there (works for static assets only, Functions override; limits 100 headers). Deploy checks: `npx wrangler whoami` first, `wrangler pages deploy <dir>`; auth via `wrangler login` or `CLOUDFLARE_API_TOKEN` env (never commit).
- Render (render.yaml Blueprint, runtime: node, `buildCommand: npm ci` -> we have no deps so skip, `startCommand: node server.js`, bind `0.0.0.0:$PORT`, `plan: free`, secrets via `sync: false`) is the closest fit for a Node backend; needs a Git remote; run `render blueprints validate`.
- Netlify/Vercel: functions run on serverless Node (AWS Lambda-like); fine for static page; backend feasible but egress IPs are shared and dynamic -> weak for DNS-TXT ownership + rate-limit-by-IP semantics; also cold starts kill 45 s scans. Vercel skill defaults to preview deploys, never production unless asked; do not curl the deployed URL to "verify".
- Any host: egress is the trust boundary. If the host has a private network (Render private services, VPC, cloud metadata 169.254.169.254), SSRF blocklist is critical, not optional. Prefer host-level egress firewall as second layer (skills: "Consider network egress controls at infrastructure level").
- Deploy needs explicit user OK for network calls/publishing; do not deploy in this task.
- Env-var secrets: never in repo; the scanner needs none (good, keep it that way).

## 3. Concrete check ideas for the scanner (from skills' security guidance)
- Headers: CSP present + parsed (script-src most important per GO-HTTP-004; flag `unsafe-inline`, `unsafe-eval`, wildcards, `data:`, missing `object-src`/`base-uri`/`frame-ancestors`), X-Frame-Options / frame-ancestors, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/CORP/COEP, HSTS (max-age, includeSubDomains, preload; only meaningful on HTTPS), Server/X-Powered-By version leakage.
- Cookies: Secure, HttpOnly, SameSite (SameSite=None without Secure = fail; session-looking cookie without HttpOnly), `__Host-`/`__Secure-` prefix validity, over-broad Domain, overlong Expires.
- CORS: `Access-Control-Allow-Origin: *` together with `Allow-Credentials: true`; reflected Origin (send `Origin: https://evil.example`, check echo; also `null`); wildcard methods/headers. (GO CORS rule.)
- Redirects: open-redirect surface (`?next=`, `?redirect=`) is active-ish, only after verification; passively check http->https redirect and scheme downgrades.
- Forwarded-header trust: passively n/a; active mode could send `X-Forwarded-Host` and detect reflection (only verified domains).
- Debug/verbose errors: stack traces in 404/500 bodies (active, verified only), `X-Debug`, `X-Powered-By: Express` (fingerprint).
- Active probe list (verified owners only, GET, no redirects followed off-host, cap 64 KB, tiny signature): /.git/HEAD (`ref: refs/`), /.git/config (`[core]`), /.env (KEY=VALUE regex, redact), /.DS_Store, /.svn/entries, /.hg/, /backup.zip|.sql|.tar.gz (check Content-Type + magic bytes via Range 0-3, don't download), /wp-config.php.bak, /phpinfo.php (`phpinfo()`), /server-status, /actuator/env, /admin, /.well-known/security.txt (also passive), /debug, /swagger.json|openapi.json (info only). Report: URL, status, signature id, severity. Never store body.
- Passive but valuable: security.txt (Contact, Expires not past, Canonical, signature), robots.txt exposing sensitive paths, mixed content in HTML, SRI on cross-origin script/link, cookies over HTTP, TLS versions/cert expiry via node:tls, CAA/SPF/DMARC via node:dns TXT/CAA.
- Scanner self-tests (node:test): SSRF matrix with every blocked range above + IPv4-mapped IPv6 + decimal/hex/octal literals + `localhost.` + `0`, redirect-to-private, rebinding via stub `lookup` that returns public first then private (must be impossible because pinned), body-cap abort, timeout abort, verification token mismatch/expiry.

## 4. Pitfalls
- Validate-then-fetch with two DNS resolutions = rebinding hole. Pin the IP; send original hostname as `Host` and TLS `servername` (SNI) so certs still verify.
- Check ALL returned addresses (A and AAAA); a mixed public+private answer must be rejected or private ones dropped, never "first wins".
- IPv4-mapped IPv6 (`::ffff:127.0.0.1`), IPv6 zone ids, 6to4/NAT64 (`64:ff9b::/96`), `0.0.0.0`, trailing-dot hostnames, IDN homographs, `localhost` aliases, `*.nip.io` style wildcard DNS all bypass naive string checks. Use numeric parsing (`node:net` isIP + BigInt/octet compare), not regex on strings.
- Redirect handling: default `fetch` follows redirects silently -> SSRF via redirect. Use `redirect: "manual"` or `http.request`, re-validate each hop, cap hops.
- node:dns has no DNSSEC validation (no AD bit exposure via resolve). DNSSEC check needs DNSKEY/DS query via `Resolver` best-effort or DoH (a DoH call to a fixed public resolver is an allowed egress; hardcode host). Mark DNSSEC as "best effort" rather than fake certainty.
- DNS TXT ownership: cache negative answers briefly; TTLs cause false "not verified"; case-insensitive compare, TXT strings may be split into multiple chunks (join them). Use a fixed public resolver or system resolver consistently (a private resolver can be poisoned by split-horizon DNS).
- Verified status must be per (domain, requester), not global, and revoked on TXT removal. Subdomain vs apex: require TXT on the exact host or apex by explicit rule; document it.
- Active probes on a verified domain can still hit third-party infra (CDN/shared hosting). Rate-limit gently (e.g. 2 req/s, sequential), and stop on 429/5xx spikes.
- Rate limits keyed by `X-Forwarded-For` are spoofable (skills call this out). In-memory Map limits reset on restart and don't scale - acceptable for v1, note ceiling with a `ponytail:` comment.
- Don't recommend HSTS/Secure-cookies in a way that breaks localhost dev (security-best-practices TLS note); scoring should look at the target's HTTPS state, not ours on localhost.
- `security.txt` is only valid at /.well-known/security.txt (root fallback legacy); require HTTPS, `text/plain`, Expires + Contact present.
- Cloudflare gotchas: `_headers` only applies to static assets; Pages Functions override it; free-tier CPU limit 10 ms; Next/Remix adapters deprecated (irrelevant, we use plain static).
- Serverless hosts: cold starts + 10-60 s limits cut long scans; keep scans short (<= 30 s) or stream progress (SSE) from a long-lived Node host.
- Reports/logs must not contain probe response bodies or user-supplied secrets; log only host, verdict, timing.
- security-ownership-map and threat-model reference files write files into the repo by default; do not run them here (Python/networkx dependency, unrelated to scanning).
