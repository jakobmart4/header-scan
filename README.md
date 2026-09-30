# header-scan

A SecurityHeaders.com-style scanner that checks much more: security headers (CSP parsed), cookies, TLS, DNS/mail (CAA, SPF, DMARC, DNSSEC), CORS, mixed content, SRI, `security.txt`, plus SEO, AI-visibility and UX-hygiene checks from a 40-item project checklist.

Node >= 20, ESM, **zero npm dependencies**, one static HTML page. 138 findings in total: 113 passive, 25 active (only after ownership is verified).

## Usage

```
npm start          # http://127.0.0.1:8787  (PORT / HOST env override; HOST defaults to 127.0.0.1)
npm test           # node --test test/
```

Open the page, type a URL, press Scan. Two grades are shown: **security** (headers, cookies, tls, dns, mail, content, exposure) and **quality** (seo, ai, ux). Only `pass`/`warn`/`fail` count; `info` and `skipped` never affect the score.

## API

All responses are JSON (`application/json; charset=utf-8`). Errors: `{"error":{"code","message"}}`.

| Route | Body | Success | Notes |
|---|---|---|---|
| `GET /api/scan?url=<u>` | - | 200 Result (passive) | a URL without scheme gets `https://` |
| `POST /api/scan` | `{url, deep?:true}` | 200 Result | `deep:true` re-checks ownership on the server; not verified -> 403 `NOT_VERIFIED` (message names the TXT record) |
| `POST /api/verify/start` | `{host}` | 200 `{host, token, txtName, txtValue, expiresAt}` | |
| `POST /api/verify/check` | `{host}` | 200 `{host, verified, txtName}` | stateless, DNS lookup on every call |
| `GET /api/health` | - | 200 `{ok:true, version}` | |

Error codes: `BAD_URL` 400, `BAD_REQUEST` 400, `BLOCKED_TARGET` 400, `NOT_VERIFIED` 403, `NOT_FOUND` 404, `METHOD_NOT_ALLOWED` 405, `TOO_LARGE` 413 (body > 4 KiB), `RATE_LIMITED` 429 (+`Retry-After`), `INTERNAL` 500, `SCAN_FAILED` 502, `BUSY` 503 (> 4 concurrent scans), `TIMEOUT` 504.

Result: `{url, host, scannedAt, durationMs, verified, deep, score:{security,quality,categories}, findings:[Finding], errors:[{module,message}]}`.
Finding: `{id, category, title, status: pass|warn|fail|info|skipped, severity: 1-5, evidence (<=300 chars), fix, ref?, checklist?}`.

## Ownership verification (for deep scans)

Active probes are only run against a domain you have proven you control.

1. `POST /api/verify/start {host}` returns a token, e.g. TXT name `_headerscan-verify.example.com` and value `headerscan-verify=<token>`.
2. Add that TXT record at your DNS provider.
3. `POST /api/verify/check {host}` looks the record up. When it is found, the UI enables "Run deep scan".
4. `POST /api/scan {url, deep:true}` checks the record again **on every request**. Verified state is never stored and never accepted from the client.

The token is `base64url(expiresAt).base64url(HMAC-SHA256(secret, host|expiresAt))[:32]`: bound to the exact host (`example.com` does not verify `www.example.com`), valid 24 h, tamper-evident, compared in constant time. The secret comes from `HEADERSCAN_SECRET` or is random per process (tokens then die on restart). DNS errors always mean "not verified". Shared hosting domains (`*.vercel.app`, `*.netlify.app`, `*.github.io`, ...) and IP literals are refused, so deep scans are impossible there.

## Safety model

- **Passive by default.** Normal scans only do what a browser would: fetch the page, `robots.txt`, `sitemap.xml`, a few same-origin links and up to 3 scripts, one TLS handshake, DNS lookups.
- **Active probes** (24 fixed paths such as `/.git/HEAD`, `/.env`, backups): only when ownership is verified. GET only, fixed allowlist (never user-supplied paths), no redirects followed, <= 2 requests/s, stop on 429 or repeated 5xx. A baseline request to a random path is compared first, so SPA catch-alls and soft 404s never produce false positives. A hit reports only `HTTP <status>, signature '<id>' matched`; file contents are discarded immediately and never logged or returned.
- **SSRF protection.** Only http/https on ports 80/443; no userinfo; IP literals in decimal/hex/octal form are normalized and checked. Every A/AAAA answer is checked after DNS resolution (loopback, private, link-local incl. `169.254.169.254`, CGNAT, multicast, reserved, IPv4-mapped/NAT64/6to4 IPv6) and **any** blocked answer rejects the host. The connection is pinned to the checked IP (no second lookup, so no DNS rebinding); the original hostname is kept for `Host` and TLS SNI. Every redirect hop is re-validated (max 5, loops detected).
- **Limits.** Request body 4 KiB, page 1 MiB, other text 256 KiB, probe body 64 KiB, 10 s per request, 45 s per scan, 60 requests per scan (100 for deep), <= 10 crawled pages, <= 3 scripts, max 4 concurrent scans.
- **Rate limit.** In-memory, per client IP (`X-Forwarded-For` ignored unless `HEADERSCAN_TRUST_PROXY=1`): scans 6/min, deep scans 2/min, verify 20/min.
- **Output.** Evidence never contains secrets, cookie values or file contents. The UI renders scan data with `textContent` only; the page is served with a strict CSP.
- The server binds to `127.0.0.1` by default. Put it behind a reverse proxy with TLS if you expose it.

## Checklist mapping

`c#` = line number of the item in the 40-item checklist (1-20 first list, 21-40 second list); the finding carries it in `checklist`.

| c# | IDs | c# | IDs |
|---|---|---|---|
| 1 | ux-default-hostname | 21 | ux-404-page |
| 2 | seo-spa-shell | 22 | ux-cta-above-fold |
| 3 | ux-404-page | 23 | ux-internal-links |
| 4 | seo-spa-shell | 24 | ux-thank-you |
| 5 | seo-duplicate-titles | 25 | ux-breadcrumbs |
| 6 | seo-meta-description, seo-meta-desc-length | 26 | ux-case-studies |
| 7 | seo-og-image | 27 | ux-faq |
| 8 | seo-structured-data | 28 | ux-response-time |
| 9, 10 | seo-h1 | 29 | ux-sticky-mobile-cta (not measurable in v1) |
| 11 | seo-canonical | 30 | seo-robots-txt |
| 12 | ai-llms-txt | 31 | seo-title, seo-title-length, seo-duplicate-titles |
| 13 | ai-robots-blocks-bots | 32 | seo-meta-description |
| 14 | ux-favicon | 33 | seo-og-image |
| 15 | seo-sitemap | 34 | ux-maps |
| 16 | seo-lang | 35 | ux-reviews |
| 17 | ux-alt-text | 36 | ux-alt-text |
| 18 | exp-source-maps | 37 | ux-local-schema |
| 19 | ux-console-errors (not measurable in v1) | 38 | ux-privacy-policy |
| 20 | ux-js-bundle-size | 39 | ux-analytics |
| | | 40 | ux-team-photo |

## Limitations

- No headless browser: console errors and sticky mobile CTA are always `skipped`; SPA content that only exists after JavaScript runs is judged on the raw HTML.
- DNSSEC is best effort (DoH to a fixed host); SPF lookup counting is approximate; DKIM selectors cannot be enumerated, so it is informational.
- Rate limiting is in-memory and resets on restart.
- Heuristic checks (CTA above the fold, team photo, reviews) are labelled as such in their evidence.
- The tests use a local fixture server (`test/fixture-server.js`, plain http on a random localhost port) and set `HEADERSCAN_ALLOW_PRIVATE=1` per test file; that variable must never be set in production because it disables the SSRF private-range and port rules.
