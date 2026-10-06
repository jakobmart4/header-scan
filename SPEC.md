# header-scan SPEC (single contract for 7 parallel builders)

Node >= 20, ESM (`"type":"module"`), ZERO npm deps, `node:test`. Code + comments in English. Ponytail: small, boring, no speculative features. Windows: use `py` never `python`. Never use port 34872 (Rojo) or 1000 (UA dashboard); default port 8787 (`PORT` env). Never leave a server running after checks.
Where this spec is silent, choose the simplest option; where it speaks, obey it literally (other builders rely on it).
SecurityHeaders.com parity round (6 new IDs, changed coop/coep/corp, `rawHeaders`): `docs/specs/PARITY-SPEC.md`.

## 1. File layout and ownership

| Builder | Files |
|---|---|
| B1 | `lib/ssrf.js`, `lib/verify.js`, `test/ssrf.test.js`, `test/verify.test.js` |
| B2 | `server.js`, `lib/scan.js`, `lib/score.js`, `package.json`, `README.md`, `test/score.test.js`, `test/scan.test.js`, `test/api.test.js` |
| B3 | `lib/checks/headers.js`, `lib/checks/cookies.js`, `test/headers.test.js`, `test/cookies.test.js` |
| B4 | `lib/checks/csp.js`, `lib/checks/tls.js`, `test/csp.test.js`, `test/tls.test.js` |
| B5 | `lib/checks/dns.js`, `public/index.html`, `test/dns.test.js` |
| B6 | `lib/checks/html.js`, `test/html.test.js` |
| B7 | `lib/checks/site.js`, `lib/checks/probes.js`, `test/fixture-server.js`, `test/site.test.js`, `test/probes.test.js` |

No other files. No shared helper files: shared helper `finding()` lives in `lib/score.js` (see 3). Tiny HTML regexes are duplicated per module on purpose (independence beats DRY here). `package.json`: `{"name":"header-scan","type":"module","private":true,"scripts":{"start":"node server.js","test":"node --test \"test/*.test.js\""}}` (later rounds added `build:ui`, `build`, `deploy` scripts and `version`), no dependencies. `package.json` test script must set env `HEADERSCAN_ALLOW_PRIVATE=1` via each test file (`process.env.HEADERSCAN_ALLOW_PRIVATE='1'` at top), not in the script (Windows-portable).

## 2. Contracts

### 2.1 Check module (all `lib/checks/*.js`)
```js
export const IDS = ['id-a', ...];              // exactly the IDs owned by this module (section 6)
export async function run(ctx) /* -> Finding[] */ // never throws for target problems
```
- Return EXACTLY one Finding per ID in `IDS`, always (status `skipped` when not applicable, never omit). Exception: `probes.js` (see 7).
- Must not throw for network/parse problems: catch and return the finding as `skipped` with evidence "error: <code>". Programming errors may throw; the orchestrator catches them.
- Never put secrets, cookie values, file contents or response bodies in `evidence`.
- Only use `ctx.fetch` / `ctx.resolve` for network I/O (except `tls.js`, which uses `node:tls` after `assertPublicHost`). Never `child_process`, never `eval`.
- Fetched bodies are hostile input. The size caps (page body 1 MiB; every other text body 256 KiB, because `ctx.fetch` defaults to 256 KiB and never reads more than 1 MiB per call; a script bundle's tail at most 1 MiB) bound memory, not time. So every scan of a body must be linear in its size: tag patterns use `[^<>]*` instead of `[^>]*`, the 404 stack-frame pattern is bounded to 200 characters on each side, robots.txt and security.txt are read line by line, and a terminator that does not exist (`-->`, a closing quote, `</script>`, `*/`) is searched for once and remembered, never once per opener. The `html.js` tokenizer (see 6.6; it also budgets the work spent on tags that never close at twice the body length plus 65,536 characters, after which the rest of the page counts as text), `stripInert` in `csp.js` and the `pageType` form/noscript scans (sorted positions and moving indexes) follow this. `test/hostile-input.test.js` feeds a fixed list of hostile shapes (unclosed comments, quotes, tags and scripts, runs of `<`, ...) of 256 KiB to the html, site, csp and headers modules and asserts that each finishes within 3 s: a regression guard, not a proof.

### 2.2 ctx
```js
ctx = {
  target:  { url, host, origin },        // normalized: url = final-input URL string, host lowercase no port, origin = "https://host[:port]"
  verified: boolean,                     // set ONLY by the orchestrator from a server-side DNS TXT check; never from client input
  allowPrivate: false,                   // true only if env HEADERSCAN_ALLOW_PRIVATE=1 (tests)
  fetch(url, opts) -> Promise<FetchResult>,   // SSRF-safe (2.3); already bound to allowPrivate + per-scan request budget
  page: { status, headers, body, finalUrl, redirects: [{status,from,to}], timingMs },  // GET of target.url, redirects followed
  resolve: {                             // arrays; [] on ENODATA/ENOTFOUND; throws on other DNS errors
    a():[string], aaaa():[string], ns():[string],
    mx():[{exchange,priority}], caa():[{critical,tag,value}],
    txt(name):[string],                  // each record's chunks JOINED into one string
    dnssec()?: Promise<{status:'signed'|'unsigned'|'unknown'}>   // optional, best effort (DoH to fixed host)
  },
  budget: { requestsLeft: number }       // informational; ctx.fetch throws FetchError('BUDGET') at 0
}
```
`page.headers`: lowercase keys, string values; `set-cookie` is always `string[]`. If the initial page fetch fails, orchestrator still runs modules with `page = {status:0, headers:{}, body:'', finalUrl:target.url, redirects:[], timingMs:0}` and modules return `skipped` where they need it.

### 2.3 lib/ssrf.js
```js
export class SsrfError extends Error { code }   // 'BLOCKED_TARGET' | 'DNS_FAILED' | 'BAD_URL'
export class FetchError extends Error { code }  // 'TIMEOUT'|'NETWORK'|'REDIRECT_LOOP'|'TOO_MANY_REDIRECTS'|'BLOCKED_TARGET'|'BAD_URL'|'BUDGET'
export function isBlockedIp(ip: string): boolean
export function parseTarget(input: string, opts?: {allowPrivate?:boolean}): {url, host, origin}  // sync; throws SsrfError('BAD_URL'|'BLOCKED_TARGET')
export async function assertPublicHost(host: string, opts?: {allowPrivate?:boolean, lookup?:Function}): Promise<{address:string, family:4|6}[]>  // throws SsrfError
export async function safeFetch(url: string, opts?: SafeFetchOpts): Promise<FetchResult>
// SafeFetchOpts: {method='GET', headers={}, maxBytes=1048576, timeoutMs=10000, maxRedirects=5, followRedirects=true,
//                 allowPrivate=false, encoding='utf8'|'latin1'='utf8', lookup? /*test injection*/}
// FetchResult: {status, headers, body:string, finalUrl, timingMs, redirects:[{status,from,to}], truncated:boolean}
```
Rules (all mandatory):
- `parseTarget`: http/https only; length <= 2048; no userinfo; strips fragment; lowercases host; trailing dot removed; IDN -> punycode via `new URL`; host must contain a dot or be an IP literal; ports other than 80/443 rejected unless allowPrivate. Rejects IP literals in decimal/hex/octal forms by normalizing through `new URL` then `isBlockedIp`.
- `isBlockedIp` uses numeric parsing (`node:net` isIP + octet/BigInt compare), NOT string regex. Blocks: 0.0.0.0/8, 10/8, 100.64/10, 127/8, 169.254/16 (incl. 169.254.169.254), 172.16/12, 192.0.0/24, 192.0.2/24, 192.168/16, 198.18/15, 198.51.100/24, 203.0.113/24, 224/4, 240/4, 255.255.255.255; IPv6 `::`, `::1`, fc00::/7, fe80::/10, ff00::/8, `::ffff:v4` and 64:ff9b::/96 (mapped back to v4 then re-checked), 2001:db8::/32, 2002::/16 (6to4 embedded v4 re-checked). Invalid input -> true (blocked).
- `assertPublicHost`: resolve ALL A and AAAA (`dns.lookup(host,{all:true})`); if ANY address is blocked -> throw `BLOCKED_TARGET` (mixed answers rejected, never "first wins"). Skipped entirely (returns addresses) when `allowPrivate`.
- `safeFetch`: uses `node:http`/`node:https` `request` (never global `fetch`); resolves via `assertPublicHost` then PINS the chosen address via the request's `lookup` option (custom lookup returning that IP), sends original hostname as `Host` and TLS `servername`; validates EVERY redirect hop (same rules, only http/https, max 5 hops, loop detection); User-Agent `header-scan/1.0 (+security scanner)`; `Accept-Encoding: identity` unless caller sets it; reads at most `maxBytes` then destroys the socket and sets `truncated:true`; `timeoutMs` is a TOTAL deadline per call (not idle); `followRedirects:false` returns the 3xx as-is. Non-2xx statuses resolve normally. Response `set-cookie` is `string[]`.
- Defaults: page 1 MiB, other text 256 KiB (callers pass `maxBytes`), probes 64 KiB, connect+total 10 s.

### 2.4 Finding
```js
{ id:'kebab-id', category:'headers|cookies|tls|dns|mail|content|seo|ai|ux|exposure',
  title:string, status:'pass|warn|fail|info|skipped', severity:1|2|3|4|5,
  evidence:string /* <=300 chars, no secrets */, fix:string /* one sentence, '' for pass */,
  ref?:url, checklist?:number /* first checklist number of the id (ids owning two items emit only the first); 1..40 = line number of item in the checklist txt, section 6 column c */ }
```
Helper (in `lib/score.js`, imported by all modules as `import { finding } from '../score.js'`):
`finding(id, category, title, status, severity, {evidence='', fix='', ref, checklist}={})` -> Finding; truncates evidence to 300 chars (adds `...`), asserts status/category/severity are legal (throws on programmer error).
Severity in section 6 = the severity of the finding when it is `warn` or `fail`; `pass`/`info`/`skipped` still carry the same number (used for weighting).
Checklist numbering: item-2 list = 1..20 in file order (vercell=1 ... massive JS bundles=20), item-3 list = 21..40 (custom 404=21 ... team photo=40).

### 2.5 lib/scan.js
```js
export async function scan({url, deep=false, verified=false, allowPrivate=(process.env.HEADERSCAN_ALLOW_PRIVATE==='1'),
                            resolve?, fetch?}) -> Promise<Result>
```
`resolve`/`fetch` are optional injections (tests); defaults use `node:dns/promises` `Resolver` and `safeFetch`. Steps: `parseTarget` -> `assertPublicHost` -> fetch page (5 redirects) -> build ctx -> run all modules via `Promise.allSettled` (probes.js only when `deep && verified`; when `deep` and not verified, probes.js is still run and returns its single `skipped` gate finding) -> flatten -> sort by (category order, status severity: fail, warn, info, pass, skipped, then id) -> `score()`. A rejected module adds `{module, message}` to `errors` (no stack) and its findings are missing. Total scan deadline 45 s (`AbortSignal.timeout`-style: after deadline, remaining modules are reported in `errors` as "timeout"). Request budget: 60 per scan (passive), 100 when `deep && verified`. Fetches to the same host: max 4 concurrent (semaphore inside the ctx.fetch wrapper). Module list order (category order): headers, cookies, csp, tls, dns, html, site, probes. `probes` runs only after all other modules have settled (never concurrently with them), so the <= 2 req/s probe pacing is the real request rate against the target.

### 2.6 Result JSON
```json
{ "url":"https://example.com/", "host":"example.com", "scannedAt":"ISO-8601", "durationMs":1234,
  "verified":false, "deep":false, "rawHeaders":[{"name":"...","value":"..."}],
  "score": { "security":{"score":87,"grade":"B"}, "quality":{"score":72,"grade":"C"},
             "categories":{"headers":{"score":80,"pass":9,"warn":2,"fail":1,"info":1,"skipped":0}, "...":{}} },
  "findings":[Finding], "errors":[{"module":"dns","message":"timeout"}] }
```
`verified` is echoed from the server-side check. `score` per 4. `rawHeaders` = the page response headers as lowercase `name`/`value` pairs in arrival order (`[]` when the page fetch failed); Set-Cookie lines keep name + safe attributes only (value redacted; a nameless cookie shows an empty name; Path only as `/`, Domain never; SameSite/Priority/Max-Age/Expires only in their strict shapes), token-like header names are redacted, other values are verbatim (report URLs may still carry tokens, they are public response data), at most 80 entries (cookie lines at most 20, overflow shown as a `(truncated)` row), values cut to 512 chars.

## 3. Scoring (lib/score.js)
```js
export function score(findings) -> {security:{score,grade}, quality:{score,grade}, categories:{[cat]:{score,pass,warn,fail,info,skipped}}}
export function gradeFor(score:number|null, findings:Finding[]) -> 'A+'|'A'|'B'|'C'|'D'|'E'|'F'|'N/A'
export function finding(...)   // see 2.4
```
- Only `pass`, `warn`, `fail` count. `info` and `skipped` are excluded from numerator AND denominator (never penalize what could not be measured or is advisory).
- Weight = `severity`. earned = weight * (pass=1, warn=0.5, fail=0). `score = round(100 * sum(earned) / sum(weight))` over counted findings; if no counted findings -> `score:null, grade:'N/A'`.
- `security` group = categories headers, cookies, tls, dns, mail, content, exposure. `quality` group = seo, ai, ux. Per-category score uses the same formula within the category.
- Grade table (applied to group score, then caps): >=97 A+, >=90 A, >=80 B, >=70 C, >=55 D, >=40 E, else F.
  Caps: A+ requires zero `fail` and zero `warn` with severity>=3 in the group; otherwise max A. Any `fail` with severity 5 caps the grade at D; any `fail` with severity 4 caps at C; more than 3 `fail`s cap at D (quality group: caps by count only, not severity).
- Deterministic and pure; unit-tested with hand-built findings arrays.

## 4. HTTP API (server.js, `node:http`, no framework)
Serves `public/index.html` only (`GET /` and `GET /index.html` -> index.html; anything else in `public/` -> 404, see "other public files -> 404" in `test/api.test.js`) and the JSON API. So `/privacy` and `/samples/*.json` exist only as Worker static assets (section 11): on a standalone server the footer Privacy link answers 404 and the sample-report buttons show an error (known limit). When `HEADERSCAN_PROXY_KEY` is set (behind the Worker, section 11) `GET /` is 404 without the key and every `/api/*` route except `/api/health` is 403 `FORBIDDEN` without it. Bind `127.0.0.1` by default (`HOST` env to change). All API responses `Content-Type: application/json; charset=utf-8`. Send on every response: `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` (API) and on index.html a strict CSP: `default-src 'none'; script-src 'sha256-..'; style-src 'sha256-..'; connect-src 'self'; img-src data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'`. index.html has one inline `<style>` and one inline `<script>` (layout allows no other files); server computes their SHA-256 at startup and injects the hashes. Scan data is rendered with `textContent`/`createElement` only, never `innerHTML`.

| Route | Body | Success | Notes |
|---|---|---|---|
| `GET /api/scan?url=<u>` | - | 200 Result (passive, `deep:false`) | `url` without scheme gets `https://` prepended |
| `POST /api/scan` | `{url, deep?:true}` | 200 Result | `deep:true` -> server does the TXT check itself; not verified -> 403 `NOT_VERIFIED` (message includes the txtName to add) |
| `POST /api/verify/start` | `{host}` | 200 `{host, token, txtName, txtValue, expiresAt}` | `txtName="_headerscan-verify.<host>"`, `txtValue="headerscan-verify=<token>"` |
| `POST /api/verify/check` | `{host}` | 200 `{host, verified:boolean, txtName}` | stateless: valid if ANY TXT at txtName carries a token with valid HMAC for that host and not expired |
| `GET /api/health` | - | 200 `{ok:true, version}` | version from package.json |

Errors: `{"error":{"code":"...","message":"..."}}` and status: `BAD_URL` 400, `BAD_REQUEST` 400 (bad JSON / missing field), `BLOCKED_TARGET` 400, `NOT_VERIFIED` 403, `FORBIDDEN` 403 (only when `HEADERSCAN_PROXY_KEY` is set and the key is missing), `NOT_FOUND` 404, `METHOD_NOT_ALLOWED` 405, `TOO_LARGE` 413 (request body > 4 KiB), `RATE_LIMITED` 429 (+`Retry-After` seconds), `SCAN_FAILED` 502 (target unreachable/DNS failed), `TIMEOUT` 504, `BUSY` 503 (more than 4 concurrent scans globally; 429 `RATE_LIMITED` when one client already runs 2). Capacity is checked before the rate limiter so a rejection does not consume quota. Never return stack traces or internal resolver output; 500 -> `INTERNAL`.
Limits: request body <= 4 KiB, page body 1 MiB, other text 256 KiB, probe body 64 KiB, per-request 10 s, connect 5 s, redirects 5, whole scan 45 s, crawl <= 10 pages, <= 3 script files fetched, ports 80/443 only (unless allowPrivate).
Concurrency: at most 4 scans at once (`MAX_ACTIVE`) and at most 2 per client (`MAX_PER_IP`); both are checked by `admit()` before the rate limiter. Rate limit (in-memory `Map`, sliding 60 s window, pruned every 60 s so an address is held 60 to 120 s, key = client IP: `x-headerscan-client` when the proxy key matches, else the rightmost `X-Forwarded-For` entry only if env `HEADERSCAN_TRUST_PROXY=1`, else `req.socket.remoteAddress`; IPv6 collapsed to its /64): `/api/scan` GET+POST 6/min/IP, deep scans 2/min/IP, `/api/verify/*` 20/min/IP. Known limits: a /64 bucket does not stop someone who holds a /48 (65,536 /64 networks, each with fresh quota); and once the map holds more than 50,000 keys a request with a new key gets 429 for 60 s (memory bound under many-IP floods). Add `// ponytail: in-memory, resets on restart` comment. Prune the map every 60 s with `unref()`'d timer.

## 5. Ownership verification (lib/verify.js)
```js
export function makeToken(host, {secret, now=Date.now(), ttlMs=86400000}={}) -> {token, txtName, txtValue, expiresAt}
export function tokenValid(host, token, {secret, now=Date.now()}={}) -> boolean
export async function isVerified(host, resolveTxt /* name->string[] */, {secret, now}={}) -> Promise<boolean>
export function txtNameFor(host) -> string           // "_headerscan-verify." + host
export function isSharedHost(host) -> boolean        // deny-list
export function getSecret() -> string                // env HEADERSCAN_SECRET else random 32 bytes hex generated once per process
```
- Token = `base64url(expiresAtMs) + "." + base64url(HMAC-SHA256(secret, host + "|" + expiresAtMs)).slice(0,32)`; host lowercased; compare with `crypto.timingSafeEqual`. Random per process (never a fixed test value); tests pass their own `secret`.
- Valid only for the exact host string (verifying `example.com` does NOT verify `www.example.com` or vice versa); TTL 24 h; expired or tampered -> false. `isVerified`: for each TXT value at `txtNameFor(host)`, strip optional quotes/whitespace, require prefix `headerscan-verify=`, case-insensitive prefix, token compared case-sensitively; DNS errors -> false (never true on error).
- `isSharedHost`: hosts that are or end with `.vercel.app`, `.netlify.app`, `.pages.dev`, `.github.io`, `.onrender.com`, `.herokuapp.com`, `.azurewebsites.net`, `.web.app`, `.firebaseapp.com`, `.workers.dev` -> verification refused (400 `BAD_REQUEST`), so deep scans are impossible there; IP literals also refused.
- Verified state is NEVER stored or cached and never accepted from the client: `POST /api/scan {deep:true}` re-runs `isVerified` on every request.
- Accepted limits (documented, not bugs): the token is per host, not per requester, and TXT is public, so while the record exists anyone can run deep scans of that host (2/min/IP); the TXT proves control of the name, not of the server its A record points at, so a third party's public IP can be probed via an attacker-owned name (bounded by the fixed read-only path list, no redirects, <= 2 req/s). Deployments that are publicly reachable must add authentication in front and set `HEADERSCAN_SECRET`.

## 6. Check IDs (complete; each owned by exactly ONE module)
Columns: `id | sev | rule (P=pass W=warn F=fail I=info S=skipped)`; `c#` = checklist number (2.4). "page" = `ctx.page`. HTTPS-only rules -> `S` when `target` scheme is http unless stated. Every module always returns one finding per ID.

### 6.1 headers.js (category `headers`; CORS also `headers`) - 22
```
hdr-hsts 4           F missing; W max-age<15552000; P otherwise. (http target: F "no HTTPS")
hdr-hsts-subdomains 2 W missing includeSubDomains; P present; S if hsts missing
hdr-hsts-preload 1    P has preload and max-age>=31536000 and includeSubDomains; else I
hdr-xcto 3            P value 'nosniff'; else F missing/other
hdr-frame-protection 3 P X-Frame-Options DENY|SAMEORIGIN or CSP frame-ancestors present; else F
hdr-referrer-policy 2 P value in {no-referrer, same-origin, strict-origin, strict-origin-when-cross-origin}; W missing or unsafe-url / no-referrer-when-downgrade / origin-when-cross-origin / origin; unknown token W "unrecognized value"
hdr-permissions-policy 2 P header present; W missing
hdr-coop 1            P Cross-Origin-Opener-Policy enforcing (same-origin, same-origin-allow-popups, noopener-allow-popups); else I ("report-only, not enforced" when only the -report-only header is sent)
hdr-coep 1            P Cross-Origin-Embedder-Policy enforcing (require-corp, credentialless); else I (report-only noted the same way)
hdr-corp 1            P Cross-Origin-Resource-Policy same-site|same-origin|cross-origin; else I (no report-only variant exists)
hdr-server-leak 2     W Server contains a digit-version (e.g. nginx/1.18.0); P otherwise
hdr-powered-by 2      W X-Powered-By present (also X-AspNet-Version); P absent
hdr-generator-leak 1  W <meta name=generator content=...> with a version number; P otherwise
hdr-cache-control-html 2  W page has Set-Cookie and Cache-Control lacks no-store|private; W Cache-Control missing on HTML; P otherwise
hdr-compression 2     P Content-Encoding gzip|br|deflate|zstd (page fetched with Accept-Encoding: gzip, br, via ctx.fetch opts); W absent and body>2 KiB; S otherwise
cors-wildcard-credentials 4  refetch page with Origin: https://evil.example; F reflected origin with ACAC true; W ACAO '*' with ACAC true (browsers reject it, misconfiguration); P otherwise
cors-reflected-origin 3  W ACAO echoes the evil origin without credentials; P otherwise
cors-null-origin 3    refetch with Origin: null; W/F(F if ACAC true) ACAO 'null'; P otherwise
hdr-xss-protection 2  P header absent or first token 0; W any other value (legacy filter can introduce XSS); evidence is the first token only
hdr-legacy-headers 1  W X-Permitted-Cross-Domain-Policies: all; I any of Expect-CT, Public-Key-Pins(-Report-Only), Feature-Policy, X-Download-Options, P3P present (names only, values never echoed); P none
cors-wildcard-public 2 ACAO '*' on the page or in the evil-origin probe: W when personalised (Set-Cookie, Vary Cookie/Authorization, Cache-Control private); I public wildcard; P no wildcard
hdr-reporting 1       always I: lists Report-To, Reporting-Endpoints, NEL, CSP report-uri/report-to found plus endpoint HOSTS only (never paths); "no reporting configured (optional)" when none
```

### 6.2 cookies.js (category `cookies`; ALL cookies from `page.headers['set-cookie']`; evidence lists cookie NAMES only) - 8
```
cookie-secure 4           F any cookie without Secure on an https page; P all secure; I no cookies
cookie-httponly 3         F cookie whose name matches /sess|auth|token|sid|jwt|login/i lacks HttpOnly; W other cookie lacks it; I no cookies
cookie-samesite 3         W any cookie without SameSite; P all set; I no cookies
cookie-samesite-none 3    F SameSite=None without Secure; P otherwise; I no cookies
cookie-prefix 1           P any __Host-/__Secure- cookie valid (Secure, and __Host: Path=/ and no Domain); W prefix used but invalid; I otherwise
cookie-domain 2           W Domain attribute set on a session-like cookie (exposes to subdomains); P otherwise; I no cookies
cookie-lifetime 2         W session-like cookie with Max-Age/Expires > 400 days; P otherwise; I no cookies
cookie-cache-control 2    W cookie set while page Cache-Control contains 'public'; P otherwise; I no cookies
```

### 6.3 csp.js (categories: `headers` for csp-*, `content` for mixed/sri) - 16
CSP parsing: split on `;`, first token = directive (lowercased), `script-src` falls back to `default-src`; `'unsafe-inline'` only counts when no nonce/hash/`'strict-dynamic'` is in the same directive. Enforced header `content-security-policy` is evaluated; report-only is evaluated only for csp-report-only.
```
csp-present 4              F no enforced CSP header (meta CSP counts as W); P present. Several comma-joined policies are all evaluated; per check the best finding among the policies that set the relevant directive wins (a problem counts only if every policy has it); empty elements are skipped
csp-report-only 1          I only Content-Security-Policy-Report-Only present; P/I otherwise (P if enforced too, I if none)
csp-unsafe-inline 4        F script-src(or default-src) has effective 'unsafe-inline'; P otherwise; S no CSP
csp-unsafe-eval 3          W 'unsafe-eval' in script-src/default-src; P otherwise; S no CSP
csp-wildcard 3             F script-src/default-src has '*', a bare TLD wildcard (*.com) or https: / http: bare scheme; P otherwise; S no CSP
csp-data-uri 2             W data: in script-src/default-src/object-src; P otherwise; S no CSP
csp-object-src 3           W no object-src 'none' (and default-src not 'none'); P otherwise; S no CSP
csp-base-uri 2             W base-uri missing; P present; S no CSP
csp-frame-ancestors 2      W missing (XFO alone does not satisfy); P present; S no CSP
csp-default-src 2          W no default-src; P present; S no CSP
csp-upgrade-insecure 1     P upgrade-insecure-requests or block-all-mixed-content present; else I; S no CSP
csp-style-unsafe-inline 2  W effective 'unsafe-inline' in style-src-elem|style-src|default-src (first present, 'strict-dynamic' ignored); P otherwise; S no CSP
csp-script-bypass-hosts 3  script-src-elem|script-src|default-src allowlists a host known to allow CSP bypass (`lib/data/csp-bypass-hosts.js`): W host-level hit; I path-scoped hit only; P none or 'strict-dynamic' present; S no CSP
mixed-active 5             https page only: F http:// in script[src], iframe[src], link[rel=stylesheet][href]; P none; S http target
mixed-passive 3            https page only: W http:// in img/audio/video/source[src|srcset]; P none; S http target
sri-external 3             W cross-origin <script src> or <link rel=stylesheet> lacking integrity (evidence: count + first 3 hosts); P all have it or none cross-origin
```

### 6.4 tls.js (category `tls`; uses `node:tls` `connect` to the pinned address returned by `assertPublicHost`, servername=host, port 443, 8 s timeout; `S` for all if target scheme is http and site has no https, except tls-https) - 11
```
tls-https 5              F https://host unreachable/ not offered; P ok
tls-protocol 4           P TLSv1.3 or TLSv1.2 (evidence names version); F TLSv1.1 or lower negotiated
tls-legacy-protocols 4   try connect with maxVersion 'TLSv1.1' & minVersion 'TLSv1'; F accepted; P rejected; S if local OpenSSL cannot attempt it (evidence says so)
tls-cert-expiry 4        F expired or <7 days; W <30 days; P otherwise
tls-cert-host 5          F hostname not covered by SAN/CN (`tls.checkServerIdentity`); P ok
tls-cert-chain 4         F `authorized===false` (self-signed, incomplete chain, untrusted); P ok
tls-cert-key 2           F RSA <2048 bits; P RSA >=2048 or EC >=256
tls-cert-sigalg 2        F SHA-1/MD5 signature; P otherwise (from `peerCertificate` fields; S if unavailable)
tls-alpn-h2 1            P negotiated 'h2'; I otherwise
tls-http-redirect 3      GET http://host/ (no redirects followed): P 301/302/307/308 to https://; F serves 200 on http; I no http listener (unreachable is fine); I any other answer (403, 404, 5xx, 3xx without https): "HTTP responds <status>, no redirect, no content served"
tls-redirect-permanent 1 P redirect status 301/308; I 302/307; S when tls-http-redirect not a redirect
```

### 6.5 dns.js (categories `dns` and `mail`; uses ctx.resolve) - 15
SPF lookups counted recursively over `include:`/`a`/`mx`/`ptr`/`exists:`/`redirect=` with depth<=10 and loop guard, via `ctx.resolve.txt`; approximate (mechanism count for a/mx, no expansion).
```
dns-caa 2                W no CAA records; P present
dns-dnssec 2             P signed; W unsigned; S if unknown/ctx.resolve.dnssec missing
dns-ns-count 2           W <2 NS records; P >=2 (looked up at the host, then its parents like CAA/MX; S none found)
dns-ipv6 1               I no AAAA; P has AAAA
mail-mx 1                I no MX (evidence: "no mail expected? add null MX '0 .'"); P present or null MX (Node returns exchange '' for `0 .`); a null MX still counts as no MX for the SPF/DMARC severity
mail-spf-present 4       F no SPF when MX present; W no SPF when no MX; P present (exactly one `v=spf1` TXT at host)
mail-spf-single 4        F >1 SPF records; P otherwise; S no SPF
mail-spf-all 4           F '+all' or '?all' or no all mechanism; W '~all'; P '-all'; S no SPF
mail-spf-lookups 3       F >10 DNS-lookup mechanisms; W 8-10; P otherwise; S no SPF
mail-dmarc-present 4     F missing at _dmarc.host when MX present; W when no MX; P present
mail-dmarc-policy 4      F p=none; W p=quarantine with pct<100 or sp weaker; P p=reject|quarantine; S no DMARC
mail-dmarc-rua 1         W no rua=; P present; S no DMARC
mail-mta-sts 1           I _mta-sts TXT missing; P 'v=STSv1' present
mail-tls-rpt 1           I _smtp._tls TXT missing; P 'v=TLSRPTv1' present
mail-dkim 1              I always: probes selectors default,google,selector1,selector2,k1,s1,mail at <sel>._domainkey.host; P if any found; else I "selector unknown, cannot conclude"
```

### 6.6 html.js (categories `seo`, `ux`, `content`, `ai`; parses `page.body` with a linear tokenizer over the first 1 MiB (see 2.1, hostile input), raw HTML only, no DOM) - 31
Legend of `c#`: checklist number. Visible text = the text between tokens: tags, comments, `<script>`/`<style>`/`<title>` elements and the `<!doctype ...>` / `<?xml ...?>` declarations are not text. SPA shell = visible text <200 chars AND a shell root: an `<app-root>` element or a `<div>` whose id is `root`, `app`, `__next`, `__nuxt`, `___gatsby` or `svelte`.
```
seo-title 3             F missing/empty; P present                                            c31
seo-title-length 1      W length <10 or >60; P otherwise; S no title                          c31
seo-meta-description 3  F missing/empty; P present                                            c6,c32
seo-meta-desc-length 1  W length <70 or >160; P otherwise; S none                             c6
seo-canonical 2         P absolute canonical href same host as finalUrl; W missing/relative/other host; also honors Link: rel=canonical header   c11
seo-h1 3                P exactly one <h1>; W >1; F 0 (evidence notes "0 in raw HTML" when SPA shell)   c9,c10
seo-heading-order 1     W a heading level skips (h1->h3); P otherwise
seo-lang 3              P <html lang> matches ^[a-z]{2,3}(-[A-Za-z0-9]+)*$; F missing/invalid   c16
seo-viewport 3          P <meta name=viewport> contains width=device-width; W tag present without it; F tag missing
seo-og-image 2          F og:image missing; W not absolute http(s) URL; P ok (no HEAD request here)   c7,c33
seo-og-basic 1          W og:title or og:description missing; P both present
seo-twitter-card 1      W twitter:card missing; P present
seo-structured-data 2   P >=1 valid JSON-LD block with @type; W none; F any invalid JSON   c8
seo-noindex 4           F noindex in meta robots or X-Robots-Tag header; P otherwise
seo-spa-shell 4         F SPA shell (empty view-source); W Vite/CRA/Next-shell fingerprints (/assets/index-*.js, /@vite/client, type=module + root) but text>=200; P otherwise   c2,c4
ux-alt-text 3           F any <img> without alt attribute (evidence "M of N missing"); P all have alt; I no images (alt="" counts as decorative)   c17,c36
ux-internal-links 2     S `minimal page: nothing to link to` when `pageType().isMinimal`. P >=3 same-site (www and apex are one site) <a href> (not #, javascript:, mailto:, tel:, data:; counted as distinct path + query pairs); W 1-2; F 0 (SPA-shell note). S `single-page tool: no other pages to link to` when `pageType().isSinglePageTool` (an empty SPA shell is never skipped: seo-spa-shell owns it)   c23
ux-cta-above-fold 1     P first 3000 chars of <body> contain a/button with CTA words (contact|book|get|buy|start|call|quote|kontakt|broneeri|telli|tel:|mailto:); W none. Heuristic, say so. S `minimal page: no sales content to call to action on` when `isMinimal`; S `single-page tool: the on-page form is the primary action` when `isSinglePageTool`   c22
ux-breadcrumbs 1        P JSON-LD BreadcrumbList or aria-label=breadcrumb or class~=breadcrumb; else I   c25
ux-case-studies 1       P same-origin link whose path has a whole segment matching /(^|/)(case-stud(y|ies)|portfolio|projects|tood|cases|our-work)(/|$|[-_.])/ (external links and slug substrings such as `/eeltood-uute` do not count); else I   c26
ux-faq 1                P >=5 questions (FAQPage JSON-LD mainEntity count, <details> count, or "FAQ|KKK|korduma" section with >=5 '?'; `<details>` count only when >=2, a lone one is a disclosure widget); W 1-4; I none; S `minimal page: FAQ content not expected` when <5 items and `isMinimal`; S `single-page tool: FAQ content not expected` when <5 items and `isSinglePageTool`   c27
ux-response-time 1      P regex `within \d+ (hour|business day)|reply within|vastame|\b24 ?h\b|1 tööpäeva` (case-insensitive, on visible text); else I   c28
ux-maps 1               P iframe maps/openstreetmap, maps.app.goo.gl, goo.gl/maps, hasMap/geo in JSON-LD; else I   c34
ux-reviews 1            P JSON-LD aggregateRating/Review or trustpilot/elfsight/google-reviews embed (presence only, "real" unverifiable); else I   c35
ux-local-schema 1       P LocalBusiness(+subtype) with address, telephone, openingHours*; W partial; I none   c37
ux-privacy-policy 2     a policy link is an `<a href>` that names itself: either its link text is short (<=40 chars and <=4 words, split on spaces, `_`, `.`, `-`) and matches the privacy words, or the last segment of its URL path (percent-decoded, `.html|.htm|.php|.asp|.aspx` dropped) is short (<=2 words) and matches them. Privacy words: /privacy|privaatsus|andmekaitse|isikuandme|datenschutz|confidentialit|privacidad|tietosuoja|integritet|cookie[\s_-]*(policy|notice|statement|poliitika)|k[üu]psis/i. Prose that merely contains the word is not a policy link (`/blog/privacy-friendly-analytics`, a 7-word sentence about privacy). The first anchor whose href is not #, javascript:, mailto:, tel: or data: wins; one of those only if nothing better (then W `privacy link is not http(s)`). Found: P (GET it via ctx.fetch, 256 KiB, must be 200 non-empty, else W). Known limit: a short link text that names the topic still counts (`Your privacy matters`, `Confidentiality agreements template`). Not found: F if a lead form (login/button-only forms are not lead forms; see Page-type signals), a tracker or commerce (cart/checkout) links are present; else I `minimal page with no form and no tracker: no privacy policy needed` on a minimal page, else I `no personal-data form ... (single-page tool)` on a single-page tool, else W   c38
ux-analytics 1          P gtag/js, G-XXXX, UA-, gtm.js, GTM-, plausible, matomo, umami, fathom; I none; evidence adds GDPR hint if no consent keywords. Tracker list also covers cloudflareinsights, clarity.ms, hotjar, mixpanel, posthog, segment.com, connect.facebook.net, `fbq(`, `_hsq`   c39
ux-team-photo 1         I "found"/"not found": <img> whose alt/src matches team|meeskond|staff|founder|about (low confidence)   c40
ux-theme-color 1        P <meta name=theme-color> present; I missing
ux-console-errors 1     always S "needs a headless browser (not in v1)"   c19
ux-sticky-mobile-cta 1  always S "needs a headless browser (not in v1)"   c29
```
(All `c` mappings above: the ID is the sole owner of that checklist item unless stated in another module.)

**Page-type signals.** `pageType(html, finalUrl)` (exported from html.js, pure, never throws, first 1 MiB, linear in the input, memoised: the tokenizer result and the classification each keep the last body, so html.js and site.js parse and classify once per scan) feeds the applicability-aware ux-* rules and site.js. Fields: `isAppShell`, `formCount` (forms outside `<noscript>`), `hasLeadForm`, `hasAuthForm`, `onlySearchForms`, `hasCommerce`, `hasTracker`, `internalLinks` (raw distinct same-site paths), `hasContactLink`, `isSinglePageTool`, `isMinimal`. Every counted form has one class. `inert`: has controls but no visible field (logout, consent, toggle). `auth`: the only personal field is `type=password`. `search`: no personal signal and positive evidence (type=search, role=search, a GET action, a tool-like name/id/autocomplete such as q/url/host/domain/ip_address, or app JSON-LD on the page). Everything else is `lead`: unknown stays strict, including an empty `<form></form>`, a post/contact-like action, and a text field with no positive signal. Personal signals are whole-word matches on name/id/autocomplete (hostname, domain_name, ip_address, hotel are not personal) plus placeholder/aria-label/title/label text (email-like or phone-like values count), except on a `type=search` input and on any field of a `role=search` form, where this free text is ignored (a hint such as "Search by name" does not make a search box a lead form); name/id/autocomplete, `type=email|tel|file` and a textarea (unless the page has app JSON-LD) still do, also inside a search-looking form. `isSinglePageTool` needs no shell, at most one other page (the page itself, `/` and legal/utility paths such as /privacy, /terms, /.well-known/*, robots, sitemap, llms.txt do not count), no lead form, no commerce, no tel:/mailto: link (unless app JSON-LD plus a search form) AND positive evidence: app JSON-LD (WebApplication/SoftwareApplication) with a search form or no promo links (CTA words, contact, app-store links, also cross-origin), or exactly one JS-only search form and no promo links; a tracker does not stop tool status. `isMinimal` (placeholder, parked or "hello world" page) needs ALL of: no shell root (of any text length: a client-app root means the content arrives with JavaScript); no `<script src>` other than a known analytics/tracker script (so a first-party bundle, but also any other library or CDN script, makes the page not minimal); no promo link (same definition as above: any `<a href>`, also cross-origin, whose href plus link text reads like a sales or sign-up call) and no tel:/mailto: link; no `<iframe>`, `<input>`, `<textarea>` or `<select>` anywhere in the HTML (also outside a `<form>` and inside `<noscript>`: embeds and bare fields collect data); visible text under 250 characters (see 6.6 legend: doctype/xml declarations are not text, so 249 characters is minimal and 250 is not; the empty-shell limit is likewise exactly 200); no other page (same page set as above); no form; no commerce. A short sign-up, booking or phone page therefore keeps the strict rules. `isMinimal` is checked before `isSinglePageTool` in the three skipped rules. Not applicable means `skipped` or `info` with an explanation, never fail/warn; genuine marketing pages keep the old strict results.

Known limits, deliberately unchanged: ux-response-time (`24 ?h` also matches "24h" in unrelated text), seo-spa-shell (an `<app-root>`, `__nuxt`, `___gatsby` or `svelte` root is recognised only while the page has under 200 characters of text; the `warn` fingerprints stay Vite/CRA-style, so an Angular, Nuxt or Gatsby page with more text gets no warning), ux-privacy-policy (a short link text that names the topic still counts), the regex reads in csp.js, headers.js and site.js (a `<` inside an attribute value ends the tag there; the html.js tokenizer honours quotes), ux-alt-text (noscript tracking pixels count), ux-default-hostname (fixed list), the info-only marketing checks (breadcrumbs, maps, reviews, local-schema, team-photo, response-time stay `info`), docs/news/wiki page types (a site-search form is not evidence of a non-marketing page, so CTA stays strict there), pages with several `<details>` collapsibles (>=2 still count as FAQ), `/product/projects` (matches ux-case-studies), and a tool whose other pages exist but are not linked from the scanned page (treated as single-page; the evidence says so).

### 6.7 site.js (categories `seo`, `ai`, `ux`, `exposure`; own fetches via ctx.fetch, maxBytes 262144) - 16
```
seo-robots-txt 3          P GET /robots.txt 200, not HTML, and either empty (whitespace only) or with at least one line starting `User-agent`, `Sitemap`, `Allow` or `Disallow` (case-insensitive; RFC 9309: an empty file, or one with only Sitemap/Allow/Disallow lines and no User-agent group, allows everything, and the evidence says so); F 200 that is HTML (evidence `returns HTML (SPA fallback?)`) or has none of those directives (evidence `no robots.txt directive`); W any other status (evidence `HTTP <status>`, usually 404); S fetch error   c30
ai-robots-blocks-all 5    F group `User-agent: *` with `Disallow: /` (blocks Google too); P otherwise; S no robots.txt
ai-robots-blocks-bots 2   W GPTBot|ChatGPT-User|OAI-SearchBot|ClaudeBot|Claude-Web|anthropic-ai|PerplexityBot|Google-Extended|CCBot|Bytespider disallowed '/' (evidence lists names; may be intentional); P none; S no robots.txt   c13
seo-robots-sensitive 1    I robots Disallow lists /admin|/backup|/private|/wp-admin|/.git (hint only, not a vuln); P otherwise; S no robots.txt
seo-sitemap 3             sitemap URL from robots `Sitemap:` else /sitemap.xml: P 200 with <urlset|<sitemapindex; W missing; F listed in robots but 404/not XML   c15
ai-llms-txt 1             P GET /llms.txt 200, not HTML, >20 bytes; W otherwise (optional standard, never F)   c12
ux-404-page 3             GET /<16hex>-nf: P 404 with body >=300 bytes and not a default server text; W 404 with tiny/default body ("Cannot GET", nginx/apache default); F 200 (soft 404; also on tools and SPA shells). I when the 404 is tiny/default on a single-page tool (`real HTTP 404; a custom 404 page is not needed on a single-page tool`) and when unknown paths answer 401, or 403 on a single-page tool or from a Cloudflare bot filter (`cf-mitigated` header / challenge body); 403 elsewhere stays W `random path returns HTTP 403` (S3/CloudFront without an error document)   c3,c21
ux-favicon 2              P <link rel~=icon> found in page body or GET /favicon.ico 200 image/*; W none    c14
ux-default-hostname 2     W finalUrl host ends .vercel.app|.netlify.app|.pages.dev|.github.io|.onrender.com|.herokuapp.com|.web.app; P otherwise   c1
seo-duplicate-titles 3    compare the scanned page (<=10 pages in all) with up to 9 others: same-origin `<a href>` links of the page, then sitemap `<loc>` URLs (GET each, 256 KiB, HTML 200 only; .pdf, images, .zip, .css, .js, .xml, .ico, .mp4, .txt links are skipped). Candidates are deduped by normalised path: a URL is origin + path + query with a trailing slash and `index.html|htm` removed (`/about` and `/about/` are one page). A fetched body byte-identical to the scanned page's raw body is the home page under another URL (`/index.html`, `/?lang=en`, `/home`) and is dropped; identical bodies of two other pages still count (a genuine duplicate). F duplicate <title> across the remaining pages; W duplicate meta description; P all unique; I fewer than 2 pages to compare   c5,c31
ux-thank-you 1            GET /thank-you,/thanks,/aitah,/tanks (max 4): P any 200 HTML page that is not a shell, i.e. its first 1024 characters differ from those of the random-path 404 body and of the RAW home page body (`page.body`, not the comment/script-stripped copy); I none and no form; W none but a lead form exists (`pageType().hasLeadForm`; fallback `<form` when the page type is unknown); S, with no fetches, when the page has form(s) but only benign search/tool, login (password is the only personal field) or button-only/hidden-only ones   c24
ux-js-bundle-size 2       sum size of same-origin <script src> (max 3 fetched, Content-Length else body length, transferred if Content-Encoding): F >1 MB total; W >500 KB total or a single file >300 KB or uncompressed; P otherwise; I no scripts   c20
exp-source-maps 3         for the <=3 fetched scripts: `//# sourceMappingURL=` in last 2 KiB or SourceMap header, then GET .map (status+content-type only): W .map returns 200; P none; S no scripts   c18
exp-security-txt 2        GET /.well-known/security.txt over https: P 200 text/plain; W only at /security.txt (legacy) or wrong type; I missing (advisory)
exp-security-txt-fields 2 W missing Contact or Expires, or Expires in the past; P both valid; S no security.txt
exp-error-leak 3          the /<16hex>-nf 404 body (reuse own fetch): F contains a stack frame (`\bat \S[^\n(]{0,200}\([^\n)]{0,200}:\d+:\d+\)`, bounded, see 2.1), `Traceback (most recent` or an absolute path (`C:\`, `/var/www`); P otherwise; S fetch failed
```

### 6.8 probes.js (category `exposure`; ACTIVE; only when `ctx.verified === true`) - 24 probes + 1 gate
`IDS` = `['exp-probes-gate', ...24 probe ids]`.
- `ctx.verified !== true` -> `run` returns ONLY `exp-probes-gate` (status `skipped`, sev 5, evidence "domain ownership not verified: active probes disabled", fix names `_headerscan-verify.<host>` TXT). Verified -> gate is `pass` ("owner verified") plus all probe findings.
- Fixed allowlist below; NEVER user-supplied paths; GET only (method hard-coded, asserted); `followRedirects:false`; `maxBytes: 65536`; `encoding:'latin1'`; `Range: bytes=0-4095` header for archives; sequential, 500 ms delay between requests (<=2 req/s); stop early (remaining probes `skipped`) on any 429 or 3 consecutive 5xx.
- Baseline first: GET `/<16hex>-hs-probe`; store status + SHA-256 of first 1 KiB. A probe is a HIT only if status is 200/206 AND signature matches AND body-prefix hash differs from baseline (SPA catch-all / soft-404 never false-positives).
- HIT -> `fail` with the probe's severity, evidence `"HTTP <status>, signature '<sig-id>' matched"` ONLY (no content, no snippet, no lengths of secrets). No hit -> `pass` evidence `"not found"` (or `"200 without signature, ignored"`). Bodies are discarded immediately, never logged.
```
exp-probe-git-head       5 /.git/HEAD              text starts "ref: refs/"
exp-probe-git-config     5 /.git/config            contains "[core]"
exp-probe-env            5 /.env                   a line matching ^[A-Z][A-Z0-9_]{2,}=  (never echo)
exp-probe-svn            4 /.svn/wc.db             starts "SQLite format 3"
exp-probe-hg             4 /.hg/requires           contains "revlogv1" or "store"
exp-probe-ds-store       2 /.DS_Store              bytes 4-8 == "Bud1"
exp-probe-backup-zip     5 /backup.zip             starts "PK\x03\x04"
exp-probe-backup-sql     5 /backup.sql             /CREATE TABLE|INSERT INTO|MySQL dump/
exp-probe-backup-tgz     5 /backup.tar.gz          starts "\x1f\x8b"
exp-probe-db-sql         5 /db.sql                 same as backup-sql
exp-probe-wp-config-bak  5 /wp-config.php.bak      contains "DB_PASSWORD" or "<?php"
exp-probe-phpinfo        4 /phpinfo.php            contains "phpinfo()" or "PHP Version"
exp-probe-server-status  3 /server-status          contains "Apache Server Status"
exp-probe-actuator-env   5 /actuator/env           contains "propertySources"
exp-probe-actuator       3 /actuator               contains "_links"
exp-probe-admin          2 /admin                  200 and contains type="password" (401/403 = pass "protected")
exp-probe-phpmyadmin     3 /phpmyadmin/            contains "phpMyAdmin"
exp-probe-debug          3 /debug                  /Traceback|stack trace|DEBUG = True/i
exp-probe-swagger        1 /swagger.json           contains "\"swagger\"" or "\"openapi\"" (status `info` on hit, not fail)
exp-probe-openapi        1 /openapi.json           same, `info` on hit
exp-probe-package-json   2 /package.json           contains "\"dependencies\""
exp-probe-vercel         2 /.vercel/project.json   contains "projectId"
exp-probe-web-inf        4 /WEB-INF/web.xml        contains "<web-app"
exp-probe-dir-listing    3 /uploads/               contains "Index of /"
```

## 7. Complete ID index per module (for structured output / tests)
- headers.js: hdr-hsts, hdr-hsts-subdomains, hdr-hsts-preload, hdr-xcto, hdr-frame-protection, hdr-referrer-policy, hdr-permissions-policy, hdr-coop, hdr-coep, hdr-corp, hdr-server-leak, hdr-powered-by, hdr-generator-leak, hdr-cache-control-html, hdr-compression, cors-wildcard-credentials, cors-reflected-origin, cors-null-origin, hdr-xss-protection, hdr-legacy-headers, cors-wildcard-public, hdr-reporting
- cookies.js: cookie-secure, cookie-httponly, cookie-samesite, cookie-samesite-none, cookie-prefix, cookie-domain, cookie-lifetime, cookie-cache-control
- csp.js: csp-present, csp-report-only, csp-unsafe-inline, csp-unsafe-eval, csp-wildcard, csp-data-uri, csp-object-src, csp-base-uri, csp-frame-ancestors, csp-default-src, csp-upgrade-insecure, csp-style-unsafe-inline, csp-script-bypass-hosts, mixed-active, mixed-passive, sri-external
- tls.js: tls-https, tls-protocol, tls-legacy-protocols, tls-cert-expiry, tls-cert-host, tls-cert-chain, tls-cert-key, tls-cert-sigalg, tls-alpn-h2, tls-http-redirect, tls-redirect-permanent
- dns.js: dns-caa, dns-dnssec, dns-ns-count, dns-ipv6, mail-mx, mail-spf-present, mail-spf-single, mail-spf-all, mail-spf-lookups, mail-dmarc-present, mail-dmarc-policy, mail-dmarc-rua, mail-mta-sts, mail-tls-rpt, mail-dkim
- html.js: seo-title, seo-title-length, seo-meta-description, seo-meta-desc-length, seo-canonical, seo-h1, seo-heading-order, seo-lang, seo-viewport, seo-og-image, seo-og-basic, seo-twitter-card, seo-structured-data, seo-noindex, seo-spa-shell, ux-alt-text, ux-internal-links, ux-cta-above-fold, ux-breadcrumbs, ux-case-studies, ux-faq, ux-response-time, ux-maps, ux-reviews, ux-local-schema, ux-privacy-policy, ux-analytics, ux-team-photo, ux-theme-color, ux-console-errors, ux-sticky-mobile-cta
- site.js: seo-robots-txt, ai-robots-blocks-all, ai-robots-blocks-bots, seo-robots-sensitive, seo-sitemap, ai-llms-txt, ux-404-page, ux-favicon, ux-default-hostname, seo-duplicate-titles, ux-thank-you, ux-js-bundle-size, exp-source-maps, exp-security-txt, exp-security-txt-fields, exp-error-leak
- probes.js: exp-probes-gate + the 24 `exp-probe-*` ids in 6.8

Total: 22+8+16+11+15+31+16+25 = 144 findings (119 passive, 25 deep). Categories per finding: headers.js/csp.js(csp-*)->headers; mixed-*/sri-* ->content; tls-*->tls; dns-*->dns; mail-*->mail; seo-*/ux-* as named in 6.6-6.7 (`seo-*`->seo, `ux-*`->ux, `ai-*`->ai, `exp-*`->exposure); `ux-alt-text` ux; `ux-default-hostname` ux; `seo-noindex` seo.

## 8. Frontend (public/index.html, B5)
One static file, inline `<style>`/`<script>` (see CSP hashing in section 4), no external requests, no framework, light+dark via `prefers-color-scheme`, works at 320 px, keyboard-usable, `<html lang="en">`, labelled inputs, `aria-live` region for progress. UI: URL input + "Scan" (GET /api/scan), grade badges (security + quality) with sub-score bars per category, findings grouped by category with status filter (fail/warn default open, pass collapsed), each finding shows title, evidence, fix, checklist tag. "Deep scan" panel: enter host -> POST /api/verify/start -> show TXT name+value with copy button -> "Check" (POST /api/verify/check) -> when verified enable "Run deep scan" (POST /api/scan deep). Render ALL scan data with `textContent`, never `innerHTML`. No localStorage needed.

## 9. Tests (node:test; each file starts with `process.env.HEADERSCAN_ALLOW_PRIVATE='1'` when it needs localhost)
- `test/review-fixes.test.js`: regression tests from the review round (comment/inline-script false positives, https by final URL, DNS climb, html heuristics, bundle tail/Range, probe signatures and pacing). Not covered by any test: `tls-legacy-protocols` and `tls-alpn-h2` (need a TLS server with a certificate; no dependency-free way to make one).
- `test/fixture-server.js`: `export async function start({mode='bad'}={}) -> {url:'http://127.0.0.1:<random port>', port, close()}` using `node:http` on `127.0.0.1:0`. Modes: `bad` (no security headers, `Server: nginx/1.18.0`, `X-Powered-By: Express`, cookie `sessionid=abc; Path=/` (no flags), HTML with no title/description/lang/viewport, two `<h1>`, `<img>` without alt, `http://` script src, cross-origin script without integrity, `/robots.txt` with `User-agent: GPTBot`+`Disallow: /`, no sitemap/llms.txt, 404 returns 200 soft page, reflects `Origin` in ACAO + ACAC true, `/.git/HEAD` -> `ref: refs/heads/main`, `/.env` -> `SECRET_KEY=dummy`), `spa` (every path returns the same 200 HTML shell with `<div id="root">` -> probes must produce ZERO hits), `good` (all headers set, valid meta/JSON-LD, proper 404, robots/sitemap/llms.txt). All fixture secrets are obviously fake dummies.
- Each check module test: unit-test pure parsers with hand-made `ctx` objects (no network) + one run against the fixture server through `scan()` where relevant; assert `run(ctx)` ids equal `IDS` exactly (set equality, no duplicates).
- `ssrf.test.js` MUST cover: every blocked range in 2.3, IPv4-mapped IPv6, decimal/hex/octal literals, `localhost.`, userinfo, non-http scheme, port 22/6379, mixed public+private DNS answer (injected `lookup`), rebinding impossible (lookup called once, connection uses pinned IP), redirect to private/`file:`, redirect loop, body cap -> `truncated`, total timeout, `allowPrivate` lifts private and port rules only.
- `verify.test.js`: token roundtrip, wrong host, expired, tampered, chunked/quoted TXT, DNS error -> false, shared-host deny-list, client cannot supply `verified` (API test: `POST /api/scan {deep:true}` without TXT -> 403).
- `score.test.js`: skipped/info excluded, weights, caps, A+ rules, N/A. `api.test.js`: routes, error shapes, rate limit (7th scan -> 429), body cap 413, server started on port 0 and closed in `after()`.
- Self-test (in `scan.test.js`): scan fixture `bad` -> security grade F/E-ish (assert `<= 'D'`) and specific fail IDs present; scan `good` (plain-http fixture) -> the only fails are `tls-https` and `hdr-hsts`, which cap the real security grade at D; without those two http-only findings the security sub-score is >= B and quality >= B; deep scan on `bad` with `verified:true` finds `exp-probe-git-head` and `exp-probe-env` as fail with evidence NOT containing `SECRET_KEY` or `refs/heads`; `spa` mode -> no probe hit.
- `test/hostile-input.test.js`: hostile bodies stay fast (see 2.1) and one regression test per false-verdict fix of the page-type, minimal-page, search-box, privacy-link, duplicate-title, robots.txt and thank-you rules. `test/sample-reports.test.js`: `public/samples/*.json` are labelled samples, their stored scores equal `score()` of their findings, `perfect` is A+ 100 for both groups, `mixed` lands within 47 to 53 for both, their finding ids equal the live catalog (119 passive ids) and they contain no e-mail address (see README, Sample reports).
- Command: `npm test` (= `node --test "test/*.test.js"`). All servers closed in `after()`. Finding counts asserted in `test/scan.test.js`: 119 passive, 144 deep.

## 10. README (B2)
What it is, `npm start` (port 8787), API table (link to section 4 content), the ownership-verification flow, security posture (passive by default, probes read-only GET/allowlist/no content stored, SSRF rules, rate limits), checklist mapping (c# -> ID), limitations (no headless browser: console errors, sticky CTA; DNSSEC best effort; SPF lookup count approximate; in-memory rate limit). Must stay in sync with this spec.

## 11. Deployment shape (Cloudflare Worker + Render; steps in `DEPLOY.md`)
- `worker/index.js` runs only for `/api/*` (`run_worker_first` in `wrangler.toml`); `dist/` (built from `public/` with the site-wide CSP in `_headers`) is served by the platform; this includes `/privacy` and the static sample reports `/samples/perfect.json` and `/samples/mixed.json`, which the standalone `server.js` does not serve (section 4). Secrets `BACKEND_URL` and `PROXY_KEY` (= backend `HEADERSCAN_PROXY_KEY`). Deploy order: Render first, then Cloudflare.
- Worker routes: `/api/scan` GET/POST, `/api/verify/start` and `/check` POST, `/api/health` GET; other paths 404, wrong method 405, missing secrets 500 `MISCONFIGURED`, backend down or an HTML 502-504 -> JSON 502 `BACKEND_UNREACHABLE` with `Retry-After: 30`. It forwards `x-headerscan-key` and the real client IP (`x-headerscan-client`).
- Every response the Worker produces itself carries the security headers (`SECURITY` in `worker/index.js`, kept in step with `scripts/build-pages.mjs`; `_headers` never applies to Worker responses). Plain `http://` gets a 308 to `https://` on Worker-handled paths only; static assets are not redirected (known limit, acceptable: `.dev` is HSTS-preloaded).
- No `security.txt`, no email address and no name anywhere in `public/`; the privacy page states what `server.js` really keeps (client IP in memory 60 to 120 s, nothing on disk, only internal error messages logged) and that the scanned host name is sent to `cloudflare-dns.com` for the DNSSEC check.
