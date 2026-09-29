# Brief D: composio-skills relevance scan

## 0. Key finding
All ~830 dirs in composio-skills contain ONE file (SKILL.md, ~91 lines) generated from the same template
("Automate X via Rube MCP (Composio)": RUBE_SEARCH_TOOLS -> RUBE_MANAGE_CONNECTIONS -> RUBE_MULTI_EXECUTE_TOOL).
Verified by diff against securitytrails-automation: only the toolkit name/slug differs.
They contain NO check definitions, data fields, endpoints or thresholds, and each needs Rube MCP + a third-party
account. Direct reuse = none. Value = only the category names of data those services sell (section 3), which we
re-implement keyless with plain Node. Items marked (inferred) come from general knowledge of those services, not from the files.

## 1. Skills read / matched (C:\Skills\Powers\awesome-codex-skills\composio-skills\<dir>\SKILL.md)
Read fully: securitytrails-automation. Diffed against template (identical apart from names): virustotal-automation,
dnsfilter-automation, nextdns-automation, ravenseotools-automation, sslmate-cert-spotter-api-automation, ip2whois-automation,
abuselpdb-automation, builtwith-automation, cloudflare-automation, mx-toolbox-automation, digicert-automation,
similarweb-digitalrank-api-automation.
Matched by name, not opened (same template): cloudflare-api-key, cloudflare-browser-rendering, dock-certs, hunter,
ip2location(-io), ip2proxy, ipdata-co, ipinfo-io, emailable, mailcheck, neverbounce, zerobounce, firecrawl, scrapingant,
scrapingbee, scrapfly, scrape-do, webscraping-ai, screenshotone, screenshot-fyi, uptimerobot, simple-analytics, brandfetch,
similarweb_digitalrank_api (dup), identitycheck.
Not present: urlscan, shodan, censys, wappalyzer, pagespeed, godaddy, namecheap.
False hits (irrelevant): certifier, accredible-certificates (credentials, not TLS), baselinker, datarobot, passslot, payhip.

## 2. Rules / patterns worth copying (from the template, adapted)
- "Discover before execute": checks are self-describing objects {id, title, severity, run(ctx)} in one array; UI renders whatever returns.
- Pagination note: apply to our sitemap index -> child sitemaps crawl, with hard caps.
- Session reuse: ONE shared fetch context per scan (resolved IP, homepage response, robots.txt, parsed HTML); checks never refetch.
- Bulk exec: independent checks via Promise.allSettled; a failing check yields {status:"error"}, never aborts the scan.
- Uniform result: {id, status: pass|warn|fail|info|skip|error, evidence (short), fix (one line)}.
- "Connection must be ACTIVE" precondition -> our analogue: DNS TXT ownership gate before any active probe.

## 3. Check ideas (plain Node, no API keys)
DNS / domain (securitytrails, ip2whois, mx-toolbox, nextdns categories; inferred):
- A/AAAA/CNAME/NS/MX/TXT via node:dns; NS >= 2; MX present; dangling CNAME (NXDOMAIN target) = takeover risk.
- CAA present with issuer; SPF single record, ends -all/~all, <=10 lookups, no +all/?all; DMARC at _dmarc (p=, rua, pct);
  DKIM common selectors (default, google, selector1/2, k1) info only; MTA-STS (_mta-sts TXT + https://mta-sts.<d>/.well-known/mta-sts.txt);
  TLS-RPT (_smtp._tls).
- DNSSEC: node:dns has no DS resolver -> DoH JSON (dns.google/resolve, cloudflare-dns.com/dns-query), read the AD flag; fixed hosts only.
- Domain expiry/registrar lock via RDAP (rdap.org bootstrap, keyless; replaces ip2whois): expiry < 30 d warn, clientTransferProhibited.
- PTR of resolved IP; IPv6 (AAAA answers).
TLS / certs (sslmate cert spotter, digicert; inferred):
- tls.connect + getPeerCertificate(true): days to expiry (warn <30, fail <7), issuer, SAN covers host, chain/self-signed (authorizationError),
  key type/size (RSA>=2048 / EC), no SHA-1 signature, negotiated protocol, TLS 1.0/1.1 accepted = fail, TLS 1.3 = pass, ALPN h2.
- HTTP->HTTPS redirect, HSTS (max-age >= 31536000, includeSubDomains, preload), www vs apex cert match.
- Optional CT subdomain list via crt.sh?q=%25.domain&output=json (keyless but flaky: short timeout, row cap, skip on failure).
Web/app layer (builtwith, similarweb, ravenseotools categories; inferred):
- Security headers (CSP parsed, XFO/frame-ancestors, XCTO, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP), cookie flags,
  CORS (Origin: https://evil.example -> ACAO reflected or * with credentials), mixed content, SRI on third-party assets, security.txt (Contact, Expires).
- Tech fingerprint from Server / X-Powered-By / meta generator / script paths (info, advise hiding versions). Own tiny signature list.
- SEO/AI: robots.txt (exists, Sitemap: line, not blocking all, GPTBot/ClaudeBot/PerplexityBot/Google-Extended policy), sitemap.xml (valid, <50k urls, lastmod),
  title 30-60, meta description 70-160, canonical, single h1, lang, viewport, OG/Twitter, JSON-LD parses, hreflang, img alt ratio,
  noindex header vs meta, llms.txt (info), favicon, soft-404 (random path must return 404).
- Perf hygiene (headers only): br/gzip, Cache-Control on static, TTFB, HTML weight.
Reputation (virustotal, abuseipdb, urlscan categories): NOT keyless -> skip, or show plain "check externally" links; no API calls.
Active probes (owner-verified only): /.git/HEAD ("ref:" signature), /.env (KEY=VALUE pattern), /.DS_Store, backup.zip|sql|tar.gz,
wp-config.php.bak, /server-status, /phpinfo.php, /admin, directory listing ("Index of"). Record status + Content-Type + signature match only;
discard the body immediately; never echo it.

## 4. Pitfalls
- The composio skills are empty templates, not a spec; do not depend on Rube MCP or vendor names in shipped code/UI.
- SSRF: validate every hop. dns.lookup({all:true}); reject 127/8, 10/8, 172.16/12, 192.168/16, 169.254/16 (metadata 169.254.169.254),
  100.64/10, 0.0.0.0/8, 224/4, ::1, fc00::/7, fe80::/10, ::ffff:v4-mapped and 64:ff9b::/96 (map back to v4, re-check), odd IP literals
  (decimal/octal/hex). Connect to the pinned IP (custom lookup fn) with servername + Host set to defeat DNS rebinding.
  Re-validate per redirect (max 5), http/https only, ports 80/443 only.
- DoH/RDAP/crt.sh hostnames are fixed constants, never user-derived, and still go through the guard.
- Limits: 10 s per request, 1-2 MB body cap (destroy the stream), global concurrency ~4, per-client rate limit on the scanner, identifying User-Agent.
- Ownership gate: TXT at _headerscan.<domain> with per-session token = crypto.randomBytes(16).toString("hex"), never derived from the domain;
  verify the registrable domain, not a subdomain of shared hosts (vercel.app, github.io, etc.: keep a small deny-list, no full PSL); short cache TTL.
- dns errors: ENODATA/ENOTFOUND mean "record absent" (a result); ETIMEOUT/ESERVFAIL = "error", not "fail".
- SPF lookup counting must follow include/redirect recursively with depth and loop guards.
- CSP: split on ";", first token = directive; script-src falls back to default-src; 'unsafe-inline' only counts when no nonce/hash/'strict-dynamic';
  Report-Only is not enforcement; multiple CSP headers intersect.
- Cookies: use res.headers["set-cookie"] (array); __Host-/__Secure- prefix rules; warn on missing SameSite.
- TLS: rejectUnauthorized:false ONLY on the cert-inspection socket, never for content you then trust. Cert dates are strings (Date.parse).
  OpenSSL 3 may refuse TLS 1.0/1.1 client-side: report "could not test", not "pass".
- Secret files: SPA/CDN catch-alls return 200 + HTML for any path; require signature match and non-HTML Content-Type, compare with a random-path baseline.
- Scanned data is attacker-controlled (titles, cookie names, headers): render with textContent only, never innerHTML.
- Tests: inject resolver/socket functions into the guard so node:test runs offline. Windows: use py, stop any dev server, never port 34872.
