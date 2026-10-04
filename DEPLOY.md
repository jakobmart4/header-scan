# Deploy: Cloudflare Worker with static assets (UI + proxy) + Render (Node backend)

```
Browser -> Cloudflare Worker (static UI from dist/, _headers CSP)
              |  /api/*  (worker/index.js, run_worker_first)
              v  adds x-headerscan-key + real client IP
           Render free web service (Docker, server.js)  -> scans targets
```
Why split: the scanner needs `node:tls` / `node:dns` / raw sockets, which Workers/Pages don't provide. All 144 checks stay intact.

## 1. Backend (Render, free)
1. Render -> New -> Blueprint -> pick this private repo (`render.yaml`).
2. Set env `HEADERSCAN_PROXY_KEY` to a long random string (e.g. `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`).
   `HEADERSCAN_SECRET` is generated once and persists (needed so ownership tokens survive restarts).
3. Copy the service URL, e.g. `https://header-scan-backend.onrender.com`.
Free tier sleeps after ~15 min idle. Measured: the first request just waits (about 15 s, documented up to 60 s); it is not answered with a 502. If the host does answer 502/503/504 while waking, the Worker turns it into a JSON 502 `BACKEND_UNREACHABLE` with a "waking up, retry in about 30 seconds" message and `Retry-After: 30`.
With `HEADERSCAN_PROXY_KEY` set, the backend's own `/` is 404 (the UI is served by the Worker only); `/api/health` stays open.

## 2. Frontend (Cloudflare Workers Builds, free)
Dashboard -> Workers & Pages -> Create -> Import a repository -> this repo:
- Project name `header-scan`, path `/`
- Build command `npm run build`, deploy command `npx wrangler deploy` (config is in `wrangler.toml`)
- Leave "Protect with Cloudflare Access" off (public tool)
After the first deploy: Settings -> Variables and Secrets -> add secrets `BACKEND_URL` (the Render URL) and `PROXY_KEY` (same value as `HEADERSCAN_PROXY_KEY`).
Until they are set, `/api/*` answers 500 MISCONFIGURED (the UI itself already loads).
CLI alternative: `npx wrangler login && npm run deploy`, then `npx wrangler secret put BACKEND_URL` / `PROXY_KEY`.

## 3. Check
- `https://header-scan.<your-subdomain>.workers.dev` loads and scans work.
- `curl https://<render-url>/api/scan?url=https://example.com` -> 403 (backend only answers via the proxy; `/api/health` stays open).
- Scan your own site with it: it should grade well.

## Limits / notes
- Rate limit is in memory per instance (per real client IP via the proxy; IPv6 per /64), plus at most 2 running scans per client and 4 in total. Add a Cloudflare WAF rate-limiting rule on `/api/*` for public use (dashboard, not in this repo).
- The Worker sets the security headers on every `/api/*` and error response itself (`_headers` only covers static files) and redirects plain HTTP to HTTPS (308). Static assets over `http://` on workers.dev are not redirected (the Worker only runs for `/api/*`); the `.dev` TLD is HSTS-preloaded, or use a custom domain with "Always Use HTTPS".
- Paths without a static file fall through to the Worker, which answers a JSON 404 (now with the security headers). `assets.not_found_handling = "404-page"` would serve a static 404 page instead (not enabled).
- Never enable `HEADERSCAN_ALLOW_PRIVATE` in production (tests only).
