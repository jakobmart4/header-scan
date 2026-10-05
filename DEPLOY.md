# Deploy: Cloudflare Worker with static assets (UI + proxy) + Render (Node backend)

```
Browser -> Cloudflare Worker (static UI from dist/, _headers CSP)
              |  /api/*  (worker/index.js, run_worker_first)
              v  adds x-headerscan-key + real client IP
           Render free web service (Docker, server.js)  -> scans targets
```
Why split: the scanner needs `node:tls` / `node:dns` / raw sockets, which Workers/Pages don't provide. All 144 checks stay intact.

Deploy order: Render first (the Worker needs its URL), then Cloudflare.

## 1. Backend (Render, free)
1. Render -> New -> Blueprint -> pick this private repo (`render.yaml`).
2. Set env `HEADERSCAN_PROXY_KEY` to a long random string (e.g. `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`).
   `HEADERSCAN_SECRET` is generated once and persists (needed so ownership tokens survive restarts).
3. Copy the service URL, e.g. `https://header-scan-backend.onrender.com`.
Free tier sleeps after ~15 min idle. Measured: the first request just waits (about 15 s, documented up to 60 s); it is not answered with a 502. If the host does answer 502/503/504 while waking, the Worker turns it into a JSON 502 `BACKEND_UNREACHABLE` with a "waking up, retry in about 30 seconds" message and `Retry-After: 30`.
With `HEADERSCAN_PROXY_KEY` set, the backend's own `/` is 404 (the UI is served by the Worker only), every `/api/*` route except `/api/health` answers 403 `FORBIDDEN` without the key, and `/api/health` stays open. The Dockerfile sets `HEADERSCAN_TRUST_PROXY=1` (rightmost `X-Forwarded-For` entry, Render's proxy) as the fallback client IP; behind the Worker the IP comes from `x-headerscan-client`.

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
- `/privacy`, `/samples/perfect.json` and `/samples/mixed.json` on the same host answer 200 (static assets from `dist/`), and the two "Sample reports" buttons in the UI open a report.
- `curl https://<render-url>/api/scan?url=https://example.com` -> 403 and `curl https://<render-url>/` -> 404 (backend only answers via the proxy; `/api/health` stays open).
- `curl -i http://header-scan.<your-subdomain>.workers.dev/api/health` -> 308 to `https://` (Worker-handled path).
- Scan your own site with it: it should grade well.

## Limits / notes
- Rate limit is in memory per instance (per real client IP via the proxy; IPv6 per /64), plus at most 2 running scans per client and 4 in total. **Known limit:** a /64 bucket does not stop someone who holds a /48 (65,536 /64 networks, each with its own quota), and once the map holds more than 50,000 keys a request with a new key gets 429 for 60 s. The real defence for public use is a Cloudflare WAF rate-limiting rule on `/api/*` (dashboard setting, not in this repo; paid, not used by the current deployment).
- **Known limit:** `/privacy` and `/samples/*.json` (the sample reports behind the UI's "Sample reports" buttons) are static assets of the Worker deployment. The standalone `server.js` serves only `/` and the API (`other public files -> 404`), so a local `npm start` has a dead footer Privacy link and failing sample buttons (`test/api.test.js` pins "other public files -> 404").
- The Worker sets the security headers on every response it produces itself (proxied `/api/*` answers, its JSON errors and the 308); `dist/_headers` covers static files only. Plain `http://` gets a 308 to `https://` on Worker-handled paths only (`/api/*` and paths without a static file).
- **Known limit:** static assets (`/`, `/privacy`, ...) are served by the platform and are NOT redirected from `http://`, because the Worker does not run for them (`run_worker_first = ["/api/*"]`). Acceptable because the `.dev` TLD is HSTS-preloaded, so browsers never send plain HTTP to `workers.dev`; on a custom domain use "Always Use HTTPS".
- No `security.txt` is published on purpose (it needs a contact address and the owner publishes no personal data); `test/static-pages.test.js` guards this. The privacy page (`public/privacy.html`) must stay in line with `server.js` and `worker/index.js`; re-read it when logging, storage or third-party calls change.
- Paths without a static file fall through to the Worker, which answers a JSON 404 (now with the security headers). `assets.not_found_handling = "404-page"` would serve a static 404 page instead (not enabled).
- Never enable `HEADERSCAN_ALLOW_PRIVATE` in production (tests only).
