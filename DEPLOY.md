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
Free tier sleeps after ~15 min idle: the first scan after a pause can take 30-60 s (the proxy returns 502 `BACKEND_UNREACHABLE`; retry).

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
- Rate limit is in memory per instance (per real client IP via the proxy). Add Cloudflare WAF rate-limiting rule on `/api/*` for public use.
- Never enable `HEADERSCAN_ALLOW_PRIVATE` in production (tests only).
