# Deploy: Cloudflare Pages (UI + proxy) + Render (Node backend)

```
Browser -> Cloudflare Pages (static UI, _headers CSP)
              |  /api/*  (Pages Function: functions/api/[[path]].js)
              v  adds x-headerscan-key + real client IP
           Render free web service (Docker, server.js)  -> scans targets
```
Why split: the scanner needs `node:tls` / `node:dns` / raw sockets, which Workers/Pages don't provide. Full 138 checks stay intact.

## 1. Backend (Render, free)
1. Render -> New -> Blueprint -> pick this private repo (`render.yaml`).
2. Set env `HEADERSCAN_PROXY_KEY` to a long random string (e.g. `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`).
   `HEADERSCAN_SECRET` is generated once and persists (needed so ownership tokens survive restarts).
3. Copy the service URL, e.g. `https://header-scan-backend.onrender.com`.
Free tier sleeps after ~15 min idle: the first scan after a pause can take 30-60 s (the proxy returns 502 `BACKEND_UNREACHABLE`; retry).

## 2. Frontend (Cloudflare Pages, free)
```bash
npm run build                                   # dist/ + _headers with the CSP hash (copies the committed public/index.html)
npx wrangler login
npx wrangler pages project create header-scan --production-branch main
npx wrangler pages secret put BACKEND_URL --project-name header-scan     # the Render URL
npx wrangler pages secret put PROXY_KEY   --project-name header-scan     # same value as HEADERSCAN_PROXY_KEY
npm run deploy
```
Or connect the GitHub repo in the Cloudflare dashboard: build command `npm run build`, output `dist`, add the two secrets.

The UI is generated from `ui/src/` by `npm run build:ui`; `public/index.html` is committed, so deploying does not need that step. Run `npm run build:ui` and commit the result after changing `ui/src/`.

## 3. Check
- `https://<project>.pages.dev` loads and scans work.
- `curl https://<render-url>/api/scan?url=https://example.com` -> 403 (backend only answers via the proxy; `/api/health` stays open).
- Scan your own site with it: it should grade well.

## Limits / notes
- Rate limit is in memory per instance (per real client IP via the proxy). Add Cloudflare WAF rate-limiting rule on `/api/*` for public use.
- Never enable `HEADERSCAN_ALLOW_PRIVATE` in production (tests only).
