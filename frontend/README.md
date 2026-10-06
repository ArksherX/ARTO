# ARTO frontend

Production console for the ARTO suite (Tessera, Vestigia, VerityFlux). Replaces
the Streamlit dashboards **additively** — it ships alongside them, reaches parity
screen by screen, and the Streamlit UIs are retired only once it does.

It is a thin API client: it reads the existing REST APIs over the documented
OpenAPI contracts and changes no backend code, so it cannot break the suite.

## Stack

- Vite + React 18 + TypeScript
- Tailwind CSS (theme mapped to the ARTO design tokens in `src/index.css`,
  mirror of `../reviews_out/arto_design/tokens.css`)
- React Router (tab/screen navigation), TanStack Query (data)
- `openapi-fetch` + `openapi-typescript`: typed clients generated from
  `../docs/openapi/{tessera,vestigia,verityflux}.json`

## Run

```bash
pnpm install
pnpm gen:api     # generate typed clients from docs/openapi (gitignored output)
pnpm dev         # http://localhost:5173
pnpm build       # tsc --noEmit && vite build -> dist/
```

### Live data in dev

The API endpoints require auth. For local dev the Vite proxy attaches each
service's API key (read from the shell env, never bundled into the client), so
the app sees live data:

```bash
VERITYFLUX_API_KEY=<key> TESSERA_API_KEY=<key> VESTIGIA_API_KEY=<key> pnpm dev
```

Without a key, requests 401 and each section falls back to sample data and is
tagged `sample`. In production the browser sends the signed-in user's bearer
token instead (auth increment).

In dev, the app calls `/api/<service>/...` and Vite proxies to the local
services (Tessera 8001, Vestigia 8002, VerityFlux 8003) so the browser makes no
cross-origin request. Override targets with `TESSERA_API_BASE` etc. In
production set `VITE_*_API_BASE` (see `.env.example`) to the deployed hosts and
add the frontend origin to `VERITYFLUX_ALLOWED_ORIGINS`.

## Status — increment 1 (this commit)

Foundation only, builds green:
- App shell: top bar, primary nav, persisted dark/light theme toggle, routing
  across Overview / Tessera / Vestigia / VerityFlux.
- Design tokens + a small component layer (`Card`, `Kpi`, `Chip`, `PageHeader`).
- Overview renders KPI + pillar cards from **sample data**; the three pillar
  pages are scaffolded placeholders.
- Typed API clients wired and ready in `src/lib/api.ts` (not yet called).

## Deploy (additive — runs alongside Streamlit)

The app is a static SPA served by nginx, which also proxies `/api/<service>` to
each backend. It is a new container + ingress route; it changes no backend code
and no existing ingress, so it can run beside the Streamlit dashboards until it
reaches parity, then they are retired.

```bash
# build (context = repo root, so docs/openapi is available to gen:api)
docker build -f frontend/Dockerfile -t arto-console .

# run locally (point at your backends)
docker run -p 8080:80 \
  -e TESSERA_UPSTREAM=http://host.docker.internal:8001 \
  -e VESTIGIA_UPSTREAM=http://host.docker.internal:8002 \
  -e VERITYFLUX_UPSTREAM=http://host.docker.internal:8003 \
  arto-console   # open http://localhost:8080
```

Kubernetes: `frontend/deploy/k8s/console.yaml` (Deployment + Service + Ingress).
Set the image, the three `*_UPSTREAM` Service DNS names, and the host/cert-issuer,
then `kubectl apply -f`. In production set `VITE_REQUIRE_LOGIN=true` at build time
once the backend auth below is in place.

### Backend dependencies (to finish the picture)

Two backend items unblock the last mile — tracked in
`reviews_out/ARTO_Remediation_Backlog.md`:

1. **Unified user auth.** `/auth/login` returns a placeholder token and the three
   services use different schemes (VerityFlux X-API-Key/JWT, Vestigia Bearer,
   Tessera none). Real user login needs a shared JWT all three accept, or a
   gateway/BFF that terminates user auth. The frontend auth layer is ready for it.
2. **Read endpoints for the still-sample sections.** VerityFlux detection stream
   (a list of recent scored inputs — `soc/events` is empty), and Tessera delegation
   detail / token-posture / live approvals. Vestigia is already fully live.

## Next increments

2. Wire Overview to live data (posture KPIs, pillar summaries) via TanStack Query.
3. VerityFlux runtime screen: detection stream, trajectory, intent mix, review queue.
4. Vestigia ledger screen: hash-chain, event ledger, integrity panel.
5. Tessera screen: delegation chain, agent registry, dual-control approvals.
6. Auth (bearer/JWT + API key), loading/empty/error states, mobile pass.
7. Dockerfile + ingress route (new service, alongside Streamlit), then retire Streamlit.

The static visual reference for screens 3–5 is the design prototype built in this
work; port those into real components here.
