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

## Next increments

2. Wire Overview to live data (posture KPIs, pillar summaries) via TanStack Query.
3. VerityFlux runtime screen: detection stream, trajectory, intent mix, review queue.
4. Vestigia ledger screen: hash-chain, event ledger, integrity panel.
5. Tessera screen: delegation chain, agent registry, dual-control approvals.
6. Auth (bearer/JWT + API key), loading/empty/error states, mobile pass.
7. Dockerfile + ingress route (new service, alongside Streamlit), then retire Streamlit.

The static visual reference for screens 3–5 is the design prototype built in this
work; port those into real components here.
