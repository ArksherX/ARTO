# ML-Redteam Security Suite

A local-first security suite for agentic AI systems in 2026, composed of:
- **Tessera** — identity & access control (JWT/DPoP, revocation, RBAC/SSO)
- **Vestigia** — tamper‑evident audit & forensics (ledger, SIEM/OTel)
- **VerityFlux v2** — verification/scanning (policy validation, firewall)

This repo supports **standalone runs**, **opt‑in integration**, and a **local Docker Compose stack**.

---

## Quick Start (Local Standalone)

### Tessera
```bash
cd /home/arksher/ml-redteam/tessera
streamlit run web_ui/tessera_dashboard.py
python api_server.py
```

### Vestigia
```bash
cd /home/arksher/ml-redteam/vestigia
streamlit run dashboard.py
python api_server.py
```

### VerityFlux v2
```bash
cd /home/arksher/ml-redteam/verityflux-v2
streamlit run ui/streamlit/app.py
python api/v2/main.py
```

Default ports (standalone):
- Tessera UI: **8501** | API: **8001**
- Vestigia UI: **8502** | API: **8002**
- VerityFlux UI: **8503** | API: **8003**

---

## Launch the Full Suite (Local)

```bash
/home/arksher/ml-redteam/launch_suite.sh
```

This starts all APIs + UIs on their dedicated ports.

---

## Docker Compose (Local Stack)

APIs only:
```bash
docker compose -f /home/arksher/ml-redteam/docker-compose.suite.yml up -d
```

APIs + UIs:
```bash
docker compose -f /home/arksher/ml-redteam/docker-compose.suite.yml --profile ui up -d
```

APIs + Ops stack (Prometheus/Grafana/Vector placeholders):
```bash
docker compose -f /home/arksher/ml-redteam/docker-compose.suite.yml --profile ops up -d
```

Local Docker host ports (current mapping):
- Tessera UI: **18501** | API: **18001**
- Vestigia UI: **18502** | API: **18002**
- VerityFlux UI: **18503** | API: **18003**
- Redis: **16379** → container **6379**

---

## Integration Hooks (Opt‑In)

Integration hooks forward contract events to Vestigia.
Enable with environment variables:

```bash
export MLRT_INTEGRATION_ENABLED=true
export MLRT_VESTIGIA_INGEST_URL=http://localhost:8002/events
export MLRT_VESTIGIA_API_KEY=dev-vestigia-key
```

Contract spec:
- `/home/arksher/ml-redteam/integration_contract.md`

---

## Testing & Reliability

Smoke test:
```bash
/home/arksher/ml-redteam/integration_smoke_test.py
```

Reliability check:
```bash
/home/arksher/ml-redteam/reliability_check.py
```

Integration test plan:
- `/home/arksher/ml-redteam/ops/integration_test_plan.md`

---

## Ops & Hardening

Playbooks:
- `/home/arksher/ml-redteam/ops/hardening_playbook.md`
- `/home/arksher/ml-redteam/ops/reliability_checks.md`

---

## CI Workflow

A GitHub Actions workflow spins up the local stack and runs the E2E smoke + reliability checks:
- `/home/arksher/ml-redteam/.github/workflows/suite-ci.yml`

---

## Common Issues

**Tessera fails with short secret key**
- Ensure `TESSERA_SECRET_KEY` is ≥ 64 bytes (512‑bit). The `.env` is already updated.
- If your shell has a stale key exported, `unset TESSERA_SECRET_KEY` before running.

**Tessera prod crashes due to SAML dependency**
- SAML is optional. If you need SAML, install `python3-saml`.

---

## Repo Index
- `tessera/` — IAM + access control
- `vestigia/` — audit + forensics
- `verityflux-v2/` — verification/scanning
- `ops/` — playbooks & ops configs
- `integration_contract.md` — contract schema
- `summary.md` — working status + ports

---

## Status & Roadmap
- Standalone: **working**
- Opt‑in integration: **working (event forwarding)**
- CI smoke tests: **working**
- Production deployment: **planned**

---

## License
Internal / private.
