# ML-Redteam Security Suite

Local-first security suite for agentic AI systems, composed of:
- **Tessera** — identity & access control (JWT/DPoP, revocation, RBAC/SSO)
- **Vestigia** — tamper‑evident audit & forensics (ledger, SIEM/OTel)
- **VerityFlux v2** — verification/scanning (OWASP-style detectors, policy validation, runtime firewall)

Supports **standalone runs**, **opt‑in integration**, and a **local Docker Compose stack**.

---

## Quick Start (Local Standalone)

### Tessera
```bash
cd tessera
streamlit run web_ui/tessera_dashboard.py
python api_server.py
```

### Vestigia
```bash
cd ../vestigia
streamlit run dashboard.py
python api_server.py
```

### VerityFlux v2
```bash
cd ../verityflux-v2
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
./launch_suite.sh
```

This starts all APIs + UIs on their dedicated ports.

---

## Docker Compose (Local Stack)

APIs only:
```bash
docker compose -f docker-compose.suite.yml up -d
```

APIs + UIs:
```bash
docker compose -f docker-compose.suite.yml --profile ui up -d
```

APIs + Ops stack (Prometheus/Grafana/Vector placeholders):
```bash
docker compose -f docker-compose.suite.yml --profile ops up -d
```

Local Docker host ports (current mapping):
- Tessera UI: **18501** | API: **18001**
- Vestigia UI: **18502** | API: **18002**
- VerityFlux UI: **18503** | API: **18003**
- Redis: **16379** → container **6379**

---

## Production Notes (HA + Secrets)

- Rotate all default secrets; set `TESSERA_SECRET_KEY`, `VERITYFLUX_API_KEY`, and `VESTIGIA_API_KEY` via a secret store.
- Run multiple API instances behind a reverse proxy; use shared Redis for rate limits and replay caches.
- Persist audit logs to durable storage; set `TESSERA_AUDIT_RETENTION_DAYS` and export via `/audit/export`.
- Enforce TLS and restrict ingress to internal networks where possible.
- See `ops/secrets_env.md` and `ops/hardening_playbook.md` for full env + hardening guidance.

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
- `integration_contract.md`

---

## Testing & Validation

### Full Test Suites (recommended)

```bash
# Start all services first
./launch_suite.sh

# 1. Functional plumbing (61 tests) — do APIs respond correctly?
python test_suite_complete.py

# 2. Adversarial efficacy (38 tests) — do security detections catch real attacks?
python test_adversarial_efficacy.py

# 3. E2E scenarios (28 steps) — do cross-service workflows work end-to-end?
python test_e2e_scenarios.py
```

| Script | What It Validates | Sections |
|--------|------------------|----------|
| `test_suite_complete.py` | API plumbing across all 3 services | 12 sections (A-L), 61 tests |
| `test_adversarial_efficacy.py` | Prompt injection, tool call blocking, reasoning interception, memory poisoning, session drift, scanner detection, LLM adapter connectivity | 8 sections (A-H), 38 tests |
| `test_e2e_scenarios.py` | Legitimate agent workflow, attack detection & containment, delegation chain security, cross-service resilience | 4 scenarios, 28 steps |

### Legacy Checks

Smoke test:
```bash
python integration_smoke_test.py
```

Reliability check:
```bash
python reliability_check.py
```

Failure-mode deterministic check:
```bash
EXPECT_DOWN=vestigia python ops/failure_mode_e2e.py
```

SLO report for a sandbox run:
```bash
RUN_ID=<run_id> python ops/soak_slo_report.py
```

Integration test plan:
- `ops/integration_test_plan.md`

---

## Ops & Hardening

Playbooks:
- `ops/hardening_playbook.md`
- `ops/reliability_checks.md`
- `ops/blackhat_submission_pack.md`
- `ops/production_readiness_gate.md`
- `ops/commercial_packaging_outline.md`
- `preflight_check.py` (called by `launch_suite.sh` before startup)

---

## CI Workflow

A GitHub Actions workflow spins up the local stack and runs the E2E smoke + reliability checks:
- `.github/workflows/suite-ci.yml`

---

## Common Issues

**Tessera fails with short secret key**
- Ensure `TESSERA_SECRET_KEY` is ≥ 64 bytes (512‑bit).
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
- VerityFlux real scanning: **working** (all 20 detectors query live LLMs, no simulated data)
- LLM adapter connectivity: **hardened** (timeouts for all providers, Ollama pre-flight, error diagnostics)
- Agent onboarding: **working** (single register, bulk upload, Tessera import, capability declarations)
- Runtime enforcement: **working** (reasoning interception, memory filtering, adversarial scoring, session drift)
- Production deployment: **ready** (API key pipeline, scan_mode metadata, capability-based risk assessment)
- Test coverage: **3 suites** (61 functional + 38 adversarial efficacy + 28 E2E scenario steps)

---

## License
Apache-2.0. See `LICENSE`.

## Contributing
See `CONTRIBUTING.md`.

## Notice
See `NOTICE`.
