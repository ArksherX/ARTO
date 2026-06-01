# ARTO Security Framework

Local-first security suite for agentic AI systems, composed of:
- **Tessera** — identity & access control (JWT/DPoP, revocation, RBAC/SSO)
- **Vestigia** — tamper‑evident audit & forensics (ledger, SIEM/OTel)
- **VerityFlux v2** — verification/scanning (OWASP-style detectors, policy validation, runtime firewall)

Supports **standalone runs**, **opt-in integration**, and a **local Docker Compose stack**.

The Streamlit UIs share a small repo-level theme package in `shared/`. Keep the repo layout intact when running one tool locally; do not copy a tool subdirectory by itself unless you also copy `shared/`.

---

## Clone And Install

```bash
git clone https://github.com/ArksherX/ARTO.git
cd ARTO
python3 -m venv venv
source venv/bin/activate
pip install -r tessera/requirements.txt -r vestigia/requirements.txt -r verityflux-v2/requirements.txt
```

If your platform uses `python` instead of `python3`, substitute accordingly.

---

## Launch The Full Suite (Local)

```bash
./launch_suite.sh
```

This starts all APIs + UIs on their dedicated ports.

Default local ports:
- Tessera UI: **8501** | API: **8001**
- Vestigia UI: **8502** | API: **8002**
- VerityFlux UI: **8503** | API: **8003**

Stop everything:

```bash
./stop_suite.sh
```

Clean demo state before recording or evaluation:

```bash
./scripts/reset_demo_state.sh
./launch_suite.sh
```

`reset_demo_state.sh` archives local runtime state under `run/demo_state_archives/<timestamp>/` before recreating clean runtime directories.

---
## Deployment Modes

  The suite can be deployed as:

  - Standalone: run Tessera, Vestigia, or VerityFlux independently.
  - Paired: combine two tools for identity + evidence, runtime + evidence, or identity + runtime.
  - Full Suite: run all three for identity, enforcement, and evidence continuity.

  Standalone usage is supported, but the full suite provides the strongest control loop:
  Tessera -> VerityFlux -> Vestigia
  identity -> enforcement -> evidence.

## Run One Tool Locally

Run each tool from the repo root in separate terminals when you want only one component.

### Tessera Only
```bash
source venv/bin/activate
cd tessera
python api_server.py
python -m streamlit run web_ui/tessera_dashboard.py --server.port 8501
```

### Vestigia Only
```bash
source venv/bin/activate
cd vestigia
python api_server.py
python -m streamlit run dashboard.py --server.port 8502
```

### VerityFlux Only
```bash
source venv/bin/activate
cd verityflux-v2
PYTHONPATH="$PWD" python api/v2/main.py
python -m streamlit run ui/streamlit/app.py --server.port 8503
```

For standalone mode without cross-tool forwarding, set:

```bash
export MLRT_INTEGRATION_ENABLED=false
```

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

Single tool examples:
```bash
# Tessera API only
docker compose -f docker-compose.suite.yml up tessera-api

# Vestigia API + UI
docker compose -f docker-compose.suite.yml --profile ui up vestigia-api vestigia-ui

# VerityFlux API + UI
docker compose -f docker-compose.suite.yml --profile ui up verityflux-api verityflux-ui
```

The UI services mount `./shared:/shared:ro` and set `PYTHONPATH=/` so the shared open-source theme is available inside containers.

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
- See `ops/hardening_playbook.md` for hardening guidance.

---

## Integration Hooks (Opt‑In)

Integration hooks forward contract events to Vestigia.
`launch_suite.sh` enables them by default for local full-suite runs, but standalone mode remains available and you can disable forwarding explicitly with `MLRT_INTEGRATION_ENABLED=false`.
Configure with environment variables:

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

# 1. Functional plumbing (68 tests) — do APIs respond correctly?
python test_suite_complete.py

# 2. Adversarial efficacy (42 tests) — do security detections catch real attacks?
python test_adversarial_efficacy.py

# 3. E2E scenarios (28 steps) — do cross-service workflows work end-to-end?
python test_e2e_scenarios.py
```

| Script | What It Validates | Sections |
|--------|------------------|----------|
| `test_suite_complete.py` | API plumbing across all 3 services, including A2A reasoning contamination, protocol-integrity enforcement, and cross-agent memory-poisoning checks | 12 sections (A-L), 68 tests |
| `test_adversarial_efficacy.py` | Prompt injection, tool call blocking, A2A reasoning contamination, protocol integrity, reasoning interception, memory poisoning, cross-agent memory poisoning, session drift, scanner detection, LLM adapter connectivity | 8 sections (A-H), 42 tests |
| `test_e2e_scenarios.py` | Legitimate agent workflow, attack detection & containment, delegation chain security, cross-service resilience | 4 scenarios, 28 steps |

### Legacy Checks

Smoke test:
```bash
python integration_smoke_test.py
```

Integration test plan:
- `test_e2e_scenarios.py` (scenarios are documented inline)

---

## Ops & Hardening

Playbooks:
- `ops/hardening_playbook.md`
- `ops/production_env_checklist.md`

---

## CI Workflow

A GitHub Actions workflow runs the test pyramid and suite smoke checks:
- `.github/workflows/suite-ci.yml`

Local equivalent:

```bash
venv/bin/pytest -q tests/smoke tests/integration tests/regression tests/ui tests/e2e
```

---

## Common Issues

**Tessera fails with short secret key**
- Ensure `TESSERA_SECRET_KEY` is ≥ 64 bytes (512‑bit).
- If your shell has a stale key exported, `unset TESSERA_SECRET_KEY` before running.

**Tessera prod crashes due to SAML dependency**
- SAML is optional. If you need SAML, install `python3-saml`.

**Vestigia opens in a tamper or lockdown state during demos**
- Old local runtime ledgers or prior tamper tests can cause this.
- Run `./scripts/reset_demo_state.sh` before `./launch_suite.sh` for a clean demo slate.

**Cognitive Firewall Activity is empty**
- This is expected until reasoning interception, tool-call interception, or policy evaluation runs.
- Agent onboarding alone does not create firewall decisions.

---

## Repo Index
- `tessera/` — IAM + access control
- `vestigia/` — audit + forensics
- `verityflux-v2/` — verification/scanning
- `ops/` — AIVSS tools + hardening playbook
- `shared/` — shared Streamlit theme tokens for the three UIs
- `scripts/reset_demo_state.sh` — archive-first local demo reset
- `integration_contract.md` — contract schema
- `USE_CASE_GUIDE.md` — operator workflows and component usage patterns

---

## Status & Roadmap
- Standalone: **working**
- Integration: **working** (`launch_suite.sh` defaults it on; override with `MLRT_INTEGRATION_ENABLED=false`)
- CI smoke tests: **working**
- VerityFlux real scanning: **working** (20 core detectors query live LLMs; 3 fuzz + 4 MCP detectors available via scan flags)
- VerityFlux protocol integrity enforcement: **working** (schema drift, field smuggling, contract desync, multi-hop trust collapse via live API + UI)
- VerityFlux A2A reasoning contamination detection: **working** (inherited handoff reasoning flagged before execution, with Vestigia evidence correlation)
- VerityFlux cross-agent working-memory poisoning coverage: **working** (shared-memory retrieval sanitization, alerting, and Vestigia evidence correlation)
- VerityFlux skill-layer AST10 assessment: **working** (`SKILL.md`, `skill.json`, `manifest.json`, `package.json` via UI + API, with Tessera/Vestigia control mapping)
- LLM adapter connectivity: **hardened** (timeouts for all providers, Ollama pre-flight, error diagnostics)
- Agent onboarding: **working** (single register, bulk upload, Tessera import, capability declarations)
- Runtime enforcement: **working** (reasoning interception, A2A handoff contamination checks, memory filtering, cross-agent memory poisoning alerts, adversarial scoring, session drift, protocol integrity)
- Open-source UI: **working** (shared hybrid forensic console theme across Tessera, Vestigia, and VerityFlux)
- Demo reset: **working** (archive-first reset for clean local recordings)
- Production deployment: **ready** (API key pipeline, scan_mode metadata, capability-based risk assessment)
- Test coverage: **3 suites** (68 functional + 42 adversarial efficacy + 28 E2E scenario steps) plus pytest smoke/integration/regression/UI/E2E coverage

---

## License
Apache-2.0. See `LICENSE`.

## Contributing
See `CONTRIBUTING.md`.

## Notice
See `NOTICE`.
