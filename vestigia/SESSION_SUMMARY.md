# Vestigia — Session Summary & Project Status

> **Last updated:** 2026-02-08
> **Purpose:** Reference this file at the start of a new Claude session to restore full context.

---

## What Is Vestigia?

An **AI agent forensic audit system** — a tamper-evident ledger that records every action AI agents take (tool calls, token issuance, security scans, access requests). Think blockchain-style hash chains for AI accountability. The system provides:

- Append-only SHA-256 hash-chained event ledger
- Real-time monitoring, PII scrubbing, SIEM integration
- Compliance reporting (GDPR/CCPA), risk scoring
- Full observability stack (Prometheus, Grafana, Jaeger, AlertManager)

---

## Current Status: Phases 1–5 COMPLETE | Phase 6 In Progress

| Phase | Status | Description |
|-------|--------|-------------|
| Phase 1 | DONE | Core ledger engine, validator, verifier, dashboard, watchtower, CLI |
| Phase 2 | DONE | OTel tracing, SIEM forwarder, PII classification, cost manager, enrichment |
| Phase 3 | DONE | FastAPI server, PostgreSQL backend, Docker (15 services), configs, tests |
| Phase 4 | DONE | Advanced ML threat detection, behavioral analytics, anomaly detection |
| Phase 5 | DONE | Intelligence & automation: anomaly models, NL query, playbooks, risk forecasting |
| Phase 6 | IN PROGRESS | SaaS multi-tenancy, managed infra, developer ecosystem |

**Test suite: 135 tests, all passing** (as of last run).

---

## What Was Done (Chronological)

### Session 1 — Audit & Gap Analysis

**Starting state:** Documentation (`claude.md`) claimed 91% readiness across Phases 1–3. Reality was ~35–40%.

**Findings:**
- Phase 1 core (ledger engine, validator, dashboard, watchtower) was functional
- Phase 2 was **entirely missing** (all 5 modules)
- Phase 3 was **mostly missing** (no API server, no PostgreSQL, minimal Docker, no configs, no tests)
- **Critical bug:** `security/verifier.py` used a different hash format than `core/ledger_engine.py`, causing false tampering alerts
- Legacy duplicate file `vestigia_core.py` with incompatible hash format

### Session 1 — Full Implementation

After the audit, user instructed: *"proceed with doing all that's necessary to meet 100% readiness."*

#### Bugs Fixed
1. **Hash incompatibility** (`security/verifier.py`): Rewrote `_recalculate_hash` to match `ledger_engine.py`'s field-by-field canonical JSON format
2. **Witness format mismatch**: Made `_load_witness` handle both JSON and plain-text witness files
3. **Deleted legacy files**: `vestigia_core.py`, `fix_all_issues.py`, `fix_dashboard.py`, `fix_ledger.py`, `fix_vestigia.py`

#### Files Created — Phase 2 Modules
| File | What It Does |
|------|-------------|
| `core/otel_integration.py` | OpenTelemetry distributed tracing, W3C context propagation, `@traced` decorator, graceful degradation if OTel not installed |
| `core/resilient_siem_forwarder.py` | SQLite persistent queue, circuit breaker, exponential backoff, token bucket rate limiter, DLQ, Splunk/ES/Datadog/Syslog formatters |
| `core/data_classification.py` | PII detection (email, phone, SSN, credit card, API key, IPv4/IPv6, JWT), Luhn validation, GDPR/CCPA scrubbing |
| `core/cost_manager.py` | Severity-based sampling (CRITICAL:100%, WARNING:50%, INFO:10%, DEBUG:1%), budget tracking, cost projection |
| `core/enrichment_service.py` | GeoIP lookup, IOC matching, historical actor context, risk scoring, SIEM webhook handling, event correlation |

#### Files Created — Phase 3 Infrastructure
| File | What It Does |
|------|-------------|
| `api_server.py` | FastAPI, 9 endpoints (POST/GET events, batch, health, integrity, statistics, SIEM webhook), Bearer auth, CORS, rate limiting |
| `core/postgres_ledger.py` | PostgreSQL backend with psycopg2 connection pooling, same interface as VestigiaLedger |
| `sql/schema.sql` | PostgreSQL schema: vestigia_events (UUID PK, hash chain, JSONB evidence), witness_anchors, access_log, append-only trigger |
| `sql/phase2-migrations.sql` | Adds data_classification, pii_scrubbed, sampling_decision columns; siem_forward_queue, dead_letter_queue, cost_budgets tables |
| `docker-compose.yml` | 15-service stack: PostgreSQL, API, Watchtower, Dashboard, Enrichment, OTel Collector, Prometheus, Grafana, AlertManager, Jaeger, Nginx, Redis, SIEM forwarder, backup |
| `Dockerfile.api` | Python 3.12-slim, uvicorn on port 8000 |
| `Dockerfile.watchtower` | Runs watchtower.py |
| `Dockerfile.dashboard` | Streamlit on port 8501 |
| `Dockerfile.enrichment` | Runs enrichment service |
| `config/prometheus.yml` | Scrape configs for all services |
| `config/alert-rules.yml` | 20+ Prometheus alert rules (critical/warning/infrastructure) |
| `config/alertmanager.yml` | Alert routing: PagerDuty (critical), Slack (warning), webhook (default) |
| `config/nginx/nginx.conf` | Reverse proxy, TLS, rate limiting, security headers, WebSocket for Streamlit |
| `config/otel-collector-config.yaml` | OTLP receivers, batch processor, Prometheus/Jaeger/logging exporters |
| `config/grafana/datasources/prometheus.yml` | Datasource: prometheus:9090 |
| `config/grafana/dashboards/vestigia-main.json` | 11-panel dashboard |
| `deploy.sh` | One-command deployment: prereq checks, SSL certs, secrets, docker compose up, health checks, DB migrations |
| `backup.sh` | PostgreSQL dump, JSON ledger copy, tar.gz compression, 30-day rotation |

#### Files Created — Test Suite (135 tests)
| File | Tests | Coverage |
|------|-------|----------|
| `tests/conftest.py` | — | Shared fixtures: tmp_ledger_dir, tmp_ledger_path, ledger, populated_ledger, validator, sample_event |
| `tests/test_ledger.py` | 16 | Init, append, hash chain integrity, tamper detection, queries, stats, export, concurrency, rotation |
| `tests/test_api.py` | 17 | All 9 endpoints, auth (no token / wrong token / correct token), rate limiting, batch ingest |
| `tests/test_tracing.py` | 18 | Span lifecycle, attributes, W3C inject/extract, event tracing, `@traced` decorator, no-op stubs |
| `tests/test_siem.py` | 22 | Circuit breaker states, token bucket, persistent queue CRUD, DLQ, forwarder queue/stats/start-stop/replay, severity mapping |
| `tests/test_pii.py` | 23 | Luhn, PII detection (7 types), classification levels, nested scan, scrubbing, GDPR auto-scrub, custom patterns, stats |
| `tests/test_enrichment.py` | 22 | Event enrichment, IOC detection, actor context, risk scoring, SIEM webhooks, correlation, GeoIP, helpers, lifecycle |
| `integration_tests.py` | 14 | 7 end-to-end suites: ledger→validator, enrichment→PII, tracing→ledger, concurrent stress (10 threads), full lifecycle, IOC enrichment, PII cascade |

### Session 2 — Phase 4 + Phase 5 Enhancements

#### Phase 4 (Strengthened)
| File | What It Does |
|------|-------------|
| `core/hsm_client.py` | HSM-backed signing with local fallback, key rotation hooks |
| `core/merkle_tree.py` | Merkle root construction for batch integrity |
| `core/blockchain_anchor.py` | External anchoring client (ledger hash anchoring) |
| `core/access_audit.py` | Access audit log + approval workflows |
| `replication/` | Replication scripts + runbook |
| `sql/phase4-migrations.sql` | DB migrations for anchors + access audits |

#### Phase 5 (In Progress)
| File | What It Does |
|------|-------------|
| `core/anomaly_detection.py` | Persistent baselines + risk scoring + feedback loop |
| `retrain_anomaly_baselines.py` | Background retraining loop for baselines |
| `sql/phase5-migrations.sql` | Anomaly baselines + feedback tables |
| `api_server.py` | Anomaly scoring on ingest, SIEM alert streaming, Prometheus metrics, `/metrics` endpoint |
| `dashboard.py` | SIEM Alerts tab + anomaly risk visibility |

---

## Key Technical Details

### Hash Chain Format (canonical)
```python
evidence_str = json.dumps(evidence, sort_keys=True, separators=(',', ':'))
payload = f"{timestamp}{actor_id}{action_type}{status}{evidence_str}{previous_hash}"
hash = hashlib.sha256(payload.encode()).hexdigest()
# Or HMAC if VESTIGIA_SECRET_SALT is set
```

### API Endpoints
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/events` | Yes | Ingest single event |
| GET | `/events` | Yes | Query with filters + pagination |
| GET | `/events/{id}` | Yes | Get single event by ID |
| POST | `/events/batch` | Yes | Batch ingest |
| GET | `/health` | No | Health check |
| GET | `/status` | No | Infrastructure status (ops) |
| GET | `/integrity` | Yes | Full forensic validation |
| GET | `/statistics` | Yes | Aggregate stats |
| POST | `/webhooks/siem` | Yes | SIEM alert webhook |
| GET | `/metrics` | Yes | Prometheus metrics export |
| POST | `/anomalies/score` | Yes | On-demand anomaly scoring |
| POST | `/anomalies/feedback` | Yes | Mark anomalies as benign |
| POST | `/tenants` | Platform admin | Create tenant + admin user + key |
| POST | `/tenants/{tenant_id}/users` | Yes | Create tenant user |
| POST | `/tenants/{tenant_id}/apikeys` | Yes | Create tenant API key |

### Known Gotcha
The global `rate_limiter` in `api_server.py` persists across TestClient instances. Test fixtures must reset it:
```python
api_server.rate_limiter = api_server.TokenBucket(rate=10.0, capacity=20.0)
```

---

## File Tree (key files only)

```
vestigia/
├── api_server.py              # FastAPI REST API (657 lines)
├── dashboard.py               # Streamlit UI (597 lines)
├── validator.py               # Hash chain validator (637 lines)
├── watchtower.py              # File monitoring daemon (537 lines)
├── integration_tests.py       # 14 end-to-end tests
├── deploy.sh                  # One-command deployment
├── backup.sh                  # Backup + rotation
├── requirements.txt           # All dependencies
├── docker-compose.yml         # 15-service stack
├── Dockerfile.api / .watchtower / .dashboard / .enrichment
├── core/
│   ├── ledger_engine.py       # Core hash-chain ledger (863 lines)
│   ├── postgres_ledger.py     # PostgreSQL backend (659 lines)
│   ├── anomaly_detection.py   # Persistent baselines + scoring + feedback
│   ├── anomaly_models.py      # Ensemble models (no external ML deps)
│   ├── feature_engineering.py # Feature extraction for anomalies
│   ├── nl_query.py            # Natural language query parser
│   ├── risk_forecasting.py    # Risk history + forecasting
│   ├── playbook_engine.py     # YAML playbooks + execution logging
│   ├── tenant_manager.py      # Multi-tenant SaaS core (tenants/users/keys)
│   ├── ops_health.py          # Ops health checks for status page
│   ├── otel_integration.py    # OpenTelemetry tracing (655 lines)
│   ├── resilient_siem_forwarder.py  # SIEM forwarding (891 lines)
│   ├── data_classification.py # PII detection & scrubbing
│   ├── cost_manager.py        # Sampling & budget tracking
│   └── enrichment_service.py  # GeoIP, IOC, risk scoring
│   ├── hsm_client.py          # HSM-backed signing
│   ├── merkle_tree.py         # Merkle roots for batch integrity
│   ├── blockchain_anchor.py   # External anchoring client
│   └── access_audit.py        # Access audit + approvals
├── security/
│   └── verifier.py            # Independent integrity verifier (FIXED)
├── sql/
│   ├── schema.sql             # PostgreSQL schema
│   └── phase2-migrations.sql  # Phase 2 DB migrations
│   ├── phase4-migrations.sql  # Anchors + access audits
│   └── phase5-migrations.sql  # Anomaly baselines + feedback
│   └── phase6-migrations.sql  # Multi-tenant tables + tenant_id column
├── config/
│   ├── prometheus.yml
│   ├── alert-rules.yml
│   ├── alertmanager.yml
│   ├── otel-collector-config.yaml
│   ├── nginx/nginx.conf
│   └── grafana/               # Datasources + dashboards
│   └── playbooks/             # Phase 5 playbooks (YAML)
├── ops/
│   ├── backup_verify.py       # Backup integrity check
│   ├── restore_from_backup.sh # DR restore helper
│   └── backup_schedule.cron   # Cron template for backups
├── kubernetes/                # Cloud-ready manifests
├── sdk/
│   └── python/                # Python SDK
├── docs/
│   ├── SDK_GUIDE.md
│   └── INTEGRATIONS.md
├── web_ui/
│   ├── status_page.py         # Operator status page
├── tests/
│   ├── conftest.py            # Shared fixtures
│   ├── test_ledger.py         # 16 tests
│   ├── test_api.py            # 17 tests
│   ├── test_tracing.py        # 18 tests
│   ├── test_siem.py           # 22 tests
│   ├── test_pii.py            # 23 tests
│   └── test_enrichment.py     # 22 tests
│   ├── test_nl_query.py        # NL query parsing + filtering
│   ├── test_playbook_engine.py # Playbook matching + execution log
│   ├── test_risk_forecasting.py # Forecasting basics
│   └── test_tenant_manager.py   # Tenant usage + role defaults
└── claude.md                  # Project specification (Phases 1-6)
```

---

## What's Next: Phase 6 — Ecosystem & Scale

Per `claude.md`, Phase 6 includes:
1. **Vestigia Cloud (SaaS)** — multi-tenant platform, billing, org-level RBAC
2. **Managed infrastructure** — automated scaling, backups, DR, status page
3. **99.99% uptime SLA** — multi-region failover, incident transparency
4. **Developer ecosystem** — SDKs, integrations, compliance packs

Refer to `claude.md` for the full Phase 6 roadmap.

---

## How to Run

```bash
# Run all tests
python -m pytest tests/ integration_tests.py -v

# Run specific test file
python -m pytest tests/test_api.py -v

# Start API server (dev mode)
python api_server.py

# Full Docker deployment
./deploy.sh

# Backup
./backup.sh
```

---

*To resume work: point Claude at this file and say "read SESSION_SUMMARY.md and continue from where we left off."*
### Phase 4 Implementation (Complete)

Implemented core Phase 4 deliverables:
- HSM abstraction (`core/hsm_client.py`) with Local/AWS/YubiHSM support
- Merkle witness signatures using HSM (signature stored on witness entries)
- Blockchain anchoring (`core/blockchain_anchor.py`) with Merkle batching + OpenTimestamps optional
- Access audit logging (`core/access_audit.py`) with suspicious access detection
- New API endpoints:
  - `/events/export` (CSV with 2-person approval for large exports)
  - `/anchors` and `/anchors/{id}` for blockchain anchors
  - `/witness/public_key` for HSM public key
- Multi-region replication scripts + runbook (`replication/`)
- Replication docker-compose template (`replication/docker-compose.replication.yml`)
- Schema updates and Phase 4 migrations (`sql/phase4-migrations.sql`)
- Tests for HSM, blockchain anchoring, access audit
- Export 2-person approval test (`tests/test_export_approval.py`)
- PostgreSQL ledger now anchors Merkle + blockchain batches in production mode
### Phase 5 Implementation (Complete)

Implemented full Phase 5 deliverables:
- Baseline store + scoring module (`core/anomaly_detection.py`)
- Ensemble anomaly models (`core/anomaly_models.py`) + feature engineering (`core/feature_engineering.py`)
- API endpoints: `POST /anomalies/score`, `POST /anomalies/feedback`
- Automatic anomaly scoring on event ingestion with alerts for high risk
- Risk history persistence + forecasting (`core/risk_forecasting.py`, `/risk/forecast`)
- Natural language query engine (`core/nl_query.py`, `/nl/query`, dashboard tab)
- Automated playbooks (`core/playbook_engine.py`, `/playbooks`, `/playbooks/execute`, YAML configs)
- Dashboard tabs: SIEM alerts, NL query, playbooks, risk forecast
- Retraining loop (`retrain_anomaly_baselines.py`)
- Persistent baselines in PostgreSQL (`sql/phase5-migrations.sql`)
- Anomaly alerts stream to SIEM when configured (`VESTIGIA_SIEM_TARGETS`)
- Tests: `tests/test_anomaly_detection.py`, `tests/test_nl_query.py`, `tests/test_playbook_engine.py`, `tests/test_risk_forecasting.py`, `tests/test_tenant_manager.py`

### Phase 6 Implementation (In Progress)

Track 1 — Multi-tenant SaaS core:
- Tenant/user/API key store (`core/tenant_manager.py`) with JSON or Postgres backing
- API key auth now supports multi-tenant mode (`VESTIGIA_MULTI_TENANT=true`)
- Tenant-scoped event ingestion and queries (tenant_id on events + query filters)
- New endpoints: `/tenants`, `/tenants/{tenant_id}/users`, `/tenants/{tenant_id}/apikeys`
- New DB migration: `sql/phase6-migrations.sql` (tenant tables + tenant_id column)
- Plan enforcement for event and user limits (per-tenant daily usage tracking)
- Dashboard tab: “🏢 Tenants” for tenant/admin provisioning

Track 2 — Managed infrastructure:
- Ops health checks (`core/ops_health.py`) + `/status` endpoint
- Operator status page (`web_ui/status_page.py`)
- Backup verification + restore tooling (`ops/backup_verify.py`, `ops/restore_from_backup.sh`)
- Backup scheduling template (`ops/backup_schedule.cron`)
- Kubernetes manifests (`kubernetes/`) for cloud-ready deployment

Track 3 — Developer ecosystem:
- Python SDK (`sdk/python/vestigia_client.py`)
- SDK example (`examples/vestigia_sdk_example.py`)
- Developer docs (`docs/SDK_GUIDE.md`, `docs/INTEGRATIONS.md`)
