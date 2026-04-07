# VerityFlux v2 — AI Security Scanner

## Overview

VerityFlux is a production security scanner for LLM and agentic AI systems. It tests real targets against the **OWASP LLM Top 10 (2025)** and **OWASP Agentic AI Top 10 (2026)** — 20 core vulnerability categories total — by sending adversarial prompts to live LLM endpoints and analyzing responses for unsafe behavior. It also supports **3 workflow fuzz detectors** and **4 MCP security detectors** as optional scan modes.

VerityFlux also performs **live protocol-integrity enforcement** for structured tool-call and agent-message flows. It can detect and score **schema drift**, **field smuggling**, **contract desynchronization**, and **multi-hop trust collapse** through the runtime interception path and dedicated MCP analysis APIs.

In the runtime memory path, VerityFlux now distinguishes ordinary retrieval sanitization from **cross-agent working-memory poisoning**. Shared-memory entries originating from other agents or shared/team/global stores are treated as trust-boundary crossings and surfaced as dedicated alerts when they contain poisoned control content.

In the runtime reasoning path, VerityFlux now detects **A2A chain-of-thought contamination** when inherited reasoning from another agent carries unsafe approval claims, hidden scratchpad content, disabled-safety claims, or unvalidated continuation instructions.

VerityFlux supports **OpenAI**, **Anthropic**, **Azure OpenAI**, **Hugging Face**, **Ollama** (local), and **custom endpoints**. A **mock mode** is available for demos and CI pipelines where no API key is needed.

VerityFlux also supports **skill-layer assessment** for agent behavior packages and manifests. Operators can assess `SKILL.md`, `skill.json`, `manifest.json`, and `package.json` content against AST01-AST10 style risks, store the result, and map findings directly to **Tessera** identity controls, **VerityFlux** policy gates, and **Vestigia** evidence workflows.

---

## How It Works

### Scan Pipeline

1. **Onboard** your agent or LLM target (via UI, API, or Tessera import).
2. **Declare capabilities** — what security controls the target has (sandbox, RBAC, approval workflows, circuit breakers, etc.).
3. **Provide credentials** — API key for the LLM provider (or use Ollama for local models).
4. **Run scan** — VerityFlux sends adversarial prompts through 20 core detectors against the live LLM endpoint, with 3 fuzz and 4 MCP detectors available when those scan modes are enabled.
5. **Analyze results** — each detector returns a `ThreatDetectionResult` with risk level, confidence, evidence, and actionable recommendations.
6. **Assess protocol integrity** — review MCP Security status or call the protocol-integrity API to inspect structured message envelopes before execution.
7. **Assess skills** — optionally upload or paste a skill manifest/package in the Scanner UI's **Skill Security** tab to evaluate skill-layer risks before activation.

Every scan result includes a `scan_mode` field (`"real"`, `"mock"`, or `"unknown"`) so operators always know whether findings come from actual LLM responses or simulated data.

### What the Detectors Test

Each detector sends crafted attack prompts to the target LLM and checks responses for compliance indicators (the model did the unsafe thing) vs. refusal indicators (the model correctly refused). No `random.random()` or hardcoded simulation is used.

| Category | ID | Threat |
|----------|-----|--------|
| LLM | LLM01 | Prompt Injection |
| LLM | LLM02 | Sensitive Data Disclosure |
| LLM | LLM03 | Supply Chain Vulnerabilities |
| LLM | LLM04 | Data & Model Poisoning |
| LLM | LLM05 | Insecure Output Handling |
| LLM | LLM06 | Excessive Agency |
| LLM | LLM07 | System Prompt Leakage |
| LLM | LLM08 | RAG Security (Vector/Retrieval) |
| LLM | LLM09 | Misinformation & Hallucination |
| LLM | LLM10 | Unbounded Consumption |
| Agentic | AAI01 | Agentic Goal Hijacking |
| Agentic | AAI02 | Agent Identity & Trust Abuse |
| Agentic | AAI03 | Unsafe Code Execution |
| Agentic | AAI04 | Insecure Inter-Agent Communication |
| Agentic | AAI05 | Human-Agent Trust Exploitation |
| Agentic | AAI06 | Tool Misuse & Exploitation |
| Agentic | AAI07 | Agentic Supply Chain |
| Agentic | AAI08 | Memory & Context Poisoning |
| Agentic | AAI09 | Cascading Failures |
| Agentic | AAI10 | Rogue Agent Detection |

---

## Agent & LLM Onboarding

### Via the UI (Streamlit)

1. Navigate to the **Agents** tab in the VerityFlux UI.
2. Use one of three onboarding methods:
   - **Single Register** — enter agent name, type, provider, model, endpoint URL, and API key.
   - **Bulk Upload** — upload a CSV/JSON file with multiple agents.
   - **Import from Tessera** — pull registered agents from the Tessera identity plane (requires Tessera API running).
3. Under **Security Capabilities**, declare what controls the agent has:
   - Sandbox, approval workflow, RBAC, identity verification
   - Code validation, cost controls, monitoring, kill switch
   - Persistent memory, RAG, tool access
4. Registered agents appear in the live inventory and can be selected as scan targets.

### Via the API

```bash
# Register an agent
curl -X POST http://localhost:8003/api/v1/soc/agents/register \
  -H "Content-Type: application/json" \
  -d '{
    "agent_name": "customer-support-bot",
    "agent_type": "conversational",
    "provider": "openai",
    "model": "gpt-4o",
    "endpoint_url": null,
    "api_key": "sk-...",
    "has_sandbox": false,
    "has_approval_workflow": true,
    "has_rbac": true,
    "has_identity_verification": false,
    "has_memory": true,
    "has_rag": true,
    "has_code_validation": false,
    "has_cost_controls": true,
    "has_monitoring": true,
    "has_kill_switch": false
  }'
```

### Capability Declarations

Capabilities directly affect scan results. For example:
- If `has_sandbox=False`, the AAI03 (Unsafe Code Execution) detector flags the absence as a risk factor.
- If `has_approval_workflow=False`, the LLM06 (Excessive Agency) detector adjusts its risk assessment upward.
- If `has_circuit_breaker=False` and `has_error_isolation=False`, the AAI09 (Cascading Failures) detector factors in infrastructure gaps.

Undeclared capabilities default to `False` (conservative security posture — absent until proven present).

---

## Running a Production Scan

### Prerequisites

- An LLM provider API key (OpenAI, Anthropic, etc.) **or** a local Ollama instance running.
- VerityFlux API server running (`python api/v2/main.py`).

### Via the UI

1. Go to the **Scanner** tab.
2. Select provider (openai, anthropic, ollama, azure_openai, huggingface, custom).
3. Enter model name (e.g., `gpt-4o`, `claude-sonnet-4-20250514`, `llama3`).
4. Enter API key (not required for Ollama or mock mode).
5. Optionally enter a custom endpoint URL.
6. Under **Target Capabilities**, check all security controls that apply to your target.
7. Click **Start Scan**.

### Via the API

```bash
curl -X POST http://localhost:8003/api/v2/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target_type": "openai",
    "model_name": "gpt-4o",
    "api_key": "sk-...",
    "config": {
      "is_agent": true,
      "has_tools": true,
      "has_memory": true,
      "has_rag": true,
      "has_sandbox": false,
      "has_approval_workflow": true,
      "has_rbac": true,
      "has_cost_controls": true,
      "has_monitoring": true
    }
  }'
```

### Scan Modes

| Mode | When | What happens |
|------|------|-------------|
| **Real** (`scan_mode="real"`) | Valid API key + reachable provider | Adversarial prompts sent to live LLM, responses analyzed |
| **Mock** (`scan_mode="mock"`) | No API key or provider="mock" | Deterministic simulated responses for demos and CI |

The API key flows through: **UI** -> **API** (`ScanTargetRequest` with backward-compatible extraction) -> **`_build_target_dict()`** -> **detector** -> **`get_llm_adapter(target)`** -> **`LLMAdapter`** -> **provider SDK**.

---

## Local Development

```bash
cd verityflux-v2

# Install dependencies
pip install -r requirements.txt

# Start API server
python api/v2/main.py

# Start UI (separate terminal)
streamlit run ui/streamlit/app.py

# Access:
# - API: http://localhost:8003
# - UI: http://localhost:8503
# - API docs: http://localhost:8003/docs
```

### Running with Ollama (no API key needed)

```bash
# Install and start Ollama
ollama serve

# Pull a model
ollama pull llama3

# In VerityFlux, select provider=ollama, model=llama3
# Scans will run against your local model with scan_mode="real"
```

---

## Deployment

### Docker Compose (Development)

```bash
cp .env.example .env
vim .env  # Set API keys and secrets
docker-compose up -d
```

### Docker Compose (Production)

```bash
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

---

## Kubernetes Deployment

### Prerequisites

- Kubernetes cluster (1.24+)
- kubectl configured
- nginx-ingress-controller (or similar)
- cert-manager (for TLS)
- Storage class for PVCs

### Deploy with Kustomize

```bash
# Create namespace
kubectl create namespace verityflux

# Edit secrets (IMPORTANT!)
vim deploy/k8s/02-secrets.yaml

# Deploy all resources
kubectl apply -k deploy/k8s/

# Check deployment status
kubectl get pods -n verityflux
kubectl get svc -n verityflux
kubectl get ingress -n verityflux

# View logs
kubectl logs -f deployment/verityflux-api -n verityflux
```

### Deploy with Helm

```bash
# Add Helm repo (if published)
# helm repo add verityflux https://charts.verityflux.ai

# Install from local chart
helm install verityflux ./deploy/helm \
  -n verityflux \
  --create-namespace \
  -f deploy/helm/values.yaml \
  --set secrets.values.JWT_SECRET_KEY="$(openssl rand -hex 32)"

# Upgrade
helm upgrade verityflux ./deploy/helm \
  -n verityflux \
  -f deploy/helm/values.yaml

# Uninstall
helm uninstall verityflux -n verityflux
```

---

## Environment Configuration

### Required Environment Variables

```bash
# Database
DATABASE_URL=postgresql://user:pass@host:5432/verityflux

# Redis
REDIS_URL=redis://host:6379/0

# Security
JWT_SECRET_KEY=<32+ char random string>
SECRET_KEY=<32+ char random string>
```

### LLM Provider Keys (for production scanning)

```bash
# At least one provider key is needed for real scans.
# The key can also be provided per-scan via the UI or API payload.
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
AZURE_OPENAI_API_KEY=...
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com
HUGGINGFACE_API_KEY=hf_...
# Ollama requires no key — just a running local instance.
```

### Integration Environment Variables

```bash
# Slack
SLACK_BOT_TOKEN=xoxb-...
SLACK_SIGNING_SECRET=...

# Jira
JIRA_URL=https://company.atlassian.net
JIRA_USERNAME=user@company.com
JIRA_API_TOKEN=...

# PagerDuty
PAGERDUTY_ROUTING_KEY=...

# Vulnerability Database
NVD_API_KEY=...
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Load Balancer                           │
│                    (nginx / ALB / Traefik)                      │
└─────────────────────────┬───────────────────────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          │               │               │
          ▼               ▼               ▼
┌─────────────────┐ ┌─────────────┐ ┌─────────────┐
│   API Server    │ │  Streamlit  │ │  WebSocket  │
│   (FastAPI)     │ │    (UI)     │ │   Server    │
│   Port 8000     │ │  Port 8501  │ │  Port 8000  │
└────────┬────────┘ └──────┬──────┘ └──────┬──────┘
         │                 │               │
         └────────┬────────┴───────────────┘
                  │
    ┌─────────────┼─────────────┐
    │             │             │
    ▼             ▼             ▼
┌────────┐  ┌──────────┐  ┌──────────┐
│ Postgres│  │  Redis   │  │ Workers  │
│(Timescale)│  │ (Cache) │  │ (Celery) │
└────────┘  └──────────┘  └──────────┘
```

---

## Scaling

### Horizontal Pod Autoscaler

```yaml
# API scales 3-10 replicas based on CPU/memory
# Workers scale 2-8 replicas
# UI scales 2-5 replicas
```

### Manual Scaling

```bash
# Scale API
kubectl scale deployment/verityflux-api --replicas=5 -n verityflux

# Scale workers
kubectl scale deployment/verityflux-worker --replicas=4 -n verityflux
```

---

## Health Checks

### Endpoints

| Service | Health | Ready |
|---------|--------|-------|
| API | `GET /health` | `GET /ready` |
| UI | `GET /_stcore/health` | - |

### Kubernetes Probes

- **Liveness**: Restart if unhealthy
- **Readiness**: Remove from load balancer if not ready

---

## Monitoring

### Prometheus Metrics

```bash
# API exposes metrics at
GET /metrics
```

### Grafana Dashboards

Import dashboards from `deploy/grafana/dashboards/`:
- SOC Overview
- API Performance
- Agent Health
- Scan Statistics

---

## Backup & Recovery

### PostgreSQL Backup

```bash
# Manual backup
kubectl exec -n verityflux verityflux-postgres-0 -- \
  pg_dump -U verityflux verityflux > backup.sql

# Restore
kubectl exec -i -n verityflux verityflux-postgres-0 -- \
  psql -U verityflux verityflux < backup.sql
```

### Automated Backups

Consider using:
- Velero for cluster-wide backups
- pg_dump cron jobs
- Managed database snapshots (RDS, Cloud SQL)

---

## Security Checklist

- [ ] Change all default passwords
- [ ] Generate strong JWT_SECRET_KEY (32+ chars)
- [ ] Enable TLS for ingress
- [ ] Configure network policies
- [ ] Use managed secrets (Vault, AWS Secrets Manager)
- [ ] Enable audit logging
- [ ] Review RBAC permissions
- [ ] Set resource limits
- [ ] Enable pod security policies

---

## Troubleshooting

### Common Issues

**API pods not starting:**
```bash
kubectl describe pod -l app.kubernetes.io/component=api -n verityflux
kubectl logs -l app.kubernetes.io/component=api -n verityflux
```

**Database connection issues:**
```bash
# Test connectivity
kubectl run -it --rm debug --image=postgres:15 --restart=Never -n verityflux -- \
  psql postgresql://verityflux:PASSWORD@verityflux-postgres:5432/verityflux
```

**Redis connection issues:**
```bash
kubectl run -it --rm debug --image=redis:7-alpine --restart=Never -n verityflux -- \
  redis-cli -h verityflux-redis ping
```

---

## Project Structure

```
verityflux-v2/
├── api/v2/main.py                  # FastAPI server, scan + agent + enterprise endpoints
├── core/
│   ├── types.py                    # ThreatDetectionResult, FuzzThreat, MCPThreat, enums
│   └── scanner.py                  # Scan orchestrator (20 OWASP + 3 fuzz + 4 MCP detectors)
├── cognitive_firewall/
│   ├── firewall.py                 # Core cognitive firewall with stateful tracking
│   ├── reasoning_interceptor.py    # Runtime CoT interception (allow/block/escalate)
│   ├── rationalization_engine.py   # LLM-as-a-Judge independent oversight
│   ├── memory_runtime_filter.py    # Runtime RAG retrieval sanitization
│   ├── adversarial_scorer.py       # Semantic hostility grading
│   ├── stateful_intent_tracker.py  # Session drift + crescendo detection
│   ├── mcp_sentry.py               # MCP request interception
│   ├── tool_manifest_signer.py     # HMAC-SHA256 manifest signing
│   ├── schema_validator.py         # JSON Schema enforcement
│   ├── supply_chain_monitor.py     # AIBOM tracking
│   ├── tool_registry.py            # Tool verification + signature checks
│   └── complete_stack.py           # Wires all runtime modules together
├── detectors/
│   ├── common.py                   # Shared get_llm_adapter() factory
│   ├── llm_top10/                  # LLM01-LLM10 detectors
│   ├── agentic_top10/              # AAI01-AAI10 detectors
│   ├── fuzz/                       # Agentic workflow fuzz detectors (3)
│   └── mcp/                        # MCP security detectors (4)
├── integrations/
│   └── llm_adapter.py              # Unified LLM client (OpenAI/Anthropic/Ollama/HF/Azure/Mock)
└── ui/streamlit/app.py             # Streamlit dashboard (12+ tabs)
```

---

## Version History

| Version | Date | Notes |
|---------|------|-------|
| 2.3.2 | 2026-02-18 | LLM adapter hardening: fixed timeouts for all providers (Ollama 120s, HF 60s, OpenAI/Anthropic 60s), Ollama pre-flight check, error truncation expanded to 200 chars, response bodies in errors. New test suites: `test_adversarial_efficacy.py` (38 tests) and `test_e2e_scenarios.py` (28 steps). |
| 2.3.1 | 2026-02-18 | Scan history persistence, fuzz/MCP detector files, scan flag passthrough, AttackVector enums, type handling fixes. |
| 2.3.0 | 2026-02-17 | Enterprise features: runtime enforcement layer, MCP security scanning, agentic fuzz testing, AIBOM, tool manifest signing, 12 new API endpoints, 6 new dashboard tabs. OWASP AI Exchange + MCP Security Guide alignment. |
| 2.2.0 | 2026-02 | Scan-from-agent bridge, Azure OpenAI, OWASP alignment (crescendo + evasion), context fields |
| 2.1.0 | 2026-02 | Real detection: all 20 core detectors query live LLMs, capability-based checks, scan_mode metadata |
| 2.0.0 | 2026-01 | Initial v2 with OWASP Agentic Top 10 coverage |
