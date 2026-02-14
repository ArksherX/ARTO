# CLAUDE.md - VerityFlux AI Security Platform
## Complete Project Context & Architecture

---

## 🎯 Project Vision & Mission

**VerityFlux** is an **enterprise-grade AI Security Platform** - the world's first comprehensive behavioral firewall designed specifically for autonomous AI agents. It provides real-time monitoring, threat detection, behavioral analysis, and human-in-the-loop approval for AI systems operating in production environments.

### The Problem We Solve

AI agents are increasingly autonomous and can:
- Execute arbitrary code
- Access databases and APIs
- Send emails and messages
- Modify files and configurations
- Make financial transactions
- Interact with external systems

**Without VerityFlux:** These agents operate as black boxes with no visibility, no control, no audit trail, and no way to stop malicious or compromised behavior.

**With VerityFlux:** Every action is analyzed for intent, risky actions require human approval, threats are detected in real-time, compromised models are identified, and everything is logged for compliance.

### Market Position

Think of VerityFlux as: **Cloudflare WAF + CrowdStrike EDR + PagerDuty + Snyk**, but specifically designed for AI agents.

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                           VERITYFLUX SECURITY PLATFORM v3.5                         │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  ┌───────────────────┐  ┌───────────────────┐  ┌───────────────────┐               │
│  │   COGNITIVE       │  │    BACKDOOR       │  │      HITL         │               │
│  │   FIREWALL        │  │    DETECTOR       │  │    APPROVAL       │               │
│  │                   │  │                   │  │                   │               │
│  │ • Intent Analysis │  │ • Model Poisoning │  │ • Risk-based      │               │
│  │ • Goal Alignment  │  │ • Trigger Detect  │  │   Routing         │               │
│  │ • Deception Det.  │  │ • Behavioral      │  │ • Escalation      │               │
│  │ • Action Scoring  │  │   Anomalies       │  │   Chains          │               │
│  │ • SQL Validation  │  │ • Supply Chain    │  │ • Policy Engine   │               │
│  │ • Policy Engine   │  │   Compromise      │  │ • Auto-approve    │               │
│  └───────────────────┘  └───────────────────┘  └───────────────────┘               │
│           │                      │                      │                          │
│           └──────────────────────┴──────────────────────┘                          │
│                                  │                                                 │
│  ┌───────────────────┐  ┌───────┴───────┐  ┌───────────────────┐                  │
│  │   SOC COMMAND     │  │   SECURITY    │  │   FLIGHT          │                  │
│  │   CENTER          │  │   SCANNER     │  │   RECORDER        │                  │
│  │                   │  │               │  │                   │                  │
│  │ • Real-time Dash  │  │ • OWASP LLM   │  │ • Complete Audit  │                  │
│  │ • Alert Mgmt      │  │   Top 10      │  │ • Compliance      │                  │
│  │ • Incident Mgmt   │  │ • OWASP       │  │ • Forensics       │                  │
│  │ • SLA Tracking    │  │   Agentic 10  │  │ • Replay          │                  │
│  │ • Playbooks       │  │ • Custom      │  │                   │                  │
│  │ • SIEM Export     │  │   Vulns       │  │                   │                  │
│  └───────────────────┘  └───────────────┘  └───────────────────┘                  │
│                                                                                    │
├────────────────────────────────────────────────────────────────────────────────────┤
│                        ADVERSARIAL SIMULATION LAB (Red Team)                       │
├────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                    │
│  ┌───────────────────┐  ┌───────────────────┐  ┌───────────────────┐              │
│  │   ARTEMIS         │  │   ATTACK          │  │   TOOL            │              │
│  │   INTEGRATION     │  │   LIBRARY         │  │   ORCHESTRATOR    │              │
│  │   (Stanford)      │  │   (PROPRIETARY)   │  │                   │              │
│  │                   │  │                   │  │ • Garak (NVIDIA)  │              │
│  │ • Red Team        │  │ • 40+ Payloads    │  │ • PyRIT (MSFT)    │              │
│  │   Framework       │  │ • Jailbreaks      │  │ • ART (IBM)       │              │
│  │ • CTF Challenges  │  │ • Injections      │  │ • TextAttack      │              │
│  │ • OWASP Coverage  │  │ • Exfiltration    │  │ • Unified Report  │              │
│  │ • Tool Discovery  │  │ • Contextual Gen  │  │                   │              │
│  └───────────────────┘  └───────────────────┘  └───────────────────┘              │
│                                                                                    │
├────────────────────────────────────────────────────────────────────────────────────┤
│                              ENTERPRISE FEATURES                                   │
├────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │Multi-Tenant │  │ Rate        │  │ Prometheus  │  │ Air-Gapped  │              │
│  │ RBAC        │  │ Limiting    │  │ Metrics     │  │ Deploy      │              │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘              │
│                                                                                    │
├────────────────────────────────────────────────────────────────────────────────────┤
│                                INTEGRATIONS                                        │
├────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                    │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐   │
│  │LangChn │ │AutoGen │ │CrewAI  │ │ Slack  │ │ Jira   │ │PagerDty│ │ SIEM   │   │
│  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘ └────────┘ └────────┘   │
│                                                                                    │
└────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🧠 Component Deep Dive

### 1. Cognitive Firewall (`cognitive_firewall/`)

**Purpose:** Real-time behavioral analysis engine that understands agent INTENT, not just actions.

**This is NOT just prompt injection detection.** The Cognitive Firewall is a comprehensive behavioral analysis system.

#### Intent Analysis Engine
- **Goal-Action Alignment:** Analyzes if the agent's action matches its stated goal
  - Example: Goal "Generate sales report" + Action "DELETE FROM users" = MISMATCH → BLOCK
- **Reasoning Chain Analysis:** Examines the agent's step-by-step reasoning for deception indicators
  - Detects urgency manipulation ("URGENT", "bypass", "override")
  - Detects authority claims ("admin access", "emergency protocol")
  - Detects contradiction between reasoning steps
- **Context Window Analysis:** Tracks conversation history for gradual escalation attacks

#### Deception Detection
- **Manipulation Indicators:** Detects when agents try to deceive the firewall
  - Social engineering patterns
  - Authority impersonation
  - False urgency creation
- **Behavioral Anomalies:** Identifies unusual patterns
  - Sudden capability requests
  - Out-of-scope actions
  - Resource access escalation

#### Risk Scoring System
Every action receives a composite risk score (0-100) based on:
```python
risk_score = (
    intent_mismatch_score * 0.3 +      # Goal vs Action alignment
    deception_indicator_score * 0.25 +  # Manipulation attempts
    vulnerability_match_score * 0.25 +  # Known attack patterns
    behavioral_anomaly_score * 0.2      # Historical deviation
)
```

#### SQL Query Validation
- Detects SQL injection patterns (OR 1=1, UNION, stacked queries)
- Blocks dangerous operations (DROP, DELETE without WHERE, TRUNCATE)
- Validates query structure and parameters

#### Decision Engine
Based on risk score and policy, returns one of:
- `ALLOW` - Action is safe, proceed
- `LOG_ONLY` - Low risk, allow but log for review
- `REQUIRE_APPROVAL` - Medium-high risk, pause for human review
- `BLOCK` - Critical risk, deny immediately

#### Policy Engine
- Configurable per-tenant, per-agent, per-tool policies
- Time-based restrictions (e.g., no database deletes after hours)
- Resource-based limits (e.g., max 100 API calls per minute)
- Sensitive data access controls

**Location:** `cognitive_firewall/cognitive_firewall.py`

---

### 2. Backdoor Detector (`detectors/`)

**Purpose:** Detect compromised, poisoned, or malicious AI models before they cause harm.

#### What It Detects:
- **Model Poisoning:** Hidden triggers that activate malicious behavior
- **Behavioral Backdoors:** Models that behave normally until specific input
- **Supply Chain Attacks:** Compromised model weights or configurations
- **Trojan Triggers:** Specific phrases or patterns that bypass safety

#### Detection Methods:
- Statistical analysis of model outputs
- Trigger pattern scanning
- Behavioral baseline comparison
- Activation pattern analysis

**Location:** `detectors/`

---

### 3. HITL Approval System (`core/hitl/`)

**Purpose:** Human-in-the-Loop approval workflow for high-risk agent actions.

#### How It Works:
```
Agent Request → Risk Assessment → Route by Risk Level
                                         ↓
                    ┌────────────────────┼────────────────────┐
                    ↓                    ↓                    ↓
              Risk < 20            20 ≤ Risk ≤ 90        Risk > 90
            AUTO-APPROVE          HUMAN REVIEW          AUTO-DENY
                    ↓                    ↓                    ↓
              Execute Action    Create Approval Request   Block Action
                                         ↓
                                 Notify Reviewer(s)
                                         ↓
                              ┌──────────┴──────────┐
                              ↓                     ↓
                          APPROVE              DENY
                      (with conditions)    (with reason)
                              ↓                     ↓
                       Execute Action        Block + Log
```

#### Features:
- **Risk-Based Routing:** Automatic triage based on risk score
- **Escalation Chains:** If reviewer doesn't respond, escalate to next tier
- **Policy Engine:** Define which actions always require approval
- **Approval Conditions:** Approve with constraints (e.g., "only read access")
- **Audit Trail:** Complete log of who approved what and why
- **SLA Tracking:** Monitor approval response times

**Location:** `core/hitl/hitl_service.py`

---

### 4. SOC Command Center (`core/soc/`)

**Purpose:** Security Operations Center dashboard for security teams monitoring AI agents.

#### Features:

**Real-Time Event Stream:**
- Every agent action logged with full context
- Filterable by agent, action type, risk level, time
- Real-time updates via WebSocket

**Alert Management:**
- Severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO
- Auto-correlation of related events
- Deduplication and aggregation
- Alert routing rules

**Incident Management:**
- Create incidents from alerts
- Assign to team members
- Track investigation progress
- SLA tracking with escalation
- Resolution documentation

**Dashboard Metrics:**
- Events per hour/day
- Blocked actions count
- Mean Time to Resolution (MTTR)
- Active agents monitored
- Approval queue depth

**Playbook Automation:**
- Predefined response playbooks
- Automated containment actions
- Integration with ticketing systems

**SIEM Integration:**
- Export to Splunk, Elastic, Sentinel
- Standard CEF/LEEF formats
- Real-time streaming

**Location:** `core/soc/soc_command_center.py`

---

### 5. Security Scanner (`core/scanner/`)

**Purpose:** Vulnerability scanning for AI agents, models, and configurations.

#### Scan Targets:
- Agent configurations
- Tool permissions
- Model endpoints (OpenAI, Anthropic, Ollama, custom)
- Prompt templates
- RAG data sources
- API integrations

#### Vulnerability Databases:

**OWASP LLM Top 10 (2025):**
| ID | Vulnerability | Description |
|----|--------------|-------------|
| LLM01 | Prompt Injection | Direct and indirect prompt manipulation |
| LLM02 | Insecure Output Handling | Unsafe rendering of model outputs |
| LLM03 | Training Data Poisoning | Manipulation of training data |
| LLM04 | Model Denial of Service | Resource exhaustion attacks |
| LLM05 | Supply Chain Vulnerabilities | Compromised models/dependencies |
| LLM06 | Sensitive Information Disclosure | Data leakage through outputs |
| LLM07 | Insecure Plugin Design | Vulnerable tool integrations |
| LLM08 | Excessive Agency | Over-permissioned agents |
| LLM09 | Overreliance | Blind trust in model outputs |
| LLM10 | Model Theft | Extraction of proprietary models |

**OWASP Agentic AI Top 10 (2025):**
| ID | Vulnerability | Description |
|----|--------------|-------------|
| ASI01 | Agent Hijacking | Taking control of agent execution |
| ASI02 | Tool Misuse | Unauthorized or malicious tool usage |
| ASI03 | Privilege Escalation | Gaining unauthorized capabilities |
| ASI04 | Memory Poisoning | Corrupting agent memory/context |
| ASI05 | Goal Manipulation | Altering agent objectives |
| ASI06 | Multi-Agent Collusion | Coordinated malicious behavior |
| ASI07 | Resource Exhaustion | DoS through agent actions |
| ASI08 | Data Exfiltration | Unauthorized data extraction |
| ASI09 | Audit Evasion | Circumventing logging/monitoring |
| ASI10 | Human Bypass | Circumventing HITL controls |

**Location:** `core/scanner/`, `core/vulndb/`

---

### 6. Adversarial Simulation Lab (Red Team)

**Purpose:** Comprehensive security testing for AI agents using real attack techniques.

#### ARTEMIS Integration (`artemis_integration.py`)

Stanford's ARTEMIS framework integration for Red Team penetration testing.

**Red Team vs Blue Team:**
- **ARTEMIS (Red Team):** Attacks AI agents using deceptive tactics, crafted reasoning chains, malicious payloads
- **VerityFlux (Blue Team):** Defends and detects the attacks in real-time

**CTF Challenge Mode:**
Pre-defined security challenges to test defenses:
- SQL Injection Detection
- Privilege Escalation
- Data Exfiltration
- Goal Hijacking
- Prompt Injection

**Targeted Tool Attack Mode:**
- Discovers available agent tools
- Generates targeted attack payloads for each tool
- Tests each tool for vulnerabilities
- Maps results to OWASP threats

**OWASP Matrix Mapper:**
Maps all attacks to BOTH OWASP LLM Top 10 AND OWASP Agentic Top 10 with specific payloads for each threat category.

**Metrics Tracked:**
- True Positives (attacks correctly blocked)
- False Positives (safe actions incorrectly blocked)
- True Negatives (safe actions correctly allowed)
- False Negatives (attacks that got through)
- Precision, Recall, F1 Score

**Location:** `artemis_integration.py`

---

### 7. Attack Library (`redteam/attack_library.py`) - PROPRIETARY

**Purpose:** Proprietary attack payload library for security testing. **DO NOT OPEN SOURCE.**

#### Attack Categories (40+ payloads):

**Prompt Injection (10 payloads):**
- PI-001 to PI-010: Basic override, DAN activation, hypothetical bypass, ChatML injection, continuation attack, translation bypass, Base64 encoding, Markdown injection, few-shot poisoning, Unicode/homoglyph

**Jailbreak (5 payloads):**
- JB-001 to JB-005: DAN 11.0, Evil Confidant, STAN, Grandma exploit, Token smuggling

**Data Exfiltration (6 payloads):**
- DE-001 to DE-006: System prompt extraction (direct, summarize, repeat), training data extraction, PII extraction, API key extraction

**Indirect Injection (5 payloads):**
- II-001 to II-005: Hidden text, document metadata, URL content, email body, calendar event

**Tool Abuse (5 payloads):**
- TA-001 to TA-005: Code execution escape, file system traversal, tool chain exploitation, webhook exfiltration, SQL injection via tool

**Role Confusion (3 payloads):**
- RC-001 to RC-003: Admin impersonation, developer mode, support agent roleplay

**Multi-Turn Attacks (2 payloads):**
- MT-001 to MT-002: Gradual escalation, context building

#### Key Features:
- `generate_contextual_attacks()` - Custom payloads tailored to specific targets
- `generate_variants()` - Obfuscation (leetspeak, padding, encoding, case mixing)
- OWASP mapping for each payload
- Severity and complexity ratings

**Location:** `redteam/attack_library.py`

---

### 8. Tool Orchestrator (`redteam/tool_orchestrator.py`)

**Purpose:** Wrapper/orchestration layer for external security tools.

**Uses WRAPPER approach (subprocess/API) - does NOT bundle tool code. Legally safe for commercial use.**

#### Integrated Tools:

| Tool | Vendor | License | Purpose |
|------|--------|---------|---------|
| Garak | NVIDIA | Apache 2.0 | LLM vulnerability scanner |
| PyRIT | Microsoft | MIT | AI risk identification toolkit |
| ART | IBM | MIT | Adversarial robustness testing |
| TextAttack | - | MIT | NLP adversarial attacks |

**Location:** `redteam/tool_orchestrator.py`

---

### 9. Enterprise Features (`core/`)

#### Multi-Tenancy & RBAC
- Tenant isolation with separate databases/schemas
- Role-based access control (Admin, Analyst, Viewer, Agent)
- Per-tenant configuration and policies
- Usage quotas and limits
- Tier-based feature gating (Startup, Professional, Enterprise)

#### Observability (`core/observability.py`)
- Prometheus metrics endpoint (`/metrics`)
- Request latency histograms
- Business metrics (events, approvals, scans, alerts)
- Health check endpoints (`/health`, `/ready`)

**Metrics Exposed:**
- `verityflux_http_requests_total`
- `verityflux_http_request_duration_seconds`
- `verityflux_events_processed_total`
- `verityflux_approvals_created_total`
- `verityflux_scans_completed_total`
- `verityflux_alerts_created_total`

#### Rate Limiting (`core/rate_limiting.py`)
- Token bucket algorithm
- Per-user, per-IP, per-endpoint limits
- Redis backend for distributed deployment
- In-memory fallback for air-gapped

#### Authentication (`core/auth/`)
- JWT tokens (15min access, 7d refresh)
- API key authentication (SHA-256 hashed, prefix stored)
- MFA/TOTP support
- Session management

#### Air-Gapped Deployment
- Offline vulnerability database updates
- Local-only operation
- No external API dependencies required
- Update packages for manual transfer

---

### 10. SDKs & Integrations (`sdk/`)

#### Python SDK (`sdk/python/verityflux_sdk.py`)
```python
from verityflux_sdk import VerityFluxClient, ApprovalRequired

client = VerityFluxClient(
    base_url="http://localhost:8000",
    api_key="vf_xxx",
    agent_name="my-agent"
)

result = client.check_action(
    tool_name="database_query",
    action="execute",
    parameters={"query": "SELECT * FROM users"}
)
```

#### Framework Integrations:
- **LangChain:** `sdk/integrations/langchain_integration.py`
- **AutoGen:** `sdk/integrations/autogen_integration.py`
- **CrewAI:** `sdk/integrations/crewai_integration.py`
- **TypeScript:** `sdk/typescript/index.ts`

#### External Integrations:
- Slack, Jira, PagerDuty, Twilio, Email, Webhook, SIEM (Splunk, Elastic, Sentinel)

---

## 🚀 Running the Project

```bash
# Install
cd ~/ml-redteam/verityflux-v2
pip install -e .

# Start API
uvicorn api.v2.main:app --reload

# Access Points
# API Docs: http://localhost:8000/docs
# Health: http://localhost:8000/health
# Metrics: http://localhost:8000/metrics

# Run Streamlit Dashboard
streamlit run web_ui_complete.py
```

---

## ✅ Complete Verification Checklist

### Cognitive Firewall
- [ ] Test goal-action mismatch detection (goal="report" + action="DELETE")
- [ ] Test deception indicators (urgency, authority claims)
- [ ] Test SQL injection detection (OR 1=1, UNION, DROP)
- [ ] Verify risk scoring (0-100)
- [ ] Verify decision engine (ALLOW, LOG_ONLY, REQUIRE_APPROVAL, BLOCK)

### Backdoor Detector
- [ ] Verify detection modules exist in `detectors/`
- [ ] Test model analysis functions

### HITL System
- [ ] Create approval request with risk_score=85
- [ ] Verify auto-approve for risk < 20
- [ ] Verify auto-deny for risk > 90
- [ ] Test approve/deny workflow
- [ ] Check escalation chains
- [ ] Verify audit trail

### SOC Command Center
- [ ] Ingest security event
- [ ] Query events with filters
- [ ] Create and manage alerts
- [ ] Create and track incidents
- [ ] Verify dashboard metrics (events/hour, MTTR, etc.)

### Security Scanner
- [ ] GET OWASP LLM Top 10 (10 vulnerabilities: LLM01-LLM10)
- [ ] GET OWASP Agentic Top 10 (10 vulnerabilities: ASI01-ASI10)
- [ ] Create scan with target
- [ ] Get scan results

### Adversarial Simulation Lab (ARTEMIS)
- [ ] ARTEMIS integration loads
- [ ] CTF challenge mode runs
- [ ] Targeted tool attack mode runs
- [ ] OWASP matrix mapper works
- [ ] Metrics calculated (TP, FP, TN, FN, F1)

### Attack Library (PROPRIETARY)
- [ ] Import AttackLibrary
- [ ] Get all payloads (should be 40+)
- [ ] Get payloads by category (7 categories)
- [ ] Generate contextual attacks
- [ ] Generate variants

### Tool Orchestrator
- [ ] Detect available tools (Garak, PyRIT, ART, TextAttack)
- [ ] Run scan with available tool
- [ ] Normalize and aggregate findings

### Enterprise Features
- [ ] Rate limiting blocks after threshold
- [ ] Prometheus /metrics returns counters and histograms
- [ ] /health returns all services healthy
- [ ] JWT authentication works
- [ ] API key authentication works

### SDKs
- [ ] Python SDK: `from sdk.python.verityflux_sdk import VerityFluxClient`
- [ ] LangChain: `from sdk.integrations.langchain_integration import *`
- [ ] AutoGen: `from sdk.integrations.autogen_integration import *`
- [ ] CrewAI: `from sdk.integrations.crewai_integration import *`
- [ ] TypeScript SDK exists: `sdk/typescript/index.ts`

### Deployment
- [ ] `deploy/docker/Dockerfile` valid
- [ ] `deploy/docker/docker-compose.yml` valid
- [ ] `deploy/k8s/*.yaml` manifests valid
- [ ] `deploy/helm/values.yaml` valid

---

## 🔐 Security Notes

1. **Attack Library (`redteam/`)** is **PROPRIETARY** - DO NOT open source
2. External tools use **wrapper pattern** - legally safe for commercial
3. All secrets from environment variables
4. JWT tokens: 15min access, 7d refresh
5. API keys: SHA-256 hashed, only prefix stored
6. Rate limiting on all endpoints
7. Authentication required (except /health, /ready, /metrics, /docs)

---

## 📊 Project Statistics

| Metric | Value |
|--------|-------|
| Total Python Files | 50+ |
| Lines of Code | 30,000+ |
| Test Functions | 79 |
| OWASP Coverage | 20/20 (LLM Top 10 + Agentic Top 10) |
| Attack Payloads | 40+ |
| Attack Categories | 7 |
| SDK Languages | 2 (Python, TypeScript) |
| Framework Integrations | 3 (LangChain, AutoGen, CrewAI) |
| External Integrations | 7 (Slack, Jira, PagerDuty, Twilio, Email, Webhook, SIEM) |
