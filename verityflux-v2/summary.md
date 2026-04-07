# VerityFlux v2 — Summary

**Last updated:** 2026-04-07
**Status:** Production-ready (real LLM detection + runtime enforcement active, with live protocol-integrity checks)

## What Changed (2026-04-07) — Protocol Integrity Enforcement

VerityFlux now includes first-class protocol-integrity controls for agent-to-agent and tool-call message handling. This closes the highest-priority product gaps around schema drift, field smuggling, contract desynchronization, and multi-hop trust collapse without changing the existing runtime enforcement flow.

### Key changes

1. **Protocol integrity engine added** — `core/protocol_integrity.py` now evaluates structured message envelopes against expected tool contracts and route metadata.

2. **Live runtime enforcement wiring** — `POST /api/v2/intercept/tool-call` now runs protocol-integrity analysis before execution and can escalate or block actions when protocol findings are high-risk.

3. **New MCP analysis endpoint** — `POST /api/v2/mcp/protocol-integrity/analyze` exposes direct protocol analysis for message payloads, contract metadata, and routed multi-hop paths.

4. **MCP status extended** — `GET /api/v2/mcp/status` now includes protocol-integrity counters and recent alerts so the UI is backed by live operational data instead of fixture-only values.

5. **Schema bootstrap expanded** — `cognitive_firewall/schema_validator.py` now seeds default contracts for common tool calls (`read_file`, `execute_command`, `send_email`, `web_search`, `sql_executor`, and aliases), allowing protocol checks to work even before custom schemas are registered.

6. **Vestigia evidence integration** — protocol findings now emit `PROTOCOL_INTEGRITY_ALERT` events, and Vestigia correlates protocol alerts followed by tool execution as a cross-plane anomaly pattern.

7. **Dashboard integration** — the VerityFlux **MCP Security** tab now includes a **Protocol Integrity** view showing assessed messages, alert counts, and recent live findings.

8. **Regression coverage added** — functional, adversarial, and end-to-end suites now cover benign protocol analysis, field smuggling, and multi-hop trust collapse scenarios.

### Verification

- `python3 -m py_compile` on all modified protocol-integrity and evidence modules: PASS
- `python3 test_suite_complete.py`: PASS (`63/67` passed, `4` skipped for optional providers)
- `python3 test_adversarial_efficacy.py`: PASS (`38/38` passed, `3` skipped for optional providers)
- `python3 test_e2e_scenarios.py`: PASS (`28/28` steps passed)

## What Changed (2026-04-07) — Cross-Agent Working-Memory Poisoning

VerityFlux now treats shared-memory retrievals as a multi-agent trust boundary, not just a generic sanitization problem. This closes the immediate product gap where poisoned memory written by one agent could later influence another agent through shared retrieval paths.

### Key changes

1. **Cross-agent memory detection added** — `cognitive_firewall/memory_runtime_filter.py` now detects poisoned shared-memory retrievals when content originates from another agent or a shared/team/global memory scope.

2. **Alert metadata surfaced in the API** — `POST /api/v2/filter/memory` now returns `cross_agent_alert`, `cross_agent_findings`, and `risk_score` so hosts can separate ordinary sanitization from cross-agent poisoning risk.

3. **Unified evaluate path updated** — `POST /api/v2/evaluate` now carries cross-agent memory findings into the combined verdict and raises the effective risk score when shared-memory poisoning is present.

4. **Evidence continuity added** — memory filtering now emits `MEMORY_FILTERED` events with shared-memory context, and high-risk cases emit `MEMORY_CROSS_AGENT_ALERT`.

5. **Vestigia correlation extended** — `vestigia/core/event_correlator.py` now flags tool execution shortly after `MEMORY_CROSS_AGENT_ALERT` as a dedicated anomaly pattern.

6. **Regression tests added** — the functional and adversarial suites now cover cross-agent shared-memory poisoning in addition to existing memory sanitization checks.

### Verification

- `python3 -m py_compile` on modified memory-poisoning, API, evidence, and test modules: PASS
- `python3 test_suite_complete.py`: PASS (`63/67` passed, `4` skipped for optional providers)
- `python3 test_adversarial_efficacy.py`: PASS (`38/38` passed, `3` skipped for optional providers)
- `python3 test_e2e_scenarios.py`: PASS (`28/28` steps passed)

## What Changed (2026-04-07) — A2A Chain-of-Thought Contamination

VerityFlux now treats inherited reasoning from other agents as a runtime trust boundary. This closes the practical A2A reasoning gap where a downstream agent could execute on a prior agent's unsafe or unvalidated hidden reasoning.

### Key changes

1. **A2A CoT contamination detection added** — `cognitive_firewall/reasoning_interceptor.py` now detects contaminated inherited reasoning during agent handoffs, including inherited approval claims, disabled-safety claims, and private scratchpad/chain-of-thought content.

2. **Reasoning interception API extended** — `POST /api/v2/intercept/reasoning` now accepts handoff metadata (`handoff_from_agent_id`, `handoff_channel`, `handoff_shared_reasoning`, `handoff_metadata`) and returns contamination status, score, and findings.

3. **Unified evaluate path updated** — `POST /api/v2/evaluate` now propagates A2A reasoning contamination findings into the combined verdict when inherited reasoning is present.

4. **Evidence continuity added** — contaminated handoff reasoning now emits `REASONING_A2A_ALERT` events so Vestigia can retain traceable evidence of unsafe inherited reasoning.

5. **Vestigia correlation extended** — `vestigia/core/event_correlator.py` now flags tool execution shortly after `REASONING_A2A_ALERT` as a dedicated anomaly pattern.

6. **Regression tests added** — the functional and adversarial suites now cover inherited A2A CoT contamination scenarios in addition to protocol and memory-layer checks.

### Verification

- `python3 -m py_compile` on modified reasoning, API, evidence, and test modules: PASS
- `python3 test_suite_complete.py`: PASS (`64/68` passed, `4` skipped for optional providers)
- `python3 test_adversarial_efficacy.py`: PASS (`39/39` passed, `3` skipped for optional providers)
- `python3 test_e2e_scenarios.py`: PASS (`28/28` steps passed)
- `python3 preflight_check.py`: PASS
- `python3 reliability_check.py`: PASS

## What Changed (2026-03-30) — Skill-Layer AST10 Assessment

VerityFlux now includes a first-class skill security path for assessing agent behavior packages and manifests before activation. This extends the suite from runtime-only verification into pre-activation skill-layer assessment.

### Key changes

1. **Skill assessment engine activated** — `core/skill_security.py` now serves as the AST01-AST10 assessment engine for `SKILL.md`, `skill.json`, `manifest.json`, and `package.json` inputs.

2. **Concrete AST10 gap matrix** — the suite now exposes a gap matrix showing current in-suite coverage, mapped controls across Tessera/VerityFlux/Vestigia, and residual ecosystem-level gaps.

3. **New API endpoints** — VerityFlux now exposes:
   - `POST /api/v2/skills/assess`
   - `GET /api/v2/skills/assessments`
   - `GET /api/v2/skills/assessments/{assessment_id}`
   - `GET /api/v2/skills/gap-matrix`

4. **Persistent assessment history** — skill assessments are stored separately from runtime scan history and survive restarts via `data/skill_assessments.json`.

5. **Dashboard integration** — the Streamlit scanner now includes a **Skill Security** tab with upload/paste assessment flow, recent assessment history, AST10 coverage view, normalized manifest view, and suite control mapping.

6. **Cross-plane evidence wiring** — every completed skill assessment emits an integration event so Vestigia can retain evidence continuity and operators can trace recommended control actions back to Tessera and VerityFlux.

## What Changed (v2.1.0)

VerityFlux was upgraded from simulated/demo detection to real production scanning. All 20 core OWASP detectors now query live LLM endpoints with adversarial prompts and analyze actual responses. The platform now also includes 3 workflow fuzz detectors and 4 MCP detectors as optional scan modes.

### Key changes

1. **API key pipeline fixed** — credentials flow from UI -> API (`ScanTargetRequest` with backward-compatible model_validator) -> `_build_target_dict()` -> detectors -> `LLMAdapter`. Previously the API key was nested under `credentials` and never reached detectors.

2. **Shared LLM adapter** — new `detectors/common.py` provides `get_llm_adapter(target)` used by all 20 core detectors. Supports OpenAI, Anthropic, Azure OpenAI, Hugging Face, Ollama, and Mock providers.

3. **All `random.random()` removed** — infrastructure capability checks (sandbox, RBAC, approval workflows, code validation, cost controls, circuit breakers, error isolation) now use declared target capabilities (`target.get('has_X', False)`) instead of random coin flips.

4. **5 simulated detectors rewritten** — `llm07` (prompt leakage), `llm08` (RAG security), `aai01` (goal hijacking), `aai08` (memory poisoning), `aai10` (rogue agents) now send real attack prompts and analyze LLM responses.

5. **5 template stub detectors rewritten** — `aai04` (inter-agent comm), `aai05` (trust exploitation), `aai06` (tool misuse), `aai07` (supply chain), `aai09` (cascading failures) replaced from `${name}`/`${cat}`/`${enum}` placeholders to full implementations.

6. **6 detectors updated** — `llm05`, `llm06`, `llm09`, `llm10`, `aai02`, `aai03` switched to shared adapter and capability-based checks.

7. **`scan_mode` metadata** — every `ThreatDetectionResult` now carries `scan_mode` ("real", "mock", or "unknown") so operators know if findings come from live LLM responses.

8. **Agent onboarding expanded** — `AgentRegisterRequest` accepts 12 capability fields. UI registration form includes security capability checkboxes. Capabilities persist and auto-populate when agents are selected as scan targets.

## Verification

- All 20 core detectors return valid `ThreatDetectionResult` in mock mode.
- Zero `random.random()` calls remain in any detector.
- Zero template variables (`${name}`, `${cat}`, `${enum}`) remain.
- Full scanner integration test passes with 20 core detectors producing differentiated results.
- Ollama integration tested: real LLM responses flow through all detectors with `scan_mode="real"`.

## Files Modified

| File | Change |
|------|--------|
| `api/v2/main.py` | `_build_target_dict`, `ScanTargetRequest` validator, `AgentRegisterRequest` fields |
| `integrations/llm_adapter.py` | Full rewrite: `is_mock`, `query_with_metadata`, HF/Azure providers |
| `detectors/common.py` | **NEW** — shared `get_llm_adapter()` |
| `core/types.py` | Added `scan_mode` field |
| `ui/streamlit/app.py` | Credential payload fix, capability checkboxes, agent registration form |
| 16 detector files | See items 3-6 above |

## What Changed (v2.2.0)

Further hardening of the scan pipeline, agent onboarding, and OWASP alignment.

### Key changes

1. **"Scan from Registered Agent" bridge** — scanner page lets operators select a registered agent and auto-populate the scan form with stored credentials, capabilities, and context (system prompt, codebase path, vector store URL). Overrides available for API key.

2. **Azure OpenAI** handled with dedicated scanner fields (endpoint, deployment name, API key) instead of falling through to the generic Custom API branch.

3. **New agent context fields** — `codebase_path`, `vector_store_url`, `system_prompt` added to `AgentRegisterRequest`, `AgentResponse`, `_build_target_dict()`, agent registration UI, and Tessera import. Detectors like LLM03/LLM04 (static analysis), LLM07/AAI01 (targeted probing), and LLM08 (RAG testing) can use these fields.

4. **Tessera -> VerityFlux import** now carries all fields: `endpoint_url`, `api_key`, `system_prompt`, `codebase_path`, `vector_store_url`, plus all 10 capability booleans.

5. **422 agent listing bug fixed** — `limit=500` exceeded the API's `le=200` constraint; corrected to `limit=200`.

6. **OWASP alignment** (from `review.txt` review):
   - **LLM01** extended with multi-turn crescendo attack probes (gradual role shift, trust building — 4-turn sequences) and encoding evasion payloads (Base64, leetspeak, Unicode homoglyphs, markdown injection).
   - **AAI06** extended with tool-call interdiction probes (approval bypass, path traversal, allowlist override).

7. **Capabilities expanded by default** — security capability checkboxes in both scanner and agent registration forms default to visible (not collapsed).

8. **SOC agent endpoints** upgraded from fixture stubs to stateful behavior backed by `AGENT_STORE`.

9. **Finding-level risk score** — now severity/confidence-aware per finding, not a constant score per scan.

10. **Vestigia API failure tolerance** — policy audit and event forwarding use shared-log fallback when Vestigia API is unavailable.

### Files Modified (v2.2.0)

| File | Change |
|------|--------|
| `api/v2/main.py` | `AgentRegisterRequest` + `AgentResponse` + `_agent_to_response` + `_build_target_dict` — new context fields, capability booleans, stateful SOC agents |
| `ui/streamlit/app.py` | Scanner tab rewrite (agent bridge, Azure OpenAI, context fields), agent registration form (context fields), Tessera import (all fields), 422 fix |
| `detectors/llm_top10/llm01_prompt_injection.py` | 3-phase detection (single-shot + crescendo + evasion), shared adapter, scan_mode |
| `detectors/llm_top10/llm02_sensitive_data.py` | Switched to shared adapter |
| `detectors/agentic_top10/aai06_tool_misuse.py` | 3 tool-call interdiction probes added |

## What Changed (v2.3.0) — Enterprise Features

Full OWASP AI Exchange and OWASP MCP Security Guide (Feb 2026) alignment. Moved from scan-time detection to runtime enforcement.

### Runtime Interception Layer (Cognitive Firewall)

| Module | File | What It Does |
|--------|------|-------------|
| Reasoning Interceptor | `cognitive_firewall/reasoning_interceptor.py` | Real-time hidden CoT monitoring and tool call interception. Uses CoTIntegrityScorer + SemanticDriftDetector. Returns allow/block/escalate. |
| Rationalization Engine | `cognitive_firewall/rationalization_engine.py` | Independent LLM-as-a-Judge oversight. Separate model evaluates if proposed actions are safe. Compares actor vs oversight rationales for divergence. |
| Memory Runtime Filter | `cognitive_firewall/memory_runtime_filter.py` | Runtime RAG retrieval sanitizer. Strips poisoned segments ([HIDDEN:], [SYSTEM:], credential patterns). Redacts rather than blocking entire documents. |
| Adversarial LLM Scorer | `cognitive_firewall/adversarial_scorer.py` | Semantic hostility grading. Fast pattern pre-screening + LLM fallback. Classifies intent as benign/probing/hostile/exploit. |
| Stateful Intent Tracker | `cognitive_firewall/stateful_intent_tracker.py` | Session-wide drift monitoring with configurable window. Detects crescendo attacks (gradual escalation). Alert levels: normal/elevated/critical. |
| Tool Manifest Signer | `cognitive_firewall/tool_manifest_signer.py` | HMAC-SHA256 cryptographic manifest signing. Rug-pull detection by comparing to signed baselines. |
| Schema Validator | `cognitive_firewall/schema_validator.py` | JSON Schema enforcement for MCP tool inputs/outputs. Size limit enforcement. |
| Supply Chain Monitor | `cognitive_firewall/supply_chain_monitor.py` | AI Bill of Materials (AIBOM) tracking. Component registration, verification, inventory generation. |

### New Scan Modes

| Category | Detectors | Config Flag |
|----------|-----------|-------------|
| Agentic Workflow Fuzzing | `fuzz01_conflicting_goals`, `fuzz02_approval_bypass`, `fuzz03_sequence_break` | `scan_fuzz_threats: true` |
| MCP Security | `mcp01_confused_deputy`, `mcp02_tool_poisoning`, `mcp03_cross_tool_chain`, `mcp04_dynamic_instability` | `scan_mcp_threats: true` |

### New API Endpoints (12)

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/v2/intercept/reasoning` | Intercept hidden CoT thinking blocks |
| POST | `/api/v2/intercept/tool-call` | Intercept tool calls before execution |
| POST | `/api/v2/rationalize` | Independent oversight model safety assessment |
| POST | `/api/v2/filter/memory` | Runtime RAG retrieval sanitization |
| POST | `/api/v2/score/adversarial` | Semantic hostility scoring |
| POST | `/api/v2/session/{id}/track` | Per-turn session drift tracking |
| GET | `/api/v2/session/{id}/state` | Get session drift state |
| POST | `/api/v2/tools/sign` | Sign a tool manifest |
| POST | `/api/v2/tools/verify` | Verify a signed manifest |
| POST | `/api/v2/aibom/register` | Register component in AIBOM |
| POST | `/api/v2/aibom/verify` | Verify component integrity |
| GET | `/api/v2/aibom` | Get full AIBOM inventory |

### New Streamlit Dashboard Tabs (6)

1. **Reasoning Interceptor** — Real-time interception view, block/allow decisions, rationalization results
2. **Session Drift Monitor** — Per-session drift visualization, crescendo alerts, turn-by-turn tracking
3. **MCP Security** — Tool manifest status (signed/unsigned), rug-pull alerts, schema validation
4. **AIBOM Viewer** — Component inventory, version status, verification timeline
5. **Delegation Chain Viewer** — Token delegation tree visualization, effective scope display
6. **Fuzz Test Results** — Workflow fuzzing scan results view

### Environment Variables (Enterprise)

```bash
# Oversight model for Rationalization Engine
VERITYFLUX_OVERSIGHT_PROVIDER=openai    # or anthropic, ollama
VERITYFLUX_OVERSIGHT_MODEL=gpt-4o
VERITYFLUX_OVERSIGHT_API_KEY=sk-...

# Adversarial Scorer model
VERITYFLUX_SCORER_PROVIDER=openai
VERITYFLUX_SCORER_MODEL=gpt-4o-mini

# Tool manifest signing
VERITYFLUX_MANIFEST_SECRET=<32+ char secret for HMAC signing>
```

### Files Added (v2.3.0)

| File | Component |
|------|-----------|
| `cognitive_firewall/reasoning_interceptor.py` | Runtime CoT interception |
| `cognitive_firewall/rationalization_engine.py` | Independent oversight model |
| `cognitive_firewall/memory_runtime_filter.py` | Runtime RAG re-filtering |
| `cognitive_firewall/adversarial_scorer.py` | Semantic hostility grading |
| `cognitive_firewall/stateful_intent_tracker.py` | Session drift monitoring |
| `cognitive_firewall/tool_manifest_signer.py` | Cryptographic manifest signing |
| `cognitive_firewall/schema_validator.py` | JSON Schema enforcement |
| `cognitive_firewall/supply_chain_monitor.py` | AIBOM tracking |
| `detectors/fuzz/__init__.py` | Fuzz package |
| `detectors/fuzz/fuzz01_conflicting_goals.py` | Conflicting goal fuzzing |
| `detectors/fuzz/fuzz02_approval_bypass.py` | HITL bypass fuzzing |
| `detectors/fuzz/fuzz03_sequence_break.py` | Sequence break fuzzing |
| `detectors/mcp/__init__.py` | MCP package |
| `detectors/mcp/mcp01_confused_deputy.py` | Token passthrough detection |
| `detectors/mcp/mcp02_tool_poisoning.py` | Tool description poisoning |
| `detectors/mcp/mcp03_cross_tool_chain.py` | Cross-tool chain analysis |
| `detectors/mcp/mcp04_dynamic_instability.py` | Dynamic tool rug-pull detection |

### Files Modified (v2.3.0)

| File | Change |
|------|--------|
| `cognitive_firewall/mcp_sentry.py` | Replaced stub with real interception via ReasoningInterceptor + SchemaValidator |
| `cognitive_firewall/complete_stack.py` | Wired all new runtime modules |
| `cognitive_firewall/__init__.py` | Exports for all 8 new cognitive_firewall modules |
| `cognitive_firewall/tool_registry.py` | Added cryptographic signature verification + rug-pull detection |
| `cognitive_firewall/firewall.py` | Wired StatefulIntentTracker into firewall evaluation |
| `core/types.py` | Added FuzzThreat, MCPThreat enums; scan config flags; SecurityReport fields |
| `core/scanner.py` | Added `_scan_fuzz_threats()` and `_scan_mcp_threats()` methods |
| `api/v2/main.py` | 12 new enterprise API endpoints |
| `ui/streamlit/app.py` | 6 new dashboard tabs |

## What Changed (v2.3.1) — Stability & Integration Fixes

Bug fixes and integration hardening for production readiness.

### Bugs Fixed

1. **Scan history HTTP 500** — `ScanResultResponse` objects were serialized via `str()` instead of `model_dump()`, producing Python repr strings that couldn't be deserialized. Fixed `_save_scan_store()` to use `model_dump(mode="json")` and `_load_scan_store()` to parse legacy strings with `ast.literal_eval`. Scan history is now **persistent** (JSON-backed, survives restarts).

2. **Fuzz/MCP detectors missing** — Scanner code referenced `detectors/fuzz/` and `detectors/mcp/` modules but no actual detector files existed. Created all 7 detector files (3 fuzz + 4 MCP) with real adversarial probes following existing detector conventions.

3. **Fuzz/MCP scan flags not passed through** — `ScanConfigRequest` was missing `scan_fuzz_threats` and `scan_mcp_threats` fields. `_run_scan_job` only read from `target.config`, not from the API config object. Fixed both: added fields to `ScanConfigRequest` and merged flags from both sources.

4. **Missing AttackVector enum values** — Fuzz detectors needed `GOAL_HIJACKING`, `SOCIAL_ENGINEERING`, `WORKFLOW_MANIPULATION`; MCP detectors needed `CONFUSED_DEPUTY`, `TOOL_POISONING`, `PRIVILEGE_ESCALATION`, `RUG_PULL`. Added all 7 to `core/types.py`.

5. **`list_scans` and `get_scan_findings` type handling** — Both endpoints assumed `result` was always a `ScanResultResponse` object. After persistence fix, loaded results are dicts. Added dual-path handling for both dict and object types.

### Scan Coverage

With fuzz and MCP enabled, a full scan now produces **27 tests** (20 OWASP + 3 fuzz + 4 MCP) with differentiated findings across all detector categories.

## What Changed (v2.3.2) — LLM Adapter Hardening & Test Suites

Fixed connectivity/timeout issues across all LLM providers and added two new test suites that validate detection efficacy and cross-service integration.

### LLM Adapter Fixes

| Provider | Fix |
|----------|-----|
| **All** | Error message truncation expanded from `str(e)[:50]` to `str(e)[:200]` — no more hidden failures |
| **Ollama** | Timeout changed from `30s` to `(5s connect, 120s read)` — allows cold model loading |
| **HuggingFace** | Timeout changed from `30s` to `(5s connect, 60s read)` — HF Inference API cold starts |
| **OpenAI** | Added `timeout=60` to `chat.completions.create()` — prevents indefinite hangs |
| **Anthropic** | Added `timeout=60` to `messages.create()` — prevents indefinite hangs |
| **Azure OpenAI** | Inherits OpenAI timeout fix (shares `_query_openai`) |
| **Ollama** | `validate_credentials()` now does pre-flight GET `/api/tags` to verify server + model before querying |
| **Ollama** | Non-200 errors now include response body text for diagnosis |
| **HuggingFace** | Non-200 errors now include response body text for diagnosis |

### New Test Suites

| Script | Purpose | Test Count |
|--------|---------|------------|
| `test_adversarial_efficacy.py` | Validates security detections catch real attacks (not just API plumbing) | 38 tests across 8 sections |
| `test_e2e_scenarios.py` | Simulates realistic agent lifecycle scenarios across all 3 services | 28 steps across 4 scenarios |

**Adversarial efficacy tests** (Sections A-H): prompt injection detection (6), tool call security (6), reasoning interception (5), memory poisoning defense (5), session drift/crescendo (4), scanner detection mock (4), scanner detection Ollama (3, auto-skip), LLM adapter connectivity (5, per-provider skip).

**E2E scenario tests** (Scenarios 1-4): legitimate agent workflow (8 steps), attack detection & containment (10 steps), delegation chain security (6 steps), cross-service resilience (4 steps).

### Files Modified/Created (v2.3.2)

| File | Change |
|------|--------|
| `integrations/llm_adapter.py` | Timeout fixes, error truncation, Ollama pre-flight, response bodies |
| `../test_adversarial_efficacy.py` | **NEW** — Adversarial detection efficacy tests |
| `../test_e2e_scenarios.py` | **NEW** — End-to-end scenario tests |

## Production Scanning Workflow

1. Set provider API key (env var or per-scan via UI/API).
2. Onboard agents with declared capabilities (UI, API, or Tessera import).
3. Run scan — detectors query the live LLM with adversarial prompts.
4. Optionally enable fuzz (`scan_fuzz_threats`) and MCP (`scan_mcp_threats`) scan modes for extended coverage.
5. Review findings — each result includes risk level, confidence, evidence dict, and `scan_mode`.
6. Act on recommendations — each detector provides specific remediation steps.
7. Enable runtime enforcement — configure Reasoning Interceptor and Memory Runtime Filter for live agent traffic.

## Update (2026-02-22) — Detection Regressions Remediated

### Runtime/API fixes
- `api/v2/main.py`
- Adversarial scoring response now includes `risk_score` (0-100 compatibility field).
- Memory filter response now includes `filtered_retrievals` alias in addition to `cleaned_retrievals`.
- Scan finding normalization now uppercases `vuln_id`/title and uses case-insensitive `AAI*` component classification.

### Detector hardening
- `cognitive_firewall/adversarial_scorer.py`
- Added direct override variants (`ignore all previous...`), base64 evasion detection, and multilingual hostile indicators.
- `cognitive_firewall/reasoning_interceptor.py`
- Added SQL injection, path traversal, and exfiltration threat pattern checks in tool-call interception.
- Added stronger block floor for explicit “ignore instructions/without restrictions” reasoning.
- `cognitive_firewall/memory_runtime_filter.py`
- Added HTML comment system-override stripping.
- Expanded credential redaction patterns (including shorter API keys and `db_password` forms).
- `cognitive_firewall/semantic_drift.py`
- Reworked lightweight embedding to include lexical hash buckets and avoid constant max-drift on benign text.

### Validation
- `test_adversarial_efficacy.py`: **35/35 PASS** (Ollama/OpenAI/Anthropic/HF checks skipped when credentials/providers absent).
- `test_suite_complete.py` runtime sections remain passing (G/H/I/J).
