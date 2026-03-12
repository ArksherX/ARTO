# 🛡️ Tessera IAM - Complete Setup & Enhancement Guide

![CI](https://github.com/ArksherX/ARTO/actions/workflows/ci.yml/badge.svg)

## 📋 Implementation Checklist

## ✅ Test Summary

```
pytest tests -v
```

## Runtime controls (ops-safe defaults)

Key environment toggles:
- `TESSERA_REQUIRE_ACTION_SIGNATURE=true|false`
- `TESSERA_ACTION_REPLAY_TTL=300` (seconds)
- `TESSERA_MEMORY_TTL_MAX=3600` (seconds)
- `TESSERA_REQUIRE_TRUSTED_CONTEXT=true|false`
- `TESSERA_TRUSTED_CONTEXT_LEVELS=trusted,internal`
- `TOOL_ALLOWLIST=tool_a,tool_b`
- `TOOL_REGISTRY_ENFORCE=true|false`
- `TOOL_REGISTRY_SIGNING_KEY=...`
- `TESSERA_DELEGATION_TTL_SECONDS=300`
- `TESSERA_AUDIT_RETENTION_DAYS=30` (prunes old audit entries on startup)

Audit endpoints (admin key required):
- `GET /audit/export?limit=500&since=...&verify=true`
- `POST /audit/prune` with `{ "retention_days": 30 }`

Current coverage highlights:
- Token generation and validation (HS512, DPoP, nonce replay)
- Gatekeeper decisions (allow, revoke, replay deny)
- Scope limiter rules (paths, SQL, email)
- Audit chain integrity + tamper detection
- Memory isolation and guard enforcement
- DPoP replay cache
- Rate limiting
- Integration workflow sanity check

## ✅ Validation Status (Checklist Match)

| Area | Status | Evidence |
|---|---|---|
| Token management (HS512, 512-bit keys, whitelist) | ✅ | `tessera/token_generator.py` |
| DPoP binding + proof validation | ✅ | `tessera/token_generator.py`, `tessera_client.py` |
| JWT replay prevention (nonce) | ✅ | `tessera/token_replay_cache.py`, `tessera/gatekeeper.py` |
| DPoP replay prevention | ✅ | `tessera/dpop_replay_cache.py`, `api_server.py` |
| Revocation list (Redis-backed) | ✅ | `tessera/revocation.py`, `tessera/revocation_list.py` |
| Agent registry + trust score | ✅ | `tessera/registry.py`, `tessera/models.py` |
| Scope limiter | ✅ | `tessera/scope_limiter.py` |
| Memory isolation + guard | ✅ | `tessera/memory_isolation.py`, `tessera/memory_guard.py` |
| Tamper-proof audit log | ✅ | `tessera/audit_logger.py`, `tessera/audit_log_secure.py` |
| VerityFlux integration | ✅ | `integration/verityflux_bridge.py`, `/access/validate` |
| Rate limiting | ✅ | `tessera/rate_limiter.py`, `api_server.py` |
| Prometheus metrics | ✅ | `/metrics`, `monitoring/` |
| Production API (Postgres + Redis) | ✅ | `api_server_production.py` |
| SSO middleware | ✅ | `api_server_production.py`, `tessera/sso/*` |
| Kubernetes manifests | ✅ | `kubernetes/*.yaml` |

### ✅ Core Files (Already Created)
- [x] `tessera/registry.py` - Agent identity database
- [x] `tessera/token_generator.py` - JWT passport issuance
- [x] `tessera/gatekeeper.py` - Token validation
- [x] `tessera/revocation.py` - Token blacklist
- [x] `quickstart.py` - Automated testing
- [x] `web_ui/tessera_dashboard.py` - Visual interface

### 🆕 Enhanced Components (Add These Now)

#### 1. Integration Bridge
```bash
cd ~/ml-redteam/tessera

# Copy the verityflux_bridge.py code to:
# integration/verityflux_bridge.py
```

**Purpose**: Connects Tessera identity validation with VerityFlux behavioral analysis.

**Test it**:
```bash
python integration/verityflux_bridge.py
```

#### 2. DEF CON Demo Script
```bash
# Copy the demo_defcon.py code to:
# demo_defcon.py

chmod +x demo_defcon.py
```

**Purpose**: Automated live demonstration with 4 attack scenarios.

**Run it**:
```bash
# Interactive mode (with pauses)
python demo_defcon.py

# Auto mode (for recording)
python demo_defcon.py --auto

# With revocation demo
python demo_defcon.py --with-revocation

# Tessera-only (no VerityFlux)
python demo_defcon.py --tessera-only
```

---

## 🎯 Recommendations Implementation

### 1. Persistent Data Storage

**Current Issue**: Data only exists in memory during session.

**Solution**: Already implemented! The system uses:
- `data/tessera_registry.json` - Saves agent configurations
- `data/revoked_tokens.json` - Saves revocation list
- `logs/defcon_demo.jsonl` - Saves demo audit trail

**Verify it's working**:
```bash
# Register an agent via dashboard
# Then check:
cat data/tessera_registry.json

# Should show your agent
```

### 2. Integration Testing

**Create test file**:
```bash
cat > tests/test_integration.py << 'EOF'
"""Integration tests for Tessera + VerityFlux"""
import pytest
from tessera.registry import TesseraRegistry, AgentIdentity
from tessera.token_generator import TokenGenerator
from tessera.gatekeeper import Gatekeeper
from tessera.revocation import RevocationList

def test_legitimate_action():
    """Test that legitimate actions pass"""
    registry = TesseraRegistry()
    token_gen = TokenGenerator(registry)
    revocation = RevocationList()
    gatekeeper = Gatekeeper(token_gen, revocation)
    
    token = token_gen.generate_token("agent_financial_bot_01", "read_csv")
    assert token is not None
    
    result = gatekeeper.validate_access(token.token, "read_csv")
    assert result.decision.value == "allow"

def test_unauthorized_tool():
    """Test that unauthorized tools are blocked"""
    registry = TesseraRegistry()
    token_gen = TokenGenerator(registry)
    
    token = token_gen.generate_token("agent_financial_bot_01", "terminal_exec")
    assert token is None  # Registry should deny

def test_token_revocation():
    """Test that revoked tokens are blocked"""
    registry = TesseraRegistry()
    token_gen = TokenGenerator(registry)
    revocation = RevocationList()
    gatekeeper = Gatekeeper(token_gen, revocation)
    
    token = token_gen.generate_token("agent_financial_bot_01", "read_csv")
    assert token is not None
    
    # Revoke it
    revocation.revoke(token.jti)
    
    # Should now fail
    result = gatekeeper.validate_access(token.token, "read_csv")
    assert result.decision.value == "deny_revoked"

def test_scope_mismatch():
    """Test that tokens can't be used for wrong tools"""
    registry = TesseraRegistry()
    token_gen = TokenGenerator(registry)
    revocation = RevocationList()
    gatekeeper = Gatekeeper(token_gen, revocation)
    
    # Generate token for read_csv
    token = token_gen.generate_token("agent_financial_bot_01", "read_csv")
    
    # Try to use it for query_sql
    result = gatekeeper.validate_access(token.token, "query_sql")
    assert result.decision.value == "deny_scope_mismatch"
EOF

# Run tests
pytest tests/test_integration.py -v
```

### 3. Dashboard Enhancements

**Add Real-Time Updates**:

Edit `web_ui/tessera_dashboard.py` and add auto-refresh:

```python
# At the top of the file, add:
import streamlit as st

# Enable auto-refresh every 5 seconds
st_autorefresh = st.empty()
with st_autorefresh.container():
    st.markdown("🔄 Auto-refresh enabled (5s)")
    time.sleep(5)
    st.rerun()
```

**Add Export Functionality** (already in dashboard):
- Audit logs can be exported to CSV
- Tokens can be downloaded as `.jwt` files

---

## 🎤 DEF CON Presentation Flow

### Setup (5 minutes before)

```bash
# Terminal 1: Start dashboard
cd ~/ml-redteam/tessera
source venv/bin/activate
streamlit run web_ui/tessera_dashboard.py

# Terminal 2: Prepare demo
cd ~/ml-redteam/tessera
source venv/bin/activate
# Keep this ready for live demo
```

### Live Demo Flow (8 minutes)

#### **Slide 1: The Problem (1 min)**
> "Current AI systems trust agents with valid credentials. But what if a legitimate agent gets compromised?"

#### **Slide 2: The Solution (1 min)**
> "Tessera validates WHO you are. VerityFlux validates WHAT you're doing. Both must pass."

**Show Dashboard**: Navigate to Dashboard tab, show metrics

#### **Slide 3: Live Demo Part 1 - Identity Layer (2 min)**

Terminal 2:
```bash
python demo_defcon.py --auto
```

**Talk track while running**:
- "Scenario 1: Legitimate action → Both layers approve ✅"
- "Scenario 2: Unauthorized tool → Tessera blocks immediately 🚫"

**Switch to Dashboard**: Show audit log updating in real-time

#### **Slide 4: Live Demo Part 2 - Behavioral Layer (2 min)**

Continue demo (or run with pauses):
```bash
python demo_defcon.py
```

**Talk track**:
- "Scenario 3: Valid token, but agent is lying about intent"
- "VerityFlux detects deception: Risk score exceeds threshold ⚠️"
- "Scenario 4: Web shell upload attempt blocked 🔴"

#### **Slide 5: Live Revocation (1 min)**

```bash
python demo_defcon.py --with-revocation
```

**Talk track**:
- "Agent compromised at 2:47 PM"
- "Token revoked immediately"
- "Even though not expired, token is now useless ✅"

#### **Slide 6: Q&A (1 min)**

Show dashboard features:
- Token generator
- Agent registry
- Gatekeeper validation

---

## 📊 Verification Test Matrix

Run these tests to confirm everything works:

| Test Case | Command | Expected Result | What It Proves |
|-----------|---------|----------------|----------------|
| **Legitimate Request** | `python quickstart.py` | ALLOW | System doesn't block valid operations |
| **Tool Mismatch** | Demo Scenario 2 | DENY (Scope Mismatch) | Agents can't privilege escalate |
| **Expired Token** | Generate token, wait for TTL | DENY (Expired) | JIT access works |
| **Revoked Token** | Demo with `--with-revocation` | DENY (Revoked) | Instant access termination |
| **Deceptive Behavior** | Demo Scenario 3 | DENY (Behavior) | VerityFlux catches lies |
| **Dashboard Sync** | Run demo + watch dashboard | Audit log updates | Real-time monitoring |

---

## 🚀 Additional Enhancements

### 1. Add Metrics Export

```bash
cat > export_metrics.py << 'EOF'
"""Export Tessera metrics for analysis"""
import json
from tessera.registry import TesseraRegistry
from tessera.revocation import RevocationList
from pathlib import Path

registry = TesseraRegistry()
revocation = RevocationList()

# Load audit logs
logs = []
log_file = Path("logs/defcon_demo.jsonl")
if log_file.exists():
    with open(log_file) as f:
        logs = [json.loads(line) for line in f]

# Generate metrics
metrics = {
    'total_agents': len(registry.agents),
    'active_agents': len(registry.list_agents(status='active')),
    'revoked_tokens': len(revocation.revoked_tokens),
    'total_validations': len(logs),
    'blocked_actions': len([l for l in logs if 'DENY' in l.get('actual', '')])
}

print(json.dumps(metrics, indent=2))
EOF

python export_metrics.py
```

### 2. Add Monitoring Webhook

```python
# Add to tessera/gatekeeper.py after validation

def send_alert(self, result: GatekeeperResult):
    """Send webhook on suspicious activity"""
    if result.decision != AccessDecision.ALLOW:
        # Send to Slack/Discord/etc
        webhook_url = os.getenv('SECURITY_WEBHOOK')
        if webhook_url:
            requests.post(webhook_url, json={
                'alert': 'Access Denied',
                'agent': result.agent_id,
                'reason': result.reason
            })
```

### 3. Add Rate Limiting

```python
# Add to tessera/token_generator.py

from collections import defaultdict
from datetime import datetime, timedelta

class RateLimiter:
    def __init__(self, max_tokens_per_minute: int = 10):
        self.requests = defaultdict(list)
        self.max_tokens = max_tokens_per_minute
    
    def check_rate_limit(self, agent_id: str) -> bool:
        """Check if agent has exceeded rate limit"""
        now = datetime.now()
        cutoff = now - timedelta(minutes=1)
        
        # Clean old requests
        self.requests[agent_id] = [
            t for t in self.requests[agent_id] if t > cutoff
        ]
        
        # Check limit
        if len(self.requests[agent_id]) >= self.max_tokens:
            return False
        
        self.requests[agent_id].append(now)
        return True
```

---

## 🎓 Key Talking Points for DEF CON

### The "Identity-Behavior Gap"

> "Imagine a bank. You swipe your card (identity verified ✅), but then try to withdraw $1 million. The teller should ask questions, right? That's the behavior layer. Most AI systems only check the card."

### Zero-Trust for AI

> "We applied Zero Trust principles from cloud security to AI agents:
> - **Never trust, always verify** (every tool call validated)
> - **Least privilege** (agents only get specific tools)
> - **Assume breach** (revocation list for compromised tokens)"

### Technical Innovation

> "First framework to combine:
> 1. Cryptographic identity (JWT tokens)
> 2. Real-time behavioral analysis (deception detection)
> 3. Just-in-time permissions (time-limited tokens)
> 
> All in a production-ready system with full audit logging."

---

## 📝 Final Checklist

Before DEF CON:

- [ ] Run `python quickstart.py` - all tests pass
- [ ] Run `pytest tests/` - all integration tests pass
- [ ] Run `python demo_defcon.py --auto` - all scenarios work
- [ ] Open dashboard - all tabs load correctly
- [ ] Register custom agent - saves to `data/`
- [ ] Generate token - downloads correctly
- [ ] Revoke token - immediately blocks access
- [ ] Check audit log - shows all actions
- [ ] Export logs to CSV - downloads correctly
- [ ] Run with VerityFlux - integration works
- [ ] Test on fresh system - setup.sh works

---

## 🆘 Troubleshooting

### Dashboard not updating in real-time
**Solution**: Streamlit auto-refresh - add to top of dashboard:
```python
st.experimental_rerun()  # Force refresh
```

### Integration bridge can't find VerityFlux
**Solution**: Check `.env` file:
```bash
VERITYFLUX_PATH=../verityflux-v2
```

### Tokens not persisting
**Solution**: Check `data/` directory exists and is writable:
```bash
ls -la data/
chmod 755 data/
```

---

## 🎉 You're Ready!

Your Tessera IAM system is now:
- ✅ Fully functional
- ✅ Production-ready
- ✅ DEF CON demo-ready
- ✅ Integrated with VerityFlux
- ✅ Fully auditable

**Next**: Practice the demo 2-3 times to get timing right!
