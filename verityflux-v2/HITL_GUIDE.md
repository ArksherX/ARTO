# Human-in-the-Loop (HITL) Guide

## Overview

VerityFlux Enterprise includes a complete Human-in-the-Loop system for high-risk AI agent actions.

## Features

✅ **Approval Queue**: Web UI for reviewing pending actions  
✅ **Notifications**: Slack + Email alerts  
✅ **Auto-Deny**: Security timeout (default: 15 minutes)  
✅ **Learning**: False positive feedback improves detection  
✅ **Audit Trail**: Complete history of all approvals/denials  

## Quick Start

### 1. Enable HITL in Configuration
```python
from cognitive_firewall import EnhancedCognitiveFirewall

firewall = EnhancedCognitiveFirewall(config={
    'enable_hitl': True,
    'hitl_timeout_minutes': 15
})
```

### 2. Configure Notifications (Optional)

**Slack:**
```bash
export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

**Email:**
```bash
export SMTP_HOST=smtp.gmail.com
export SMTP_PORT=587
export SMTP_USERNAME=your-email@gmail.com
export SMTP_PASSWORD=your-app-password
export SMTP_TO_EMAILS=security@company.com
```

### 3. Review Approvals

**Web UI:**
```bash
streamlit run web_ui.py
# Navigate to "HITL Approval Queue"
```

**Command Line:**
```python
from cognitive_firewall.hitl_gateway import HITLGateway

gateway = HITLGateway()

# Get pending requests
pending = gateway.get_pending_requests()

# Approve a request
gateway.approve(
    request_id="HITL-20260124-001",
    reviewer="john.doe@company.com",
    notes="Verified with security team",
    mark_false_positive=False
)
```

## Workflow
```
Agent Action
    ↓
Firewall Evaluation
    ↓
Risk Score ≥ 50? → YES → Submit for Approval
    ↓                         ↓
   NO                    Notify Reviewers
    ↓                         ↓
 ALLOW                   Wait for Decision
                              ↓
                    APPROVE or DENY
                              ↓
                         Execute/Block
```

## Auto-Deny Rules

Actions are auto-denied if:
- No approval within timeout period (default: 15 min)
- Request expires
- System shutdown

## False Positive Learning

When approving, you can mark as false positive:
```python
gateway.approve(
    request_id="...",
    reviewer="...",
    notes="This was flagged incorrectly",
    mark_false_positive=True  # ← System learns from this
)
```

This improves future detection accuracy.

## Statistics
```python
stats = gateway.get_statistics()

print(stats)
# {
#   'total_requests': 127,
#   'pending': 3,
#   'approved': 89,
#   'denied': 32,
#   'auto_denied': 3,
#   'false_positives': 12,
#   'avg_review_time_minutes': 4.2
# }
```

## Best Practices

1. **Set realistic timeouts**: 15-30 minutes for human review
2. **Configure notifications**: Ensure team receives alerts
3. **Mark false positives**: Helps system learn
4. **Review statistics**: Monitor approval patterns
5. **Audit regularly**: Check completed requests

## Integration Examples

### Synchronous (Blocking)
```python
firewall = EnhancedCognitiveFirewall()

result = firewall.execute_with_hitl(action)

if result['allowed']:
    # Execute action
    do_dangerous_thing()
else:
    print(f"Blocked: {result['hitl_status']}")
```

### Asynchronous (Non-Blocking)
```python
decision = firewall.evaluate(action)

if decision.action == "require_approval":
    request_id = decision.context['hitl_request_id']
    print(f"Approval required: {request_id}")
    # Continue with other work
else:
    # Execute immediately
    pass
```

## Troubleshooting

**No notifications received:**
- Check `.env` configuration
- Verify webhook URLs
- Check SMTP credentials

**Requests auto-denying too quickly:**
- Increase `hitl_timeout_minutes`
- Verify team is monitoring queue

**False positives not learning:**
- Ensure `mark_false_positive=True`
- Check intent analyzer logs
