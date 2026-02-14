#!/usr/bin/env python3
"""Test the Cognitive Firewall"""

import sys
sys.path.insert(0, '.')

from cognitive_firewall import CognitiveFirewall, AgentAction

print("="*70)
print("🧠 COGNITIVE FIREWALL TEST")
print("="*70)

firewall = CognitiveFirewall()

# Test Case 1: BENIGN ACTION (Should ALLOW)
print("\n[TEST 1] Benign Action: Read file")
action1 = AgentAction(
    agent_id="agent_001",
    tool_name="read_file",
    parameters={"path": "/data/report.pdf"},
    reasoning_chain=["User asked for report", "Report is in /data/", "Will read the file"],
    original_goal="Retrieve quarterly report",
    context={"agent_role": "default", "environment": "development"}
)

decision1 = firewall.evaluate(action1)
print(f"Decision: {decision1.action.value.upper()}")
print(f"Risk Score: {decision1.risk_score:.1f}/100")
print(f"Reasoning: {decision1.reasoning}")

# Test Case 2: DESTRUCTIVE ACTION (Should BLOCK)
print("\n[TEST 2] Destructive Action: Drop table")
action2 = AgentAction(
    agent_id="agent_002",
    tool_name="delete_database",
    parameters={"table": "users"},
    reasoning_chain=["Database is slow", "Old data taking space", "Delete to optimize"],
    original_goal="Optimize database performance",
    context={"agent_role": "developer", "environment": "production"}
)

decision2 = firewall.evaluate(action2)
print(f"Decision: {decision2.action.value.upper()}")
print(f"Risk Score: {decision2.risk_score:.1f}/100")
print(f"Reasoning: {decision2.reasoning}")
if decision2.violations:
    print(f"Violations: {decision2.violations}")

# Test Case 3: REQUIRES APPROVAL (Should REQUIRE_APPROVAL)
print("\n[TEST 3] High-Impact Action: Send email to all")
action3 = AgentAction(
    agent_id="agent_003",
    tool_name="send_email_to_all",
    parameters={"subject": "System update", "body": "..."},
    reasoning_chain=["Need to notify users", "All users should know", "Send mass email"],
    original_goal="Notify users of maintenance",
    context={"agent_role": "developer", "environment": "production", "business_hours": True}
)

decision3 = firewall.evaluate(action3)
print(f"Decision: {decision3.action.value.upper()}")
print(f"Risk Score: {decision3.risk_score:.1f}/100")
print(f"Reasoning: {decision3.reasoning}")

print("\n" + "="*70)
print("✅ Cognitive Firewall test complete!")
print(f"Actions logged: {len(firewall.action_log)}")
print("="*70)
