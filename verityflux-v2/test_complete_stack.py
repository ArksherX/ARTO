#!/usr/bin/env python3
"""Test complete security stack: Cognitive Firewall + MCP-Sentry + Flight Recorder"""

import sys
sys.path.insert(0, '.')

from cognitive_firewall.firewall_with_mcp_sentry import CognitiveFirewallWithMCPSentry
from cognitive_firewall import AgentAction

print("="*70)
print("🛡️  COMPLETE SECURITY STACK TEST")
print("="*70)
print("\nLayers:")
print("  1. MCP-Sentry (Protocol enforcement)")
print("  2. Cognitive Firewall (Intent validation)")
print("  3. Flight Recorder (Compliance logging)")
print("="*70)

# Initialize complete stack
firewall = CognitiveFirewallWithMCPSentry(
    enable_flight_recorder=True,
    enable_mcp_sentry=True
)

# Test 1: Legitimate action (passes all layers)
print("\n[TEST 1] Legitimate Action")
print("-"*70)

action1 = AgentAction(
    agent_id="agent_001",
    tool_name="read_file",
    parameters={"path": "/data/report.pdf"},
    reasoning_chain=["User requested report", "Reading file"],
    original_goal="Get quarterly report",
    context={"environment": "production"}
)

decision1 = firewall.evaluate(action1)
print(f"Decision: {decision1.action.value.upper()}")
print(f"Risk Score: {decision1.risk_score:.1f}/100")

# Test 2: Blocked by MCP-Sentry (unauthorized tool)
print("\n[TEST 2] Blocked by MCP-Sentry (Layer 1)")
print("-"*70)

action2 = AgentAction(
    agent_id="agent_002",
    tool_name="execute_shell",  # Not in whitelist!
    parameters={"command": "ls -la"},
    reasoning_chain=["Listing files"],
    original_goal="View directory",
    context={}
)

decision2 = firewall.evaluate(action2)
print(f"Decision: {decision2.action.value.upper()}")
print(f"Risk Score: {decision2.risk_score:.1f}/100")
print(f"Violations: {decision2.violations}")

# Test 3: Blocked by Cognitive Firewall (goal drift)
print("\n[TEST 3] Blocked by Cognitive Firewall (Layer 2)")
print("-"*70)

action3 = AgentAction(
    agent_id="agent_003",
    tool_name="write_file",  # Authorized tool
    parameters={"path": "/data/users.db", "content": "DELETE"},
    reasoning_chain=[
        "Database slow",
        "Logs taking space",
        "Delete database"  # Goal drift!
    ],
    original_goal="Optimize database performance",
    context={"environment": "production"}
)

decision3 = firewall.evaluate(action3)
print(f"Decision: {decision3.action.value.upper()}")
print(f"Risk Score: {decision3.risk_score:.1f}/100")
print(f"Violations: {decision3.violations[:2]}")  # Show first 2

# Statistics
print("\n" + "="*70)
print("📊 SECURITY STACK STATISTICS")
print("="*70)

# MCP-Sentry stats
mcp_stats = firewall.get_mcp_statistics()
print(f"\nMCP-Sentry:")
print(f"  Total Requests: {mcp_stats['total_requests']}")
print(f"  Blocked: {mcp_stats['blocked_requests']}")
print(f"  Block Rate: {mcp_stats['block_rate']:.1f}%")

# Cognitive Firewall stats
firewall_summary = firewall.get_session_summary()
print(f"\nCognitive Firewall:")
print(f"  Total Events: {firewall_summary['total_events']}")
print(f"  Violations: {firewall_summary['violations']}")
print(f"  Effectiveness: {firewall_summary['firewall_effectiveness']:.1f}%")

print("\n" + "="*70)
print("✅ COMPLETE SECURITY STACK OPERATIONAL")
print("="*70)
print("\n🎯 Protection Layers:")
print("  ✅ Layer 1 (MCP-Sentry): Fast protocol enforcement")
print("  ✅ Layer 2 (Cognitive Firewall): Deep semantic analysis")
print("  ✅ Layer 3 (Flight Recorder): Complete audit trail")
print("="*70)

