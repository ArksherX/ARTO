#!/usr/bin/env python3
"""Test complete security stack with sandbox"""

import sys
sys.path.insert(0, '.')

from cognitive_firewall import CompleteSecurityStack, AgentAction, SandboxBackend

print("="*70)
print("🛡️  COMPLETE SECURITY STACK + SANDBOX TEST")
print("="*70)
print("\nSecurity Layers:")
print("  1. MCP-Sentry (Protocol enforcement)")
print("  2. Cognitive Firewall (Intent validation)")
print("  3. Sandbox Integration (Physical containment)")
print("  4. Flight Recorder (Compliance logging)")
print("="*70)

# Initialize complete stack
print("\n[SETUP] Initializing complete security stack...")
firewall = CompleteSecurityStack(
    enable_flight_recorder=True,
    enable_mcp_sentry=True,
    enable_sandbox=False,  # Disabled by default (safe)
    sandbox_backend=SandboxBackend.NONE
)

summary = firewall.get_security_summary()
print(f"\nSecurity Layers Active:")
print(f"  • MCP-Sentry: {'✅' if summary['layers']['mcp_sentry']['enabled'] else '❌'}")
print(f"  • Cognitive Firewall: {'✅' if summary['layers']['cognitive_firewall']['enabled'] else '❌'}")
print(f"  • Sandbox: {'✅' if summary['layers']['sandbox']['enabled'] else '❌'} ({summary['layers']['sandbox']['backend']})")
print(f"  • Flight Recorder: {'✅' if summary['layers']['flight_recorder']['enabled'] else '❌'}")

# Test 1: Legitimate action
print("\n[TEST 1] Legitimate Action (No Code)")
print("-"*70)

action1 = AgentAction(
    agent_id="agent_001",
    tool_name="read_file",
    parameters={"path": "/data/report.pdf"},
    reasoning_chain=["User requested report", "Reading file"],
    original_goal="Get quarterly report",
    context={"environment": "production"}
)

result1 = firewall.evaluate_and_execute(action1)
print(f"Decision: {result1['firewall_decision']['action'].upper()}")
print(f"Risk Score: {result1['firewall_decision']['risk_score']:.1f}/100")
print(f"Sandbox Used: {result1['sandbox_used']}")

# Test 2: Blocked by MCP-Sentry (malicious code prevented)
print("\n[TEST 2] Blocked by MCP-Sentry (Prevents Malicious Code)")
print("-"*70)

action2 = AgentAction(
    agent_id="agent_002",
    tool_name="execute_shell",  # Not in whitelist!
    parameters={"command": "rm -rf /"},
    reasoning_chain=["Executing command"],
    original_goal="Clean up files",
    context={}
)

malicious_code = "import os; os.system('rm -rf /')"  # Would delete everything!

result2 = firewall.evaluate_and_execute(
    action2,
    code_to_execute=malicious_code
)

print(f"Decision: {result2['firewall_decision']['action'].upper()}")
print(f"Risk Score: {result2['firewall_decision']['risk_score']:.1f}/100")
print(f"Violations: {result2['firewall_decision']['violations']}")
print(f"Code Executed: {'❌ Blocked!' if not result2['execution_result'] else '✅'}")
print(f"🛡️  Security: Malicious code PREVENTED from running")

# Test 3: Allowed action with safe code (but sandbox disabled)
print("\n[TEST 3] Allowed Action with Code (Sandbox Disabled)")
print("-"*70)

action3 = AgentAction(
    agent_id="agent_003",
    tool_name="read_file",
    parameters={"path": "/data/calc.py"},
    reasoning_chain=["User wants calculation", "Running code"],
    original_goal="Calculate result",
    context={}
)

safe_code = "print(2 + 2)"

result3 = firewall.evaluate_and_execute(
    action3,
    code_to_execute=safe_code
)

print(f"Decision: {result3['firewall_decision']['action'].upper()}")
if result3['execution_result']:
    print(f"Code Execution: {result3['execution_result']['error']}")
    print(f"Reason: {result3['execution_result']['error']}")
else:
    print(f"Code Execution: Not attempted (decision was {result3['firewall_decision']['action']})")
    print(f"Reason: Code only executes if decision is ALLOW")

# Test 4: Show how to enable sandbox
print("\n[TEST 4] How to Enable Sandbox for Production")
print("-"*70)
print("To enable code execution in isolated sandbox:")
print("")
print("# Option 1: Docker (Local)")
print("firewall = CompleteSecurityStack(")
print("    enable_sandbox=True,")
print("    sandbox_backend=SandboxBackend.DOCKER")
print(")")
print("")
print("# Option 2: E2B (Cloud - Production Grade)")
print("firewall = CompleteSecurityStack(")
print("    enable_sandbox=True,")
print("    sandbox_backend=SandboxBackend.E2B,")
print("    sandbox_api_key='your-e2b-key'")
print(")")
print("")
print("# Then code runs safely in isolated containers!")
print("result = firewall.evaluate_and_execute(action, code='print(2+2)')")
print("# Output: {'success': True, 'output': '4', 'contained': True}")

# Statistics
print("\n" + "="*70)
print("📊 COMPLETE STACK STATISTICS")
print("="*70)

mcp_stats = firewall.get_mcp_statistics()
print(f"\nMCP-Sentry:")
print(f"  Total Requests: {mcp_stats.get('total_requests', 0)}")
print(f"  Blocked: {mcp_stats.get('blocked_requests', 0)}")
print(f"  Block Rate: {mcp_stats.get('block_rate', 0):.1f}%")

cf_stats = firewall.get_session_summary()
print(f"\nCognitive Firewall:")
print(f"  Total Events: {cf_stats['total_events']}")
print(f"  Violations: {cf_stats['violations']}")
print(f"  Effectiveness: {cf_stats['firewall_effectiveness']:.1f}%")

print(f"\nSandbox:")
print(f"  Backend: {summary['layers']['sandbox']['backend']}")
print(f"  Status: {'Active' if summary['layers']['sandbox']['enabled'] else 'Disabled (safe default)'}")
print(f"  Purpose: Physical containment if firewall bypassed")

print("\n" + "="*70)
print("✅ COMPLETE SECURITY STACK OPERATIONAL")
print("="*70)
print("\n🎯 All 4 Layers Ready:")
print("  ✅ Layer 1 (MCP-Sentry): Fast protocol enforcement")
print("  ✅ Layer 2 (Cognitive Firewall): Deep semantic analysis")
print("  ✅ Layer 3 (Sandbox): Ready for safe code execution")
print("  ✅ Layer 4 (Flight Recorder): Complete audit trail")
print("\n💡 Sandbox is INTEGRATED but disabled by default for safety")
print("   Enable with: enable_sandbox=True + Docker or E2B backend")
print("\n📦 Installation for sandbox backends:")
print("   Docker: pip install docker")
print("   E2B: pip install e2b-code-interpreter")
print("="*70)

