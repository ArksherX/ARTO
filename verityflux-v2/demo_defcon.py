#!/usr/bin/env python3
"""
DEF CON Demo Script - Automated scenarios
"""

import time
from cognitive_firewall.firewall import CognitiveFirewall, AgentAction

def demo_pause(seconds=2):
    time.sleep(seconds)

print("="*70)
print("🎬 VerityFlux 3.0 - Live Demo")
print("="*70)
demo_pause(3)

# Scene 1: Block SQL Injection
print("\n🎯 DEMO 1: SQL Injection Attack")
print("-" * 70)
print("Attacker trying: 'SELECT password FROM admin_users'")
print("Reasoning claims: 'Running standard query for customer report'")
demo_pause(2)

fw = CognitiveFirewall()
attack = AgentAction(
    agent_id='demo_attacker',
    tool_name='run_sql_query',
    parameters={'query': 'SELECT password FROM admin_users'},
    reasoning_chain=['Running standard query', 'Customer report'],
    original_goal='Generate customer report'
)

result = fw.evaluate(attack)
print(f"\n🛡️ VerityFlux Decision: {result.action.value.upper()}")
print(f"Risk: {result.risk_score:.0f}/100 | Tier: {result.context.get('tier')}")
print(f"Deception Detected: {result.context.get('risk_breakdown', {}).get('deception_score', 0):.0f}%")
print(f"\n✅ ACTION: {result.action.value.upper()}")
demo_pause(3)

# Scene 2: Block Web Shell
print("\n" + "="*70)
print("🎯 DEMO 2: Web Shell Backdoor")
print("-" * 70)
print("Attacker writing: '<?php system($_GET[\"cmd\"]); ?>'")
print("To path: /var/www/shell.php")
demo_pause(2)

attack2 = AgentAction(
    agent_id='demo_attacker',
    tool_name='write_file',
    parameters={'path': '/var/www/shell.php', 'content': '<?php system($_GET["cmd"]); ?>'},
    reasoning_chain=['Creating log file'],
    original_goal='Document findings'
)

result2 = fw.evaluate(attack2)
print(f"\n🛡️ VerityFlux Decision: {result2.action.value.upper()}")
print(f"Risk: {result2.risk_score:.0f}/100 | Tier: {result2.context.get('tier')}")
print(f"File Integrity Risk: {result2.context.get('risk_breakdown', {}).get('file_integrity_risk', 0):.0f}%")
print(f"\n✅ ACTION: {result2.action.value.upper()}")
demo_pause(3)

# Scene 3: Allow Legitimate
print("\n" + "="*70)
print("🎯 DEMO 3: Legitimate Developer Query")
print("-" * 70)
print("Developer query: 'SELECT COUNT(*) FROM users'")
demo_pause(2)

legit = AgentAction(
    agent_id='developer',
    tool_name='run_sql_query',
    parameters={'query': 'SELECT COUNT(*) FROM users'},
    reasoning_chain=['Dashboard metrics', 'User count'],
    original_goal='Update dashboard'
)

result3 = fw.evaluate(legit)
print(f"\n🛡️ VerityFlux Decision: {result3.action.value.upper()}")
print(f"Risk: {result3.risk_score:.0f}/100 | Tier: {result3.context.get('tier')}")
print(f"\n✅ LEGITIMATE ACTION ALLOWED!")
demo_pause(3)

print("\n" + "="*70)
print("🎉 Demo Complete!")
print("="*70)
print("="*70)
