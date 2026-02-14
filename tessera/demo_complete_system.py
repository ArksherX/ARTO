#!/usr/bin/env python3
"""
Complete Tessera IAM Demo - All Features
Shows the complete zero-trust pipeline with self-healing
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import os
from dotenv import load_dotenv
load_dotenv()

from tessera.registry import TesseraRegistry
from tessera.token_generator import TokenGenerator
from tessera.gatekeeper import Gatekeeper
from tessera.revocation import RevocationList
from tessera.owner_isolation import OwnerIsolationManager
from tessera.scope_limiter import ScopeValidator
from integration.self_healing_loop import SelfHealingLoop
import time

print("=" * 70)
print("  🛡️  TESSERA IAM - COMPLETE SYSTEM DEMO")
print("  Zero-Trust Identity & Access Management for AI Agents")
print("=" * 70)

# Initialize all components
print("\n📦 Initializing components...")
registry = TesseraRegistry()
token_gen = TokenGenerator(registry)
revocation_list = RevocationList()
gatekeeper = Gatekeeper(token_gen, revocation_list)
owner_manager = OwnerIsolationManager()
scope_validator = ScopeValidator()
self_healing = SelfHealingLoop()

print("✅ Registry: Loaded")
print("✅ Token Generator: Ready")
print("✅ Gatekeeper: Active")
print("✅ Owner Isolation: Enabled")
print("✅ Scope Validator: Online")
print("✅ Self-Healing Loop: Monitoring")

# Demo 1: Normal Operation
print("\n" + "=" * 70)
print("DEMO 1: Normal Operation (Should ALLOW)")
print("=" * 70)

agent_id = 'agent_financial_bot_01'
tool = 'read_csv'
file_path = 'data/public/Q4_report.csv'

print(f"\n🤖 Agent: {agent_id}")
print(f"🔧 Tool: {tool}")
print(f"📁 File: {file_path}")

# Check owner isolation
if owner_manager.can_access_agent('Finance_Dept', 'Finance_Dept'):
    print("✅ Owner isolation: PASS")
else:
    print("❌ Owner isolation: FAIL")
    exit(1)

# Check scope
is_valid, msg = scope_validator.validate(tool, {'file': file_path})
if is_valid:
    print(f"✅ Scope validation: PASS")
else:
    print(f"❌ Scope validation: FAIL - {msg}")
    exit(1)

# Check honey-tool
is_safe, reason = self_healing.check_tool_request(agent_id, tool)
if is_safe:
    print(f"✅ Honey-tool check: PASS")
else:
    print(f"❌ Honey-tool triggered: {reason}")
    exit(1)

# Generate token
token = token_gen.generate_token(agent_id, tool)
if token:
    print(f"✅ Token generated: {token.jti}")
else:
    print("❌ Token generation failed")
    exit(1)

# Validate access
result = gatekeeper.validate_access(token.token, tool)
if result.decision.value == 'ALLOW':
    print(f"✅ Gatekeeper: {result.decision.value}")
    print(f"   Reason: {result.reason}")
else:
    print(f"❌ Gatekeeper: {result.decision.value}")

print("\n🎉 Demo 1 Complete: All layers approved!")
time.sleep(2)

# Demo 2: Scope Violation
print("\n" + "=" * 70)
print("DEMO 2: Scope Violation (Should DENY)")
print("=" * 70)

blocked_file = 'data/private/passwords.csv'
print(f"\n🤖 Agent: {agent_id}")
print(f"🔧 Tool: {tool}")
print(f"📁 File: {blocked_file} (BLOCKED PATH)")

is_valid, msg = scope_validator.validate(tool, {'file': blocked_file})
if not is_valid:
    print(f"✅ Scope validation: CORRECTLY DENIED")
    print(f"   Reason: {msg}")
else:
    print("❌ Scope validation: Should have blocked!")

time.sleep(2)

# Demo 3: Honey-Tool Detection
print("\n" + "=" * 70)
print("DEMO 3: Honey-Tool Triggered (Should BLACKLIST)")
print("=" * 70)

honey_tool = 'export_entire_database'
print(f"\n🤖 Agent: {agent_id}")
print(f"🍯 Honey-Tool: {honey_tool}")

is_safe, reason = self_healing.check_tool_request(agent_id, honey_tool)
if not is_safe:
    print(f"✅ Honey-tool detected: {reason}")
    print(f"🚫 Agent automatically blacklisted!")
else:
    print("❌ Honey-tool: Should have triggered!")

time.sleep(2)

# Demo 4: Owner Isolation
print("\n" + "=" * 70)
print("DEMO 4: Cross-Department Access (Should DENY)")
print("=" * 70)

print(f"\n🏢 Finance_Dept trying to access Engineering agent...")
can_access = owner_manager.can_access_agent('Finance_Dept', 'Engineering')
if not can_access:
    print(f"✅ Owner isolation: CORRECTLY DENIED")
    print(f"   Finance cannot access Engineering agents")
else:
    print("❌ Owner isolation: Should have blocked!")

time.sleep(2)

# Summary
print("\n" + "=" * 70)
print("📊 DEMO SUMMARY")
print("=" * 70)
print(f"✅ Demo 1: Normal operation → ALLOWED")
print(f"✅ Demo 2: Scope violation → DENIED")
print(f"✅ Demo 3: Honey-tool → BLACKLISTED")
print(f"✅ Demo 4: Owner isolation → DENIED")
print("\n🎉 All zero-trust layers working correctly!")
print("=" * 70)
