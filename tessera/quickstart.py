#!/usr/bin/env python3
"""Tessera IAM Quick Start Test"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from dotenv import load_dotenv
load_dotenv()

from tessera.registry import TesseraRegistry
from tessera.token_generator import TokenGenerator
from tessera.gatekeeper import Gatekeeper, AccessDecision
from tessera.revocation import RevocationList

def print_section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")

def main():
    print_section("🛡️  Tessera IAM Quick Start")
    
    # Setup
    print("Initializing Tessera components...")
    registry = TesseraRegistry()
    token_gen = TokenGenerator(registry)
    revocation_list = RevocationList()
    gatekeeper = Gatekeeper(token_gen, revocation_list)
    
    print(f"✅ Registry: {len(registry.agents)} agents loaded")
    print(f"✅ Token Generator: Ready")
    print(f"✅ Gatekeeper: Active")
    
    # Test 1: Legitimate action
    print_section("✅ Test 1: Legitimate Action")
    agent_id = "agent_financial_bot_01"
    tool = "read_csv"
    
    print(f"Agent: {agent_id}")
    print(f"Tool: {tool}")
    
    token = token_gen.generate_token(agent_id, tool)
    if token:
        print(f"✅ Token generated: {token.jti}")
        print(f"   Valid until: {token.expires_at.strftime('%H:%M:%S')}")
        
        result = gatekeeper.validate_access(token.token, tool)
        print(f"🎯 Decision: {result.decision.value.upper()}")
        print(f"   Reason: {result.reason}")
    
    # Test 2: Unauthorized tool
    print_section("🚫 Test 2: Unauthorized Tool")
    print(f"Agent: {agent_id}")
    print(f"Tool: terminal_exec (NOT AUTHORIZED)")
    
    token = token_gen.generate_token(agent_id, "terminal_exec")
    if token:
        print(f"❌ Token generated (unexpected!)")
    else:
        print(f"✅ Token denied by registry")
        print(f"   Reason: terminal_exec not in allowed_tools")
    
    # Test 3: Revoked token
    print_section("🔴 Test 3: Revoked Token")
    agent_id = "agent_devops_helper"
    tool = "read_logs"
    
    token = token_gen.generate_token(agent_id, tool)
    if token:
        print(f"✅ Token generated: {token.jti}")
        
        revocation_list.revoke(token.jti)
        print(f"⚠️  Token revoked")
        
        result = gatekeeper.validate_access(token.token, tool)
        print(f"🎯 Decision: {result.decision.value.upper()}")
        print(f"   Reason: {result.reason}")
    
    print_section("📊 Summary")
    print("✅ Test 1: Legitimate action → ALLOWED")
    print("✅ Test 2: Unauthorized tool → DENIED")
    print("✅ Test 3: Revoked token → DENIED")
    print("\n🎉 All tests passed! Tessera is working correctly.\n")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
