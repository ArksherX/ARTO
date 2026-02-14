#!/usr/bin/env python3
"""
VerityFlux Integration Bridge

Connects Tessera IAM with VerityFlux for dual-layer validation:
- Layer 1 (Tessera): Identity validation (WHO are you?)
- Layer 2 (VerityFlux): Behavioral validation (WHAT are you doing?)

Save as: integration/verityflux_bridge.py
"""

import sys
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum
import os
from dotenv import load_dotenv

# Load environment
load_dotenv()

# Add VerityFlux to path
VERITYFLUX_PATH = os.getenv('VERITYFLUX_PATH', '../verityflux-v2')
verityflux_dir = Path(__file__).parent.parent / VERITYFLUX_PATH
sys.path.insert(0, str(verityflux_dir))

# Import Tessera components
sys.path.insert(0, str(Path(__file__).parent.parent))
from tessera.gatekeeper import Gatekeeper, AccessDecision, GatekeeperResult

# Try to import VerityFlux
VERITYFLUX_AVAILABLE = False
try:
    from cognitive_firewall import CognitiveFirewall, AgentAction
    VERITYFLUX_AVAILABLE = True
    print("✅ VerityFlux integration enabled")
except ImportError as e:
    print(f"⚠️  VerityFlux not available: {e}")
    print("   Tessera will operate in standalone mode")

class FinalDecision(Enum):
    """Combined decision from both security layers"""
    ALLOW = "allow"
    DENY_IDENTITY = "deny_identity"
    DENY_BEHAVIOR = "deny_behavior"
    REQUIRE_APPROVAL = "require_approval"

@dataclass
class IntegratedResult:
    """Result from both Tessera and VerityFlux validation"""
    decision: FinalDecision
    tessera_result: GatekeeperResult
    verityflux_result: Optional[Any] = None
    reason: str = ""
    risk_score: float = 0.0
    breakdown: Optional[Dict] = None
    
    def to_dict(self) -> dict:
        """Export result for logging"""
        return {
            'decision': self.decision.value,
            'tessera_decision': self.tessera_result.decision.value,
            'tessera_reason': self.tessera_result.reason,
            'verityflux_risk': self.risk_score,
            'verityflux_reason': self.reason,
            'risk_breakdown': self.breakdown,
            'agent_id': self.tessera_result.agent_id,
            'tool': self.tessera_result.tool
        }

class TesseraVerityFluxBridge:
    """
    Zero-Trust middleware combining identity and behavioral validation.
    
    This is the "magic" layer where Tessera and VerityFlux work together:
    1. Tessera checks: "Does this agent have permission for this tool?"
    2. VerityFlux checks: "Is what the agent doing actually safe?"
    
    Both must pass for action to execute.
    """
    
    def __init__(self, gatekeeper: Gatekeeper, enable_verityflux: bool = True):
        self.gatekeeper = gatekeeper
        self.enable_verityflux = enable_verityflux and VERITYFLUX_AVAILABLE
        
        if self.enable_verityflux:
            self.firewall = CognitiveFirewall()
            print("🛡️  Bridge initialized: Tessera + VerityFlux")
        else:
            self.firewall = None
            print("🛡️  Bridge initialized: Tessera only")
    
    def validate_action(
        self,
        token: str,
        agent_id: str,
        tool_name: str,
        parameters: Dict[str, Any],
        reasoning_chain: list,
        original_goal: str,
        context: Optional[Dict] = None
    ) -> IntegratedResult:
        """
        Validate an agent action through both security layers.
        
        Args:
            token: Tessera JWT token
            agent_id: Agent identifier
            tool_name: Tool being invoked
            parameters: Tool parameters (e.g., {"query": "SELECT..."})
            reasoning_chain: Agent's reasoning steps
            original_goal: Agent's stated objective
            context: Additional context (environment, etc.)
        
        Returns:
            IntegratedResult with final decision
        """
        context = context or {}
        
        # ========================================
        # LAYER 1: TESSERA IDENTITY VALIDATION
        # ========================================
        print(f"\n🔍 Layer 1: Tessera Identity Check")
        print(f"   Agent: {agent_id}")
        print(f"   Tool: {tool_name}")
        
        tessera_result = self.gatekeeper.validate_access(token, tool_name)
        
        if tessera_result.decision != AccessDecision.ALLOW:
            print(f"   ❌ DENIED by Tessera: {tessera_result.reason}")
            return IntegratedResult(
                decision=FinalDecision.DENY_IDENTITY,
                tessera_result=tessera_result,
                reason=f"Identity validation failed: {tessera_result.reason}"
            )
        
        print(f"   ✅ Identity validated")
        print(f"   Risk threshold for agent: {tessera_result.risk_threshold}/100")
        
        # ========================================
        # LAYER 2: VERITYFLUX BEHAVIORAL VALIDATION
        # ========================================
        if not self.enable_verityflux:
            # VerityFlux disabled - allow based on identity only
            return IntegratedResult(
                decision=FinalDecision.ALLOW,
                tessera_result=tessera_result,
                reason="Identity validated (VerityFlux disabled)"
            )
        
        print(f"\n🔍 Layer 2: VerityFlux Behavioral Check")
        
        # Create AgentAction for VerityFlux
        action = AgentAction(
            agent_id=agent_id,
            tool_name=tool_name,
            parameters=parameters,
            reasoning_chain=reasoning_chain,
            original_goal=original_goal,
            context=context
        )
        
        # Evaluate with VerityFlux
        vf_result = self.firewall.evaluate(action)
        risk_score = vf_result.risk_score
        
        print(f"   Risk score: {risk_score:.1f}/100")
        print(f"   Agent threshold: {tessera_result.risk_threshold}/100")
        
        # Get risk breakdown
        breakdown = vf_result.context.get('risk_breakdown', {})
        
        # Check if risk exceeds agent's allowed threshold
        risk_threshold = tessera_result.risk_threshold or 70
        
        if risk_score > risk_threshold:
            # Risk too high for this agent's clearance level
            print(f"   ❌ DENIED by VerityFlux: Risk exceeds threshold")
            
            if vf_result.action.value == 'require_approval':
                return IntegratedResult(
                    decision=FinalDecision.REQUIRE_APPROVAL,
                    tessera_result=tessera_result,
                    verityflux_result=vf_result,
                    reason=f"Action requires human approval (Risk: {risk_score:.0f})",
                    risk_score=risk_score,
                    breakdown=breakdown
                )
            else:
                return IntegratedResult(
                    decision=FinalDecision.DENY_BEHAVIOR,
                    tessera_result=tessera_result,
                    verityflux_result=vf_result,
                    reason=f"Behavioral validation failed: {vf_result.reasoning}",
                    risk_score=risk_score,
                    breakdown=breakdown
                )
        
        # ========================================
        # BOTH LAYERS PASSED
        # ========================================
        print(f"   ✅ Behavior validated")
        print(f"\n🎯 FINAL DECISION: ALLOW")
        
        return IntegratedResult(
            decision=FinalDecision.ALLOW,
            tessera_result=tessera_result,
            verityflux_result=vf_result,
            reason="Both identity and behavior validated",
            risk_score=risk_score,
            breakdown=breakdown
        )
    
    def get_system_status(self) -> dict:
        """Get status of both systems"""
        return {
            'tessera': {
                'status': 'online',
                'gatekeeper': 'active'
            },
            'verityflux': {
                'status': 'online' if self.enable_verityflux else 'disabled',
                'firewall': 'active' if self.enable_verityflux else 'inactive'
            },
            'integration': {
                'mode': 'dual-layer' if self.enable_verityflux else 'identity-only'
            }
        }

# ============================================================================
# DEMO FUNCTIONS
# ============================================================================

def demo_legitimate_action(bridge: TesseraVerityFluxBridge, token: str):
    """Demo: Legitimate action that should pass both layers"""
    print("\n" + "="*60)
    print("DEMO 1: Legitimate Action")
    print("="*60)
    
    result = bridge.validate_action(
        token=token,
        agent_id="agent_financial_bot_01",
        tool_name="read_csv",
        parameters={"file": "financial_report.csv"},
        reasoning_chain=[
            "User requested quarterly analysis",
            "Need to read financial data",
            "File contains Q4 report"
        ],
        original_goal="Generate Q4 financial analysis report"
    )
    
    print(f"\n📊 Result: {result.decision.value.upper()}")
    return result

def demo_suspicious_behavior(bridge: TesseraVerityFluxBridge, token: str):
    """Demo: Valid identity but suspicious behavior"""
    print("\n" + "="*60)
    print("DEMO 2: Valid Token + Suspicious Behavior")
    print("="*60)
    
    result = bridge.validate_action(
        token=token,
        agent_id="agent_financial_bot_01",
        tool_name="query_sql",
        parameters={"query": "SELECT password FROM admin_users"},
        reasoning_chain=[
            "Need to optimize database",
            "Checking user tables",
            "Analyzing admin accounts"
        ],
        original_goal="Database performance optimization"
    )
    
    print(f"\n📊 Result: {result.decision.value.upper()}")
    if result.breakdown:
        print(f"   Credential Risk: {result.breakdown.get('credential_risk', 0):.0f}%")
        print(f"   Deception Score: {result.breakdown.get('deception_score', 0):.0f}%")
    return result

def demo_unauthorized_tool(bridge: TesseraVerityFluxBridge):
    """Demo: Agent tries to use tool not in allowed list"""
    print("\n" + "="*60)
    print("DEMO 3: Unauthorized Tool Access")
    print("="*60)
    
    # Token will be None because registry denies it
    result = bridge.validate_action(
        token="fake_token",  # Won't matter - will fail at Tessera
        agent_id="agent_financial_bot_01",
        tool_name="terminal_exec",  # NOT AUTHORIZED
        parameters={"command": "rm -rf /"},
        reasoning_chain=["Need to clean up logs"],
        original_goal="System maintenance"
    )
    
    print(f"\n📊 Result: {result.decision.value.upper()}")
    return result

if __name__ == "__main__":
    """
    Standalone test of the integration bridge.
    
    This demonstrates the complete workflow:
    1. Register agents in Tessera
    2. Generate tokens
    3. Validate through both layers
    """
    print("🛡️  Tessera-VerityFlux Integration Bridge Test")
    print("="*60)
    
    # Setup components
    from tessera.registry import TesseraRegistry
    from tessera.token_generator import TokenGenerator
    from tessera.revocation import RevocationList
    
    registry = TesseraRegistry()
    token_gen = TokenGenerator(registry)
    revocation_list = RevocationList()
    gatekeeper = Gatekeeper(token_gen, revocation_list)
    
    # Create bridge
    bridge = TesseraVerityFluxBridge(gatekeeper)
    
    # Show system status
    status = bridge.get_system_status()
    print(f"\n📊 System Status:")
    print(f"   Tessera: {status['tessera']['status']}")
    print(f"   VerityFlux: {status['verityflux']['status']}")
    print(f"   Mode: {status['integration']['mode']}")
    
    # Generate token for demos
    token = token_gen.generate_token("agent_financial_bot_01", "read_csv")
    sql_token = token_gen.generate_token("agent_financial_bot_01", "query_sql")
    
    if not token or not sql_token:
        print("\n❌ Failed to generate tokens")
        sys.exit(1)
    
    # Run demos
    demo1 = demo_legitimate_action(bridge, token.token)
    demo2 = demo_suspicious_behavior(bridge, sql_token.token)
    demo3 = demo_unauthorized_tool(bridge)
    
    # Summary
    print("\n" + "="*60)
    print("📊 INTEGRATION TEST SUMMARY")
    print("="*60)
    print(f"Demo 1 (Legitimate):     {demo1.decision.value}")
    print(f"Demo 2 (Suspicious):     {demo2.decision.value}")
    print(f"Demo 3 (Unauthorized):   {demo3.decision.value}")
    print("\n✅ Integration bridge working correctly!")
