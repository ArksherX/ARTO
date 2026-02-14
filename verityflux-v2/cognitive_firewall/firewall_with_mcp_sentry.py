#!/usr/bin/env python3
"""
Enhanced Cognitive Firewall with MCP-Sentry Integration

Combines intent validation with protocol-level policy enforcement.
"""

from typing import Dict, Any, Optional
from datetime import datetime, timezone

from .firewall_with_recorder import CognitiveFirewallWithRecorder
from .firewall import AgentAction, FirewallDecision, FirewallAction
from .mcp_sentry import MCPSentry, MCPRequest

class CognitiveFirewallWithMCPSentry(CognitiveFirewallWithRecorder):
    """
    Complete protection stack:
    1. Cognitive Firewall (Intent validation)
    2. MCP-Sentry (Protocol enforcement)
    3. Flight Recorder (Compliance logging)
    """
    
    def __init__(
        self,
        intent_validator=None,
        permission_engine=None,
        impact_analyzer=None,
        config: Optional[Dict] = None,
        enable_flight_recorder: bool = True,
        enable_mcp_sentry: bool = True,
        log_dir: str = "flight_logs"
    ):
        super().__init__(
            intent_validator,
            permission_engine,
            impact_analyzer,
            config,
            enable_flight_recorder,
            log_dir
        )
        
        # Initialize MCP-Sentry
        self.mcp_sentry = MCPSentry() if enable_mcp_sentry else None
        self.enable_mcp_sentry = enable_mcp_sentry
    
    def evaluate(self, agent_action: AgentAction) -> FirewallDecision:
        """
        Two-layer evaluation:
        1. MCP-Sentry (protocol level) - Fast, rule-based
        2. Cognitive Firewall (semantic level) - Deep analysis
        """
        
        # Layer 1: MCP-Sentry (Protocol enforcement)
        if self.enable_mcp_sentry and self.mcp_sentry:
            mcp_request = MCPRequest(
                agent_id=agent_action.agent_id,
                tool_name=agent_action.tool_name,
                parameters=agent_action.parameters,
                timestamp=datetime.now(timezone.utc),
                request_id=f"mcp_{agent_action.agent_id}_{datetime.now(timezone.utc).timestamp()}",
                metadata=agent_action.context
            )
            
            mcp_response = self.mcp_sentry.intercept(mcp_request)
            
            # If MCP-Sentry blocks, skip Cognitive Firewall
            if not mcp_response.allowed:
                # Return FirewallDecision without timestamp parameter
                return FirewallDecision(
                    action=FirewallAction.BLOCK,
                    confidence=100.0,
                    reasoning=f"MCP-Sentry blocked: {mcp_response.reasoning}",
                    risk_score=mcp_response.risk_score,
                    violations=[f"MCP: {v}" for v in mcp_response.violations],
                    recommendations=[
                        "Review MCP policies",
                        "Check tool authorization",
                        "Verify parameters"
                    ]
                )
        
        # Layer 2: Cognitive Firewall (Semantic analysis)
        return super().evaluate(agent_action)
    
    def get_mcp_statistics(self) -> Dict[str, Any]:
        """Get MCP-Sentry statistics"""
        if self.mcp_sentry:
            return self.mcp_sentry.get_statistics()
        return {}

__all__ = ['CognitiveFirewallWithMCPSentry']
