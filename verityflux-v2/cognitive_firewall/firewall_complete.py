#!/usr/bin/env python3
"""
Complete Security Stack for VerityFlux 2.0

Combines ALL security layers:
1. MCP-Sentry (Protocol enforcement)
2. Cognitive Firewall (Intent validation)
3. Sandbox Integration (Physical containment)
4. Flight Recorder (Compliance logging)
"""

from typing import Dict, Any, Optional
from datetime import datetime, timezone

from .firewall_with_mcp_sentry import CognitiveFirewallWithMCPSentry
from .firewall import AgentAction, FirewallDecision, FirewallAction
from .sandbox_integration import SandboxIntegration, SandboxBackend

class CompleteSecurityStack(CognitiveFirewallWithMCPSentry):
    """
    The ULTIMATE security stack with 4 layers:
    
    Layer 1: MCP-Sentry (Fast protocol checks)
    Layer 2: Cognitive Firewall (Deep semantic analysis)
    Layer 3: Sandbox (Physical code containment)
    Layer 4: Flight Recorder (Audit trail)
    """
    
    def __init__(
        self,
        intent_validator=None,
        permission_engine=None,
        impact_analyzer=None,
        config: Optional[Dict] = None,
        enable_flight_recorder: bool = True,
        enable_mcp_sentry: bool = True,
        enable_sandbox: bool = False,
        sandbox_backend: SandboxBackend = SandboxBackend.NONE,
        sandbox_api_key: Optional[str] = None,
        log_dir: str = "flight_logs"
    ):
        super().__init__(
            intent_validator,
            permission_engine,
            impact_analyzer,
            config,
            enable_flight_recorder,
            enable_mcp_sentry,
            log_dir
        )
        
        # Initialize Sandbox
        if enable_sandbox:
            self.sandbox = SandboxIntegration(
                backend=sandbox_backend,
                api_key=sandbox_api_key
            )
            self.enable_sandbox = self.sandbox.enabled
        else:
            self.sandbox = None
            self.enable_sandbox = False
    
    def evaluate_and_execute(
        self,
        agent_action: AgentAction,
        code_to_execute: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Complete evaluation + safe execution pipeline:
        
        1. Evaluate through MCP-Sentry + Cognitive Firewall
        2. If allowed, execute code in sandbox (if provided)
        3. Return decision + execution result
        """
        
        # Step 1: Evaluate through firewall
        decision = self.evaluate(agent_action)
        
        result = {
            'firewall_decision': {
                'action': decision.action.value,
                'allowed': decision.action == FirewallAction.ALLOW,
                'risk_score': decision.risk_score,
                'confidence': decision.confidence,
                'reasoning': decision.reasoning,
                'violations': decision.violations
            },
            'execution_result': None,
            'sandbox_used': False
        }
        
        # Step 2: If allowed and code provided, execute in sandbox
        if decision.action == FirewallAction.ALLOW and code_to_execute:
            if self.enable_sandbox and self.sandbox:
                execution = self.sandbox.execute_safely(code_to_execute)
                result['execution_result'] = execution
                result['sandbox_used'] = execution['contained']
            else:
                result['execution_result'] = {
                    'success': False,
                    'error': 'Sandbox not enabled - code not executed for safety',
                    'contained': False,
                    'backend': 'none'
                }
        
        return result
    
    def get_security_summary(self) -> Dict[str, Any]:
        """Get complete security stack summary"""
        summary = {
            'layers': {
                'mcp_sentry': {
                    'enabled': self.enable_mcp_sentry,
                    'statistics': self.get_mcp_statistics() if self.enable_mcp_sentry else {}
                },
                'cognitive_firewall': {
                    'enabled': True,
                    'statistics': self.get_session_summary()
                },
                'sandbox': {
                    'enabled': self.enable_sandbox,
                    'backend': self.sandbox.backend.value if self.sandbox else 'none'
                },
                'flight_recorder': {
                    'enabled': self.enable_recording
                }
            }
        }
        
        return summary

__all__ = ['CompleteSecurityStack']
