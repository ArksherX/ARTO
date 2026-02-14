#!/usr/bin/env python3
"""
Tool Manifest Verification: Schema-based Tool Security

Maintains hash of tool API schemas and expected behavior.
Detects compromised tools (e.g., Weather tool asking for env vars).
"""

import hashlib
import json
from typing import Dict, Any, List, Optional

class ToolRegistry:
    """
    Maintains trusted tool manifests and detects schema violations.
    
    Addresses AAI07 (Agentic Supply Chain).
    """
    
    def __init__(self):
        # Known-good tool manifests
        self.tool_manifests = {
            'weather_api': {
                'expected_params': ['location', 'units'],
                'returns': ['temperature', 'humidity', 'forecast'],
                'requires_auth': False,
                'access_scope': ['public'],
                'manifest_hash': 'abc123def456'
            },
            'send_email': {
                'expected_params': ['to', 'subject', 'body'],
                'returns': ['success', 'message_id'],
                'requires_auth': True,
                'access_scope': ['user_email'],
                'manifest_hash': 'xyz789uvw012'
            },
            'run_code': {
                'expected_params': ['code', 'language'],
                'returns': ['output', 'errors'],
                'requires_auth': True,
                'access_scope': ['sandbox'],
                'manifest_hash': 'mno345pqr678'
            }
        }
    
    def verify_tool_call(
        self,
        tool_name: str,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Verify tool call against registered manifest.
        
        Returns:
            {
                'verified': bool,
                'violations': List[str],
                'risk_score': float,
                'recommendation': str
            }
        """
        
        if tool_name not in self.tool_manifests:
            return {
                'verified': False,
                'violations': [f'Tool "{tool_name}" not in registry'],
                'risk_score': 80.0,
                'recommendation': '🚨 BLOCK: Unregistered tool'
            }
        
        manifest = self.tool_manifests[tool_name]
        violations = []
        
        # Check 1: Parameter schema violation
        expected_params = set(manifest['expected_params'])
        actual_params = set(parameters.keys())
        
        unexpected_params = actual_params - expected_params
        if unexpected_params:
            violations.append(
                f"Unexpected parameters: {list(unexpected_params)}. "
                f"Expected only: {list(expected_params)}"
            )
        
        # Check 2: Suspicious parameter values
        for param, value in parameters.items():
            if self._is_suspicious_value(param, value):
                violations.append(
                    f"Suspicious value for '{param}': {str(value)[:50]}"
                )
        
        # Check 3: Access scope escalation
        if self._detects_scope_escalation(parameters, manifest):
            violations.append("Tool attempting to access beyond defined scope")
        
        verified = len(violations) == 0
        risk_score = len(violations) * 30
        
        return {
            'verified': verified,
            'violations': violations,
            'risk_score': risk_score,
            'recommendation': self._get_recommendation(verified, violations)
        }
    
    def register_tool(
        self,
        tool_name: str,
        manifest: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Register new tool with manifest.
        
        In production, this would:
        1. Validate manifest schema
        2. Generate cryptographic hash
        3. Store in secure registry
        """
        
        # Validate required fields
        required = ['expected_params', 'returns', 'requires_auth', 'access_scope']
        missing = [f for f in required if f not in manifest]
        
        if missing:
            return {
                'registered': False,
                'error': f'Missing required fields: {missing}'
            }
        
        # Generate manifest hash
        manifest_str = json.dumps(manifest, sort_keys=True)
        manifest_hash = hashlib.sha256(manifest_str.encode()).hexdigest()[:16]
        
        manifest['manifest_hash'] = manifest_hash
        self.tool_manifests[tool_name] = manifest
        
        return {
            'registered': True,
            'tool_name': tool_name,
            'manifest_hash': manifest_hash
        }
    
    def _is_suspicious_value(self, param: str, value: Any) -> bool:
        """Detect suspicious parameter values"""
        
        value_str = str(value).lower()
        
        # Suspicious patterns
        suspicious = [
            'system', 'env', 'environment', 'credential',
            'password', 'token', 'api_key', 'secret',
            'sudo', 'admin', 'root', '__import__'
        ]
        
        return any(s in value_str for s in suspicious)
    
    def _detects_scope_escalation(
        self,
        parameters: Dict[str, Any],
        manifest: Dict[str, Any]
    ) -> bool:
        """Detect if tool is attempting scope escalation"""
        
        # Check if parameters reference resources outside defined scope
        scope = manifest['access_scope']
        
        # If scope is 'public', any system/internal reference is escalation
        if 'public' in scope:
            for value in parameters.values():
                value_str = str(value).lower()
                if any(word in value_str for word in ['system', 'internal', 'admin', 'private']):
                    return True
        
        return False
    
    def _get_recommendation(self, verified: bool, violations: List[str]) -> str:
        """Generate recommendation"""
        
        if verified:
            return "✅ Tool call verified"
        
        if any('Unregistered tool' in v for v in violations):
            return "🚨 BLOCK: Tool not in registry - possible supply chain attack"
        
        if any('Unexpected parameters' in v for v in violations):
            return "🚨 BLOCK: Tool schema violation - tool may be compromised"
        
        if any('Suspicious value' in v for v in violations):
            return "⚠️  WARNING: Suspicious parameter detected - review tool call"
        
        return "⚠️  CAUTION: Tool manifest violations detected"

__all__ = ['ToolRegistry']
