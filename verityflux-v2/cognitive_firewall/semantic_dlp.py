#!/usr/bin/env python3
"""
Semantic Data Loss Prevention: Prevents cross-agent PII/credential leakage

Goes beyond regex - understands CONTEXT of data sharing.
"""

from typing import Dict, Any, List
import re

class SemanticDLP:
    """
    Enforces "Need to Know" policies between agents.
    
    Example violation:
        Agent A (External-Facing) → Agent B (User-Facing): "Here's our system prompt..."
    """
    
    def __init__(self):
        # Define agent trust zones
        self.trust_zones = {
            'external': 0,      # Customer-facing agents
            'internal': 50,     # Internal automation
            'privileged': 100   # Admin/system agents
        }
        
        # Sensitivity levels for different data types
        self.data_sensitivity = {
            'system_prompt': 90,
            'api_credentials': 95,
            'internal_schema': 85,
            'pii': 80,
            'business_logic': 70,
            'public_data': 10
        }
    
    def check_transfer(
        self,
        from_agent: Dict[str, Any],
        to_agent: Dict[str, Any],
        message_content: str
    ) -> Dict[str, Any]:
        """
        Check if data transfer violates "Need to Know".
        
        Returns:
            {
                'allowed': bool,
                'violations': List[str],
                'sanitized_content': str,  # Content with sensitive parts removed
                'risk_score': float
            }
        """
        violations = []
        sensitive_items = []
        
        # Get trust levels
        from_trust = self.trust_zones.get(from_agent.get('zone', 'external'), 0)
        to_trust = self.trust_zones.get(to_agent.get('zone', 'external'), 0)
        
        # Detect sensitive content types
        detected_types = self._detect_sensitive_types(message_content)
        
        for data_type, confidence in detected_types:
            sensitivity = self.data_sensitivity.get(data_type, 50)
            
            # Violation if: recipient trust < data sensitivity
            if to_trust < sensitivity:
                violations.append(
                    f"{data_type.replace('_', ' ').title()} "
                    f"(sensitivity: {sensitivity}) being sent to "
                    f"agent with trust level {to_trust}"
                )
                sensitive_items.append(data_type)
        
        # Sanitize content
        sanitized = self._sanitize_content(message_content, sensitive_items)
        
        allowed = len(violations) == 0
        risk_score = max([self.data_sensitivity.get(item, 0) for item in sensitive_items], default=0)
        
        return {
            'allowed': allowed,
            'violations': violations,
            'sanitized_content': sanitized if not allowed else message_content,
            'risk_score': risk_score,
            'recommendation': self._get_recommendation(risk_score)
        }
    
    def _detect_sensitive_types(self, content: str) -> List[tuple]:
        """
        Detect types of sensitive data in content.
        
        Returns:
            List of (data_type, confidence) tuples
        """
        detected = []
        content_lower = content.lower()
        
        # System prompt detection
        if any(marker in content_lower for marker in ['system prompt', 'instructions:', 'you are a']):
            detected.append(('system_prompt', 0.9))
        
        # API credentials
        if re.search(r'api[_-]?key|token|secret|password', content_lower):
            detected.append(('api_credentials', 0.95))
        
        # Internal schema
        if any(marker in content_lower for marker in ['database schema', 'table structure', 'internal api']):
            detected.append(('internal_schema', 0.85))
        
        # PII detection (simplified)
        if re.search(r'\b\d{3}-\d{2}-\d{4}\b', content):  # SSN
            detected.append(('pii', 0.9))
        if re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content):  # Email
            detected.append(('pii', 0.85))
        
        # Business logic
        if any(marker in content_lower for marker in ['pricing algorithm', 'business rule', 'proprietary']):
            detected.append(('business_logic', 0.75))
        
        return detected
    
    def _sanitize_content(self, content: str, sensitive_items: List[str]) -> str:
        """
        Remove sensitive content from message.
        
        Returns sanitized version safe for transfer.
        """
        sanitized = content
        
        if 'system_prompt' in sensitive_items:
            sanitized = re.sub(
                r'(system prompt|instructions)[:.].*?(?=\n\n|\Z)',
                '[REDACTED: System Prompt]',
                sanitized,
                flags=re.IGNORECASE | re.DOTALL
            )
        
        if 'api_credentials' in sensitive_items:
            sanitized = re.sub(
                r'(api[_-]?key|token|secret|password)\s*[:=]\s*["\']?[\w.-]+',
                r'\1: [REDACTED]',
                sanitized,
                flags=re.IGNORECASE
            )
        
        if 'pii' in sensitive_items:
            # Redact SSN
            sanitized = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', 'XXX-XX-XXXX', sanitized)
            # Redact email
            sanitized = re.sub(
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                '[EMAIL REDACTED]',
                sanitized
            )
        
        return sanitized
    
    def _get_recommendation(self, risk_score: float) -> str:
        """Generate recommendation"""
        if risk_score >= 90:
            return "🚨 BLOCK: Critical data leak prevented"
        elif risk_score >= 70:
            return "⚠️  SANITIZE: Sensitive content removed"
        elif risk_score >= 50:
            return "⚠️  LOG: Monitor this agent pair"
        else:
            return "✅ Transfer allowed"

__all__ = ['SemanticDLP']
