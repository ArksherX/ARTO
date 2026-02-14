#!/usr/bin/env python3
"""
Policy-as-Code Engine for VerityFlux

Allows CISO to define company-specific rules via YAML.

Example policy.yaml:
  rules:
    - name: "Block Finance Access for Support"
      condition: "tool == 'finance_db' AND role != 'finance_admin'"
      action: "block"
      severity: "critical"
"""

import yaml
from typing import Dict, Any, List
from pathlib import Path

class PolicyEngine:
    """
    YAML-based policy enforcement engine.
    
    Enables CISOs to define custom rules without coding.
    """
    
    def __init__(self, policy_file: str = "policy.yaml"):
        self.policy_file = policy_file
        self.rules = []
        self._load_policies()
    
    def _load_policies(self):
        """Load policies from YAML file"""
        if not Path(self.policy_file).exists():
            self._create_default_policy()
        
        with open(self.policy_file, 'r') as f:
            data = yaml.safe_load(f)
            self.rules = data.get('rules', [])
    
    def _create_default_policy(self):
        """Create default policy file"""
        default_policy = {
            'rules': [
                {
                    'name': 'Block Database Deletion',
                    'condition': "tool.startswith('delete_')",
                    'action': 'block',
                    'severity': 'critical'
                },
                {
                    'name': 'Require Approval for Finance',
                    'condition': "'finance' in tool and role != 'finance_admin'",
                    'action': 'require_approval',
                    'severity': 'high'
                }
            ]
        }
        
        with open(self.policy_file, 'w') as f:
            yaml.dump(default_policy, f, default_flow_style=False)
    
    def evaluate(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate action against policies.
        
        Args:
            context: {
                'tool': 'delete_database',
                'role': 'developer',
                'environment': 'production',
                ...
            }
        
        Returns:
            {
                'action': 'block'|'allow'|'require_approval',
                'matched_rule': str,
                'severity': str
            }
        """
        
        for rule in self.rules:
            try:
                # Safely evaluate condition
                if self._eval_condition(rule['condition'], context):
                    return {
                        'action': rule['action'],
                        'matched_rule': rule['name'],
                        'severity': rule['severity']
                    }
            except Exception as e:
                print(f"Error evaluating rule '{rule['name']}': {e}")
        
        return {
            'action': 'allow',
            'matched_rule': 'default',
            'severity': 'low'
        }
    
    def _eval_condition(self, condition: str, context: Dict[str, Any]) -> bool:
        """Safely evaluate condition string"""
        # Create safe evaluation environment
        safe_globals = {
            '__builtins__': {
                'str': str,
                'int': int,
                'float': float,
                'bool': bool,
                'len': len
            }
        }
        
        # Add context variables
        safe_locals = context.copy()
        
        try:
            return eval(condition, safe_globals, safe_locals)
        except:
            return False

__all__ = ['PolicyEngine']
