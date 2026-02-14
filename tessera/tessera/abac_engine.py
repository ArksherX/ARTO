#!/usr/bin/env python3
"""
Attribute-Based Access Control (ABAC)
Fine-grained permissions beyond simple tool names
"""

import re
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum

class AttributeType(Enum):
    RESOURCE_PATH = "resource.path"
    RESOURCE_TAG = "resource.tag"
    TIME_OF_DAY = "time.hour"
    DEPARTMENT = "agent.department"
    RISK_SCORE = "context.risk_score"

@dataclass
class Policy:
    """ABAC Policy definition"""
    policy_id: str
    effect: str  # ALLOW or DENY
    conditions: List[Dict[str, Any]]
    
    def evaluate(self, context: Dict[str, Any]) -> bool:
        """Evaluate if policy matches context"""
        for condition in self.conditions:
            if not self._evaluate_condition(condition, context):
                return False
        return True
    
    def _evaluate_condition(self, condition: Dict, context: Dict) -> bool:
        """Evaluate single condition"""
        attribute = condition['attribute']
        operator = condition['operator']
        value = condition['value']
        
        context_value = self._get_nested_value(context, attribute)
        
        if operator == 'equals':
            return context_value == value
        elif operator == 'in':
            return context_value in value
        elif operator == 'matches':
            return re.match(value, str(context_value)) is not None
        elif operator == 'greater_than':
            return float(context_value) > float(value)
        elif operator == 'less_than':
            return float(context_value) < float(value)
        elif operator == 'between':
            return value[0] <= context_value <= value[1]
        
        return False
    
    def _get_nested_value(self, obj: Dict, path: str) -> Any:
        """Get value from nested dict using dot notation"""
        parts = path.split('.')
        current = obj
        
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
        
        return current

class ABACEngine:
    """
    Attribute-Based Access Control Engine
    Evaluates complex policies beyond simple role checks
    """
    
    def __init__(self):
        self.policies: Dict[str, List[Policy]] = {}
        self._load_default_policies()
    
    def _load_default_policies(self):
        """Load default ABAC policies"""
        # Example: Finance can read_csv only from finance/ directory
        self.add_policy(
            agent_id='agent_financial_bot_01',
            policy=Policy(
                policy_id='finance_csv_restrict',
                effect='ALLOW',
                conditions=[
                    {
                        'attribute': 'resource.path',
                        'operator': 'matches',
                        'value': r'^(data/finance/|data/public/).*\.csv$'
                    }
                ]
            )
        )
        
        # Example: No database writes after business hours
        self.add_policy(
            agent_id='*',  # All agents
            policy=Policy(
                policy_id='no_writes_after_hours',
                effect='DENY',
                conditions=[
                    {
                        'attribute': 'tool.name',
                        'operator': 'in',
                        'value': ['write_database', 'update_database']
                    },
                    {
                        'attribute': 'time.hour',
                        'operator': 'between',
                        'value': [18, 6]  # 6 PM to 6 AM
                    }
                ]
            )
        )
        
        # Example: High-risk operations require low risk score
        self.add_policy(
            agent_id='*',
            policy=Policy(
                policy_id='high_risk_operations',
                effect='DENY',
                conditions=[
                    {
                        'attribute': 'tool.sensitivity',
                        'operator': 'equals',
                        'value': 'high'
                    },
                    {
                        'attribute': 'context.risk_score',
                        'operator': 'greater_than',
                        'value': 30
                    }
                ]
            )
        )
    
    def add_policy(self, agent_id: str, policy: Policy):
        """Add policy for agent"""
        if agent_id not in self.policies:
            self.policies[agent_id] = []
        self.policies[agent_id].append(policy)
    
    def evaluate(
        self, 
        agent_id: str, 
        tool: str, 
        resource_context: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        """
        Evaluate if access should be granted
        
        Returns:
            (is_allowed, reason)
        """
        from datetime import datetime
        
        # Build evaluation context
        context = {
            'agent': {
                'id': agent_id,
                'department': resource_context.get('department', 'unknown')
            },
            'tool': {
                'name': tool,
                'sensitivity': self._get_tool_sensitivity(tool)
            },
            'resource': resource_context.get('resource', {}),
            'time': {
                'hour': datetime.now().hour,
                'day_of_week': datetime.now().weekday()
            },
            'context': resource_context.get('context', {})
        }
        
        # Check agent-specific policies
        agent_policies = self.policies.get(agent_id, [])
        wildcard_policies = self.policies.get('*', [])
        
        all_policies = agent_policies + wildcard_policies
        
        # Evaluate DENY policies first (fail-safe)
        for policy in all_policies:
            if policy.effect == 'DENY' and policy.evaluate(context):
                return False, f"Denied by policy: {policy.policy_id}"
        
        # Then check ALLOW policies
        has_allow = False
        for policy in all_policies:
            if policy.effect == 'ALLOW' and policy.evaluate(context):
                has_allow = True
                break
        
        if has_allow:
            return True, "Allowed by ABAC policy"
        
        # Default deny if no explicit ALLOW
        if agent_policies:  # If there are agent-specific policies
            return False, "No matching ALLOW policy"
        
        # If no policies defined, allow (backward compatible)
        return True, "No ABAC policies defined"
    
    def _get_tool_sensitivity(self, tool: str) -> str:
        """Classify tool sensitivity"""
        high_sensitivity = [
            'delete_database', 'write_database', 'grant_access',
            'terminal_exec', 'export_entire_database'
        ]
        
        medium_sensitivity = [
            'write_file', 'send_email', 'post_social'
        ]
        
        if tool in high_sensitivity:
            return 'high'
        elif tool in medium_sensitivity:
            return 'medium'
        else:
            return 'low'

# Singleton
_abac_engine = None

def get_abac_engine() -> ABACEngine:
    global _abac_engine
    if _abac_engine is None:
        _abac_engine = ABACEngine()
    return _abac_engine
