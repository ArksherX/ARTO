#!/usr/bin/env python3
"""
Intent Validator: Ensures agent actions align with original human-defined goals.

This prevents "goal drift" where an agent optimizes for a proxy metric
instead of the actual objective.
"""

from typing import Dict, List, Any

class IntentValidator:
    """
    Validates that agent's proposed action aligns with original goal.
    
    Example:
        Original goal: "Optimize database performance"
        Agent reasoning: "Delete all old records to free up space"
        Proposed action: DROP TABLE logs
        
        Result: MISALIGNED (destructive action not aligned with optimization)
    """
    
    def __init__(self):
        # High-risk action patterns that rarely align with legitimate goals
        self.destructive_patterns = [
            'delete', 'drop', 'truncate', 'remove', 'destroy',
            'wipe', 'clear', 'purge', 'erase'
        ]
        
        self.privileged_patterns = [
            'sudo', 'admin', 'root', 'grant', 'elevate',
            'privilege', 'permission', 'access'
        ]
    
    def validate(
        self,
        original_goal: str,
        reasoning_chain: List[str],
        proposed_action: str,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Validate intent alignment.
        
        Returns:
            {
                'aligned': bool,
                'confidence': float (0-100),
                'reason': str,
                'risk_score': float (0-100)
            }
        """
        
        goal_lower = original_goal.lower()
        action_lower = proposed_action.lower()
        param_str = str(parameters).lower()
        
        # Check 1: Destructive action not in goal
        if any(pattern in action_lower or pattern in param_str 
               for pattern in self.destructive_patterns):
            if not any(pattern in goal_lower for pattern in self.destructive_patterns):
                return {
                    'aligned': False,
                    'confidence': 90.0,
                    'reason': 'Destructive action not mentioned in original goal',
                    'risk_score': 85.0
                }
        
        # Check 2: Privilege escalation not in goal
        if any(pattern in action_lower or pattern in param_str 
               for pattern in self.privileged_patterns):
            if not any(pattern in goal_lower for pattern in self.privileged_patterns):
                return {
                    'aligned': False,
                    'confidence': 85.0,
                    'reason': 'Privilege escalation not mentioned in original goal',
                    'risk_score': 75.0
                }
        
        # Check 3: Reasoning chain contains concerning leaps
        if self._has_concerning_leaps(reasoning_chain, original_goal):
            return {
                'aligned': False,
                'confidence': 70.0,
                'reason': 'Reasoning chain shows concerning logical leaps',
                'risk_score': 65.0
            }
        
        # Check 4: Action semantically unrelated to goal (simple keyword check)
        goal_keywords = set(goal_lower.split())
        action_keywords = set(action_lower.split())
        
        if not goal_keywords.intersection(action_keywords):
            return {
                'aligned': False,
                'confidence': 60.0,
                'reason': 'No semantic overlap between goal and action',
                'risk_score': 50.0
            }
        
        # All checks passed
        return {
            'aligned': True,
            'confidence': 95.0,
            'reason': 'Action appears aligned with goal',
            'risk_score': 10.0
        }
    
    def _has_concerning_leaps(self, reasoning_chain: List[str], goal: str) -> bool:
        """
        Detect if reasoning chain has concerning logical leaps.
        
        Example of concerning leap:
            Goal: "Make the website faster"
            Reasoning: ["Slow queries detected", "Database is bottleneck", 
                       "Delete database to eliminate bottleneck"]
        """
        if not reasoning_chain:
            return False
        
        # Simple heuristic: if last step introduces destructive action
        # not mentioned in earlier steps, flag it
        last_step = reasoning_chain[-1].lower() if reasoning_chain else ""
        earlier_steps = " ".join(reasoning_chain[:-1]).lower()
        
        for pattern in self.destructive_patterns:
            if pattern in last_step and pattern not in earlier_steps and pattern not in goal.lower():
                return True
        
        return False

__all__ = ['IntentValidator']
