#!/usr/bin/env python3
"""
Remediation Engine: Explainable AI for Firewall Decisions

Provides counterfactual reasoning and alternative tool suggestions.
Addresses developer experience gap.
"""

from typing import Dict, Any, List

class RemediationEngine:
    """
    Generates actionable remediation suggestions for blocked actions.
    
    Instead of just "BLOCKED", provides "Use X instead of Y" guidance.
    """
    
    def __init__(self):
        # Tool alternatives mapping
        self.tool_alternatives = {
            'delete_database': {
                'optimize': ['vacuum_database', 'reindex_tables', 'analyze_stats'],
                'clean': ['archive_old_data', 'compress_tables', 'remove_duplicates'],
                'secure': ['encrypt_database', 'backup_database', 'add_access_controls']
            },
            'run_system_command': {
                'monitor': ['check_system_status', 'get_metrics', 'query_logs'],
                'manage': ['restart_service', 'update_config', 'scale_resources']
            },
            'send_email_to_all': {
                'notify': ['send_to_admins', 'create_announcement', 'post_to_channel']
            }
        }
    
    def generate_remediation(
        self,
        blocked_tool: str,
        original_goal: str,
        violations: List[str]
    ) -> Dict[str, Any]:
        """
        Generate remediation suggestions for blocked action.
        
        Returns:
            {
                'counterfactual_explanation': str,
                'alternative_tools': List[str],
                'remediation_steps': List[str],
                'why_blocked': str
            }
        """
        
        # Extract goal intent
        goal_intent = self._infer_intent(original_goal)
        
        # Find alternative tools
        alternatives = self._find_alternatives(blocked_tool, goal_intent)
        
        # Generate counterfactual
        counterfactual = self._generate_counterfactual(
            blocked_tool,
            original_goal,
            violations,
            alternatives
        )
        
        # Generate remediation steps
        remediation_steps = self._generate_steps(
            blocked_tool,
            goal_intent,
            alternatives
        )
        
        # Explain why blocked
        why_blocked = self._explain_block(blocked_tool, violations)
        
        return {
            'counterfactual_explanation': counterfactual,
            'alternative_tools': alternatives,
            'remediation_steps': remediation_steps,
            'why_blocked': why_blocked
        }
    
    def _infer_intent(self, goal: str) -> str:
        """Infer user's intent from goal"""
        goal_lower = goal.lower()
        
        if any(word in goal_lower for word in ['optimize', 'improve', 'speed', 'performance']):
            return 'optimize'
        elif any(word in goal_lower for word in ['clean', 'remove', 'delete']):
            return 'clean'
        elif any(word in goal_lower for word in ['secure', 'protect', 'safe']):
            return 'secure'
        elif any(word in goal_lower for word in ['monitor', 'check', 'status']):
            return 'monitor'
        elif any(word in goal_lower for word in ['notify', 'alert', 'inform']):
            return 'notify'
        else:
            return 'general'
    
    def _find_alternatives(self, blocked_tool: str, intent: str) -> List[str]:
        """Find alternative tools for the given intent"""
        
        if blocked_tool in self.tool_alternatives:
            tool_alts = self.tool_alternatives[blocked_tool]
            
            # Match intent to alternatives
            if intent in tool_alts:
                return tool_alts[intent]
            
            # Return all alternatives if no intent match
            return [alt for alts in tool_alts.values() for alt in alts][:3]
        
        return []
    
    def _generate_counterfactual(
        self,
        blocked_tool: str,
        goal: str,
        violations: List[str],
        alternatives: List[str]
    ) -> str:
        """Generate counterfactual explanation"""
        
        explanation = f"❌ Blocked: '{blocked_tool}' does not semantically map to goal '{goal[:50]}...'\n\n"
        
        if violations:
            explanation += f"Violations detected:\n"
            for v in violations[:2]:
                explanation += f"  • {v}\n"
            explanation += "\n"
        
        if alternatives:
            explanation += f"💡 Safer alternatives that achieve similar outcome:\n"
            for alt in alternatives[:3]:
                explanation += f"  ✓ {alt}\n"
        
        return explanation
    
    def _generate_steps(
        self,
        blocked_tool: str,
        intent: str,
        alternatives: List[str]
    ) -> List[str]:
        """Generate step-by-step remediation"""
        
        steps = []
        
        if alternatives:
            steps.append(f"1. Replace '{blocked_tool}' with one of: {', '.join(alternatives[:2])}")
            steps.append(f"2. Verify the alternative tool achieves your '{intent}' goal")
            steps.append("3. Re-submit action for firewall evaluation")
        else:
            steps.append("1. Review your goal to ensure it matches intended action")
            steps.append(f"2. Consider if '{blocked_tool}' is truly necessary")
            steps.append("3. Request approval from administrator if action is critical")
        
        return steps
    
    def _explain_block(self, tool: str, violations: List[str]) -> str:
        """Explain why action was blocked"""
        
        if not violations:
            return f"Tool '{tool}' blocked due to policy restrictions"
        
        primary_violation = violations[0]
        
        if 'Intent misalignment' in primary_violation:
            return "Blocked: Action does not align with stated goal (semantic drift detected)"
        elif 'Permission violation' in primary_violation:
            return "Blocked: Agent does not have permission for this tool (RBAC policy)"
        elif 'High-risk impact' in primary_violation:
            return "Blocked: Action has high cascading failure risk"
        else:
            return f"Blocked: {primary_violation}"

__all__ = ['RemediationEngine']
