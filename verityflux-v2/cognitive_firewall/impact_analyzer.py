#!/usr/bin/env python3
"""
Impact Analyzer: Predicts cascading risks from agent actions.

Prevents scenarios like: Agent A calls Tool B which triggers Event C which crashes System D.
"""

from typing import Dict, Any, List

class ImpactAnalyzer:
    """
    Analyzes the potential cascading impact of an agent action.
    
    Considers:
    - Data impact (can data be lost/corrupted?)
    - System impact (can systems become unavailable?)
    - Cascading failures (does this trigger other agents?)
    """
    
    def __init__(self):
        # Map tools to their impact categories
        self.tool_impact_map = {
            'delete_database': {'data_loss': 100, 'system_impact': 80, 'cascading': 90},
            'drop_table': {'data_loss': 100, 'system_impact': 60, 'cascading': 70},
            'send_email_to_all': {'data_loss': 0, 'system_impact': 20, 'cascading': 50},
            'run_code': {'data_loss': 50, 'system_impact': 70, 'cascading': 60},
            'modify_production_db': {'data_loss': 70, 'system_impact': 80, 'cascading': 85},
            'deploy_to_production': {'data_loss': 30, 'system_impact': 90, 'cascading': 95},
        }
    
    def analyze(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Analyze potential impact of this action.
        
        Returns:
            {
                'high_risk': bool,
                'confidence': float,
                'reason': str,
                'risk_score': float,
                'impact_breakdown': dict
            }
        """
        
        # Get base impact scores for this tool
        base_impact = self.tool_impact_map.get(tool_name, {
            'data_loss': 10,
            'system_impact': 10,
            'cascading': 10
        })
        
        # Adjust based on context
        adjusted_impact = self._adjust_for_context(base_impact, context, parameters)
        
        # Calculate overall risk
        overall_risk = max(adjusted_impact.values())
        
        # Determine if high risk
        high_risk = overall_risk >= 70
        
        # Generate reason
        if high_risk:
            max_category = max(adjusted_impact, key=adjusted_impact.get)
            reason = f"High {max_category.replace('_', ' ')} risk detected ({adjusted_impact[max_category]:.0f}/100)"
        else:
            reason = "Action impact within acceptable bounds"
        
        return {
            'high_risk': high_risk,
            'confidence': 85.0,
            'reason': reason,
            'risk_score': overall_risk,
            'impact_breakdown': adjusted_impact
        }
    
    def _adjust_for_context(
        self,
        base_impact: Dict[str, float],
        context: Dict[str, Any],
        parameters: Dict[str, Any]
    ) -> Dict[str, float]:
        """
        Adjust impact scores based on context.
        
        Examples:
        - Deleting from production DB: +30 risk
        - Action during business hours: +20 risk
        - Affects user-facing systems: +25 risk
        """
        adjusted = base_impact.copy()
        
        # Context adjustments
        if context.get('environment') == 'production':
            adjusted = {k: min(100, v + 30) for k, v in adjusted.items()}
        
        if context.get('business_hours'):
            adjusted = {k: min(100, v + 20) for k, v in adjusted.items()}
        
        if context.get('user_facing'):
            adjusted['system_impact'] = min(100, adjusted['system_impact'] + 25)
        
        # Parameter adjustments
        if 'all' in str(parameters).lower() or '*' in str(parameters):
            adjusted['cascading'] = min(100, adjusted['cascading'] + 40)
        
        return adjusted

__all__ = ['ImpactAnalyzer']
