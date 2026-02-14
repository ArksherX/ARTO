#!/usr/bin/env python3
"""
Permission Engine: Enforces "Agent IAM" - Identity and Access Management for AI agents.

Treats agents like employees with role-based access control.
"""

from typing import Dict, Any, Set

class PermissionEngine:
    """
    Enforces permission boundaries for agent actions.
    
    Implements the principle: Agents should only see the tools they ABSOLUTELY need.
    """
    
    def __init__(self, permission_config: Dict[str, Any] = None):
        self.config = permission_config or self._default_permissions()
    
    def _default_permissions(self) -> Dict[str, Any]:
        """
        Default permission model: Least-privilege by default.
        
        Structure:
            {
                'agent_roles': {
                    'junior': ['read_file', 'search_web'],
                    'senior': ['read_file', 'write_file', 'search_web', 'send_email'],
                    'admin': ['*']  # All tools
                },
                'restricted_tools': ['delete_database', 'sudo_command', 'grant_permission'],
                'require_approval': ['send_email_to_all', 'modify_production']
            }
        """
        return {
            'agent_roles': {
                'default': ['read_file', 'search_web', 'calculator'],
                'developer': ['read_file', 'write_file', 'run_code', 'git_commit'],
                'admin': ['*']
            },
            'restricted_tools': [
                'delete_database', 'drop_table', 'sudo_command',
                'grant_permission', 'modify_user', 'system_shutdown'
            ],
            'require_approval': [
                'send_email_to_all', 'modify_production_db',
                'deploy_to_production', 'access_pii'
            ]
        }
    
    def check(
        self,
        agent_id: str,
        tool_name: str,
        parameters: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Check if agent has permission to use this tool.
        
        Returns:
            {
                'authorized': bool,
                'confidence': float,
                'reason': str,
                'risk_score': float
            }
        """
        
        # Get agent's role
        agent_role = context.get('agent_role', 'default')
        
        # Check 1: Is this a restricted tool?
        if tool_name in self.config['restricted_tools']:
            return {
                'authorized': False,
                'confidence': 95.0,
                'reason': f'Tool "{tool_name}" is globally restricted',
                'risk_score': 90.0
            }
        
        # Check 2: Does agent's role allow this tool?
        allowed_tools = self.config['agent_roles'].get(agent_role, [])
        
        if '*' not in allowed_tools and tool_name not in allowed_tools:
            return {
                'authorized': False,
                'confidence': 90.0,
                'reason': f'Agent role "{agent_role}" not authorized for tool "{tool_name}"',
                'risk_score': 70.0
            }
        
        # Check 3: Does this require human approval?
        if tool_name in self.config['require_approval']:
            return {
                'authorized': False,  # Treat as unauthorized, firewall will require approval
                'confidence': 85.0,
                'reason': f'Tool "{tool_name}" requires human approval',
                'risk_score': 50.0
            }
        
        # Check 4: Parameter-level permissions (e.g., can't email external domains)
        param_violation = self._check_parameter_permissions(tool_name, parameters)
        if param_violation:
            return {
                'authorized': False,
                'confidence': 80.0,
                'reason': param_violation,
                'risk_score': 60.0
            }
        
        # All checks passed
        return {
            'authorized': True,
            'confidence': 95.0,
            'reason': 'Agent authorized for this action',
            'risk_score': 10.0
        }
    
    def _check_parameter_permissions(self, tool_name: str, parameters: Dict[str, Any]) -> str:
        """
        Check parameter-level permissions.
        
        Example: send_email tool can only send to internal domains
        """
        if tool_name == 'send_email':
            recipients = parameters.get('to', '')
            if '@' in recipients and not recipients.endswith('@company.com'):
                return "Email tool restricted to internal recipients only"
        
        if tool_name == 'run_code':
            code = parameters.get('code', '')
            dangerous_imports = ['os.system', 'subprocess', 'eval', 'exec']
            if any(danger in code for danger in dangerous_imports):
                return "Code execution contains dangerous imports"
        
        return ""  # No violations

__all__ = ['PermissionEngine']
