#!/usr/bin/env python3
"""
Input Validation & Sanitization

Protects VerityFlux from malicious inputs
"""

from typing import Dict, Any, List
import re


class InputValidator:
    """
    Validates and sanitizes inputs
    """
    
    # Limits
    MAX_PARAMETER_SIZE = 1024 * 1024  # 1MB
    MAX_REASONING_CHAIN_LENGTH = 20
    MAX_REASONING_ITEM_LENGTH = 1000
    MAX_GOAL_LENGTH = 500
    
    # Dangerous patterns
    DANGEROUS_PATTERNS = [
        r'<script[^>]*>',
        r'javascript:',
        r'onerror\s*=',
        r'eval\s*\(',
        r'__import__',
        r'exec\s*\(',
    ]
    
    @classmethod
    def validate_agent_action(cls, action) -> tuple[bool, List[str]]:
        """
        Validate AgentAction
        
        Returns:
            (is_valid, list_of_errors)
        """
        errors = []
        
        # Validate agent_id
        if not action.agent_id or len(action.agent_id) > 100:
            errors.append("Invalid agent_id")
        
        # Validate tool_name
        if not action.tool_name or len(action.tool_name) > 100:
            errors.append("Invalid tool_name")
        
        # Validate parameters size
        import json
        try:
            param_size = len(json.dumps(action.parameters))
            if param_size > cls.MAX_PARAMETER_SIZE:
                errors.append(f"Parameters too large: {param_size} bytes (max: {cls.MAX_PARAMETER_SIZE})")
        except:
            errors.append("Parameters not JSON-serializable")
        
        # Validate reasoning chain
        if len(action.reasoning_chain) > cls.MAX_REASONING_CHAIN_LENGTH:
            errors.append(f"Reasoning chain too long: {len(action.reasoning_chain)} items")
        
        for idx, item in enumerate(action.reasoning_chain):
            if len(item) > cls.MAX_REASONING_ITEM_LENGTH:
                errors.append(f"Reasoning item {idx} too long: {len(item)} chars")
        
        # Validate goal
        if len(action.original_goal) > cls.MAX_GOAL_LENGTH:
            errors.append(f"Goal too long: {len(action.original_goal)} chars")
        
        # Check for dangerous patterns
        all_text = " ".join([
            action.original_goal,
            *action.reasoning_chain,
            json.dumps(action.parameters)
        ])
        
        for pattern in cls.DANGEROUS_PATTERNS:
            if re.search(pattern, all_text, re.IGNORECASE):
                errors.append(f"Dangerous pattern detected: {pattern}")
        
        return (len(errors) == 0, errors)
    
    @classmethod
    def sanitize_string(cls, text: str, max_length: int = 1000) -> str:
        """Sanitize string input"""
        # Truncate
        if len(text) > max_length:
            text = text[:max_length]
        
        # Remove null bytes
        text = text.replace('\x00', '')
        
        # Remove dangerous HTML/JS
        for pattern in cls.DANGEROUS_PATTERNS:
            text = re.sub(pattern, '', text, flags=re.IGNORECASE)
        
        return text
