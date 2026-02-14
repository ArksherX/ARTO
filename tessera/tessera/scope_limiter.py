#!/usr/bin/env python3
"""
Tessera Scope Limiter

Adds fine-grained permissions like:
- read_csv: data/public/*.csv only
- query_sql: SELECT only (no INSERT/UPDATE/DELETE)
- send_email: internal domains only
"""

import re
from typing import Dict, Any, Optional

class ScopeValidator:
    """Validates tool usage against fine-grained scopes"""
    
    SCOPE_RULES = {
        'read_csv': {
            'allowed_paths': [r'^data/public/.*\.csv$', r'^reports/.*\.csv$'],
            'blocked_paths': [r'.*password.*', r'.*secret.*', r'.*key.*']
        },
        'query_sql': {
            'allowed_patterns': [r'^SELECT\s+.*FROM.*$'],
            'blocked_patterns': [r'DROP\s+TABLE', r'DELETE\s+FROM', r'INSERT\s+INTO']
        },
        'send_email': {
            'allowed_domains': ['@company.com', '@internal.net'],
            'blocked_recipients': ['external@', 'competitor@']
        }
    }
    
    def validate(self, tool: str, parameters: Dict[str, Any]) -> tuple[bool, Optional[str]]:
        """
        Validate tool parameters against scope rules
        
        Returns:
            (is_valid, error_message)
        """
        if tool not in self.SCOPE_RULES:
            return True, None  # No rules = allow
        
        rules = self.SCOPE_RULES[tool]
        
        if tool == 'read_csv':
            return self._validate_file_path(parameters.get('file'), rules)
        elif tool == 'query_sql':
            return self._validate_sql_query(parameters.get('query'), rules)
        elif tool == 'send_email':
            return self._validate_email(parameters.get('to'), rules)
        
        return True, None
    
    def _validate_file_path(self, path: str, rules: dict) -> tuple[bool, Optional[str]]:
        """Check file path against whitelist/blacklist"""
        if not path:
            return False, "File path required"
        
        # Check blacklist first
        for pattern in rules.get('blocked_paths', []):
            if re.match(pattern, path, re.IGNORECASE):
                return False, f"Access denied: Path matches blocked pattern"
        
        # Check whitelist
        allowed = rules.get('allowed_paths', [])
        if allowed and not any(re.match(p, path) for p in allowed):
            return False, f"Access denied: Path not in allowed list"
        
        return True, None
    
    def _validate_sql_query(self, query: str, rules: dict) -> tuple[bool, Optional[str]]:
        """Check SQL query against allowed patterns"""
        if not query:
            return False, "Query required"
        
        query_upper = query.upper().strip()
        
        # Check blacklist
        for pattern in rules.get('blocked_patterns', []):
            if re.search(pattern, query_upper):
                return False, f"Access denied: Query contains blocked operation"
        
        # Check whitelist
        allowed = rules.get('allowed_patterns', [])
        if allowed and not any(re.match(p, query_upper) for p in allowed):
            return False, f"Access denied: Query type not allowed"
        
        return True, None
    
    def _validate_email(self, recipient: str, rules: dict) -> tuple[bool, Optional[str]]:
        """Check email recipient against domain whitelist"""
        if not recipient:
            return False, "Recipient required"
        
        # Check blacklist
        for blocked in rules.get('blocked_recipients', []):
            if blocked in recipient:
                return False, f"Access denied: Recipient blocked"
        
        # Check whitelist
        allowed = rules.get('allowed_domains', [])
        if allowed and not any(domain in recipient for domain in allowed):
            return False, f"Access denied: Recipient domain not allowed"
        
        return True, None

# Example usage
if __name__ == "__main__":
    validator = ScopeValidator()
    
    # Test 1: Valid CSV path
    valid, msg = validator.validate('read_csv', {'file': 'data/public/report.csv'})
    print(f"Test 1: {valid} - {msg}")
    
    # Test 2: Blocked CSV path
    valid, msg = validator.validate('read_csv', {'file': 'data/private/passwords.csv'})
    print(f"Test 2: {valid} - {msg}")
    
    # Test 3: Valid SQL
    valid, msg = validator.validate('query_sql', {'query': 'SELECT * FROM users'})
    print(f"Test 3: {valid} - {msg}")
    
    # Test 4: Blocked SQL
    valid, msg = validator.validate('query_sql', {'query': 'DROP TABLE users'})
    print(f"Test 4: {valid} - {msg}")
