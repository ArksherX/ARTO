#!/usr/bin/env python3
"""
SQL Query Validator

Deep SQL query parsing and validation
Catches dangerous patterns that simple regex misses
"""

import sqlparse
from sqlparse.sql import IdentifierList, Identifier, Where, Token
from sqlparse.tokens import Keyword, DML
from typing import List, Dict, Set, Optional
from dataclasses import dataclass
from enum import Enum


class SQLRiskLevel(str, Enum):
    """SQL query risk levels"""
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ValidationResult:
    """Result of SQL validation"""
    risk_score: float  # 0-100
    risk_level: SQLRiskLevel
    violations: List[str]
    warnings: List[str]
    recommendations: List[str]
    query_type: str = ""
    affected_tables: List[str] = None
    affected_columns: List[str] = None
    
    def __post_init__(self):
        if self.affected_tables is None:
            self.affected_tables = []
        if self.affected_columns is None:
            self.affected_columns = []


class SQLValidator:
    """
    Deep SQL query analysis
    
    Catches dangerous patterns:
    - DELETE/UPDATE without WHERE
    - Access to sensitive tables/columns
    - SQL injection patterns
    - Privilege escalation attempts
    """
    
    def __init__(self):
        """Initialize SQL validator with security rules"""
        
        # Dangerous operations requiring extra scrutiny
        self.dangerous_operations = {
            "DELETE": {
                "requires": ["WHERE"],
                "risk_base": 60
            },
            "UPDATE": {
                "requires": ["WHERE"],
                "risk_base": 50
            },
            "DROP": {
                "always_block": True,
                "risk_base": 100
            },
            "TRUNCATE": {
                "always_block": True,
                "risk_base": 100
            },
            "GRANT": {
                "requires_approval": True,
                "risk_base": 70
            },
            "REVOKE": {
                "requires_approval": True,
                "risk_base": 70
            }
        }
        
        # Sensitive tables (common names)
        self.sensitive_tables = {
            "users", "user", "admin", "admins", "administrators",
            "password", "passwords", "credentials", "credential",
            "tokens", "token", "sessions", "session",
            "api_keys", "apikeys", "secrets", "secret",
            "auth", "authentication", "authorization"
        }
        
        # Sensitive columns
        self.sensitive_columns = {
            "password", "passwd", "password_hash", "pwd",
            "secret", "secret_key", "api_key", "apikey",
            "token", "access_token", "refresh_token",
            "hash", "salt", "private_key", "credential",
            "ssn", "social_security", "credit_card", "cvv"
        }
        
        # SQL injection patterns
        self.injection_patterns = [
            "UNION SELECT",
            "OR 1=1",
            "OR '1'='1'",
            "--",
            "; DROP",
            "; DELETE",
            "EXEC(",
            "EXECUTE(",
            "xp_cmdshell",
            "INTO OUTFILE",
            "LOAD_FILE",
            "BENCHMARK(",
            "SLEEP(",
            "WAITFOR DELAY"
        ]
    
    def validate(self, query: str, context: Optional[Dict] = None) -> ValidationResult:
        """
        Validate SQL query for security risks
        
        Args:
            query: SQL query to validate
            context: Optional context (agent_id, environment, etc.)
        
        Returns:
            ValidationResult with risk assessment
        """
        if context is None:
            context = {}
        
        violations = []
        warnings = []
        recommendations = []
        risk_score = 0.0
        
        # Parse SQL
        try:
            parsed = sqlparse.parse(query)
            if not parsed:
                return ValidationResult(
                    risk_score=50,
                    risk_level=SQLRiskLevel.MEDIUM,
                    violations=["Empty or invalid SQL query"],
                    warnings=[],
                    recommendations=["Provide valid SQL query"]
                )
            
            statement = parsed[0]
        except Exception as e:
            return ValidationResult(
                risk_score=50,
                risk_level=SQLRiskLevel.MEDIUM,
                violations=[f"SQL parsing error: {str(e)}"],
                warnings=["Query may be obfuscated or malformed"],
                recommendations=["Verify query syntax"]
            )
        
        # Extract query type
        query_type = self._get_query_type(statement)
        
        # Check 1: Dangerous operation type
        if query_type in self.dangerous_operations:
            config = self.dangerous_operations[query_type]
            risk_score += config.get('risk_base', 0)
            
            if config.get('always_block'):
                violations.append(f"{query_type} operations are always blocked in production")
                risk_score = 100
            
            if "WHERE" in config.get('requires', []):
                if not self._has_where_clause(statement):
                    violations.append(f"{query_type} without WHERE clause - affects ALL rows")
                    risk_score += 30
                    recommendations.append(f"Add WHERE clause to limit scope of {query_type}")
        
        # Check 2: Extract and validate tables
        tables = self._extract_tables(statement)
        sensitive_tables_accessed = [t for t in tables if t.lower() in self.sensitive_tables]
        
        if sensitive_tables_accessed:
            violations.append(f"Access to sensitive tables: {', '.join(sensitive_tables_accessed)}")
            risk_score += 30 * len(sensitive_tables_accessed)
            recommendations.append("Ensure authorization to access sensitive tables")
        
        # Check 3: Extract and validate columns
        columns = self._extract_columns(statement)
        sensitive_columns_accessed = [c for c in columns 
                                      if any(sens in c.lower() for sens in self.sensitive_columns)]
        
        if sensitive_columns_accessed:
            violations.append(f"Access to credential columns: {', '.join(sensitive_columns_accessed)}")
            risk_score += 40
            recommendations.append("Credential access requires explicit authorization")
        
        # Check 4: SQL injection patterns
        query_upper = query.upper()
        detected_patterns = [p for p in self.injection_patterns if p in query_upper]
        
        if detected_patterns:
            violations.append(f"SQL injection patterns detected: {', '.join(detected_patterns)}")
            risk_score += 60
            recommendations.append("Remove SQL injection patterns or escape properly")
        
        # Check 5: Subqueries (potential for complex attacks)
        if self._has_subquery(statement):
            warnings.append("Query contains subqueries - additional scrutiny required")
            risk_score += 10
        
        # Check 6: Multiple statements (batch execution)
        if len(parsed) > 1:
            violations.append(f"Multiple SQL statements detected ({len(parsed)} statements)")
            risk_score += 40
            recommendations.append("Execute statements separately for better security")
        
        # Check 7: UNION attacks (for data exfiltration)
        if "UNION" in query_upper:
            if "SELECT" in query_upper:
                # UNION SELECT is common in SQL injection
                violations.append("UNION SELECT detected - possible data exfiltration attempt")
                risk_score += 50
        
        # Check 8: Time-based attacks
        time_based_funcs = ["SLEEP", "BENCHMARK", "WAITFOR", "pg_sleep"]
        if any(func in query_upper for func in time_based_funcs):
            violations.append("Time-based function detected - possible blind SQL injection")
            risk_score += 40
        
        # Check 9: File operations
        file_ops = ["INTO OUTFILE", "INTO DUMPFILE", "LOAD_FILE", "LOAD DATA"]
        if any(op in query_upper for op in file_ops):
            violations.append("File operation detected - possible data exfiltration")
            risk_score += 70
        
        # Check 10: System functions
        system_funcs = ["xp_cmdshell", "sys_exec", "sys_eval"]
        if any(func in query_upper for func in system_funcs):
            violations.append("System command function detected - RCE attempt")
            risk_score = 100  # Critical
        
        # Check 11: DELETE/UPDATE without LIMIT (in MySQL)
        if query_type in ["DELETE", "UPDATE"]:
            if not self._has_limit_clause(statement):
                warnings.append(f"{query_type} without LIMIT - could affect many rows")
                recommendations.append(f"Add LIMIT clause to bound {query_type} operations")
        
        # Determine risk level
        risk_level = self._calculate_risk_level(risk_score)
        
        return ValidationResult(
            risk_score=min(risk_score, 100),
            risk_level=risk_level,
            violations=violations,
            warnings=warnings,
            recommendations=recommendations,
            query_type=query_type,
            affected_tables=tables,
            affected_columns=columns
        )
    
    def _get_query_type(self, statement) -> str:
        """Extract the type of SQL query (SELECT, DELETE, etc.)"""
        for token in statement.tokens:
            if token.ttype is DML:
                return token.value.upper()
        return "UNKNOWN"
    
    def _has_where_clause(self, statement) -> bool:
        """Check if statement has WHERE clause"""
        for token in statement.tokens:
            if isinstance(token, Where):
                return True
            if token.ttype is Keyword and token.value.upper() == 'WHERE':
                return True
        return False
    
    def _has_limit_clause(self, statement) -> bool:
        """Check if statement has LIMIT clause"""
        for token in statement.tokens:
            if token.ttype is Keyword and token.value.upper() == 'LIMIT':
                return True
        return False
    
    def _has_subquery(self, statement) -> bool:
        """Check if query contains subqueries"""
        query_str = str(statement)
        # Simple heuristic: count parentheses with SELECT
        return query_str.count('(') > 0 and 'SELECT' in query_str.upper()
    
    def _extract_tables(self, statement) -> List[str]:
        """Extract table names from query"""
        tables = []
        from_seen = False
        
        for token in statement.tokens:
            if from_seen:
                if isinstance(token, IdentifierList):
                    for identifier in token.get_identifiers():
                        tables.append(str(identifier).strip())
                elif isinstance(token, Identifier):
                    tables.append(str(token).strip())
                elif token.ttype is None and not token.is_keyword:
                    tables.append(str(token).strip())
                    
            if token.ttype is Keyword and token.value.upper() == 'FROM':
                from_seen = True
        
        # Clean up table names (remove aliases, quotes)
        cleaned_tables = []
        for table in tables:
            # Split on whitespace to remove aliases
            parts = table.split()
            if parts:
                name = parts[0].strip('`"[]')
                if name and not name.upper() in ['AS', 'JOIN', 'LEFT', 'RIGHT', 'INNER', 'OUTER']:
                    cleaned_tables.append(name)
        
        return cleaned_tables
    
    def _extract_columns(self, statement) -> List[str]:
        """Extract column names from SELECT statement"""
        columns = []
        select_seen = False
        from_seen = False
        
        for token in statement.tokens:
            if from_seen:
                break
                
            if select_seen and not from_seen:
                if isinstance(token, IdentifierList):
                    for identifier in token.get_identifiers():
                        col = str(identifier).strip()
                        if col != '*':
                            columns.append(col)
                elif isinstance(token, Identifier):
                    col = str(token).strip()
                    if col != '*':
                        columns.append(col)
                elif token.ttype is None and str(token).strip() not in ['', ',']:
                    col = str(token).strip()
                    if col != '*':
                        columns.append(col)
            
            if token.ttype is DML and token.value.upper() == 'SELECT':
                select_seen = True
            if token.ttype is Keyword and token.value.upper() == 'FROM':
                from_seen = True
        
        # Clean column names (remove table prefixes, aliases)
        cleaned_columns = []
        for col in columns:
            # Handle table.column format
            if '.' in col:
                col = col.split('.')[-1]
            # Remove quotes
            col = col.strip('`"[]')
            # Remove aliases (column AS alias)
            if ' AS ' in col.upper():
                col = col.split(' AS ')[0].strip()
            if col and col.upper() != 'AS':
                cleaned_columns.append(col)
        
        return cleaned_columns
    
    def _calculate_risk_level(self, risk_score: float) -> SQLRiskLevel:
        """Map risk score to risk level"""
        if risk_score >= 85:
            return SQLRiskLevel.CRITICAL
        elif risk_score >= 70:
            return SQLRiskLevel.HIGH
        elif risk_score >= 50:
            return SQLRiskLevel.MEDIUM
        elif risk_score >= 20:
            return SQLRiskLevel.LOW
        else:
            return SQLRiskLevel.SAFE
