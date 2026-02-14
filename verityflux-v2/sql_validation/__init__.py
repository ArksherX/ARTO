"""
SQL Query Validation

Deep SQL query analysis to catch dangerous patterns
"""

from .validator import SQLValidator, ValidationResult

__all__ = ['SQLValidator', 'ValidationResult']
