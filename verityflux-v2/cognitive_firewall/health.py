#!/usr/bin/env python3
"""
Health Check System

Monitors component health
"""

from typing import Dict, List
from datetime import datetime
from enum import Enum


class HealthStatus(str, Enum):
    """Component health status"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class HealthCheck:
    """
    System health checker
    """
    
    def __init__(self, firewall):
        self.firewall = firewall
    
    def check_all(self) -> Dict:
        """Check all components"""
        checks = {
            'vulnerability_db': self._check_vuln_db(),
            'intent_analyzer': self._check_intent_analyzer(),
            'sql_validator': self._check_sql_validator(),
            'hitl_gateway': self._check_hitl(),
            'cache': self._check_cache(),
        }
        
        # Overall status
        statuses = [check['status'] for check in checks.values()]
        
        if all(s == HealthStatus.HEALTHY for s in statuses):
            overall = HealthStatus.HEALTHY
        elif any(s == HealthStatus.UNHEALTHY for s in statuses):
            overall = HealthStatus.UNHEALTHY
        else:
            overall = HealthStatus.DEGRADED
        
        return {
            'status': overall.value,
            'timestamp': datetime.now().isoformat(),
            'components': checks
        }
    
    def _check_vuln_db(self) -> Dict:
        """Check vulnerability database health"""
        try:
            stats = self.firewall.vuln_db.get_statistics()
            vuln_count = stats['total_vulnerabilities']
            
            if vuln_count >= 20:
                status = HealthStatus.HEALTHY
            elif vuln_count >= 10:
                status = HealthStatus.DEGRADED
            else:
                status = HealthStatus.UNHEALTHY
            
            return {
                'status': status.value,
                'vulnerabilities_loaded': vuln_count,
                'message': f"{vuln_count} vulnerability patterns loaded"
            }
        except Exception as e:
            return {
                'status': HealthStatus.UNHEALTHY.value,
                'error': str(e),
                'message': "Vulnerability database offline"
            }
    
    def _check_intent_analyzer(self) -> Dict:
        """Check intent analyzer health"""
        try:
            stats = self.firewall.intent_analyzer.get_statistics()
            categories = stats['known_categories']
            
            return {
                'status': HealthStatus.HEALTHY.value,
                'categories': categories,
                'message': f"{categories} intent categories loaded"
            }
        except Exception as e:
            return {
                'status': HealthStatus.UNHEALTHY.value,
                'error': str(e),
                'message': "Intent analyzer offline"
            }
    
    def _check_sql_validator(self) -> Dict:
        """Check SQL validator health"""
        try:
            # Test with simple query
            test_result = self.firewall.sql_validator.validate("SELECT 1")
            
            return {
                'status': HealthStatus.HEALTHY.value,
                'message': "SQL validator operational"
            }
        except Exception as e:
            return {
                'status': HealthStatus.UNHEALTHY.value,
                'error': str(e),
                'message': "SQL validator offline"
            }
    
    def _check_hitl(self) -> Dict:
        """Check HITL gateway health"""
        try:
            stats = self.firewall.hitl_gateway.get_statistics()
            pending = stats['pending']
            
            if pending > 100:
                status = HealthStatus.DEGRADED
                message = f"{pending} pending approvals - queue backing up"
            else:
                status = HealthStatus.HEALTHY
                message = f"{pending} pending approvals"
            
            return {
                'status': status.value,
                'pending_approvals': pending,
                'message': message
            }
        except Exception as e:
            return {
                'status': HealthStatus.UNHEALTHY.value,
                'error': str(e),
                'message': "HITL gateway offline"
            }
    
    def _check_cache(self) -> Dict:
        """Check cache health"""
        if not self.firewall.cache.enabled:
            return {
                'status': HealthStatus.DEGRADED.value,
                'message': "Cache disabled (degraded performance)"
            }
        
        try:
            # Test cache
            self.firewall.cache.set('health_check', 'ok', ttl=10)
            result = self.firewall.cache.get('health_check')
            
            if result == 'ok':
                return {
                    'status': HealthStatus.HEALTHY.value,
                    'message': "Cache operational"
                }
            else:
                return {
                    'status': HealthStatus.DEGRADED.value,
                    'message': "Cache responding but data inconsistent"
                }
        except Exception as e:
            return {
                'status': HealthStatus.UNHEALTHY.value,
                'error': str(e),
                'message': "Cache offline"
            }
