#!/usr/bin/env python3
"""
VerityFlux Configuration Manager
"""

import os
from pathlib import Path
from typing import Dict, Any
import json


class Config:
    """Centralized configuration"""
    
    def __init__(self, config_file: str = None):
        """
        Load configuration from file and environment
        
        Args:
            config_file: Path to JSON config file (optional)
        """
        self.config = self._load_defaults()
        
        # Load from file if provided
        if config_file and Path(config_file).exists():
            with open(config_file, 'r') as f:
                file_config = json.load(f)
                self.config.update(file_config)
        
        # Override with environment variables
        self._load_from_env()
    
    def _load_defaults(self) -> Dict[str, Any]:
        """Default configuration"""
        return {
            # Firewall thresholds
            'critical_threshold': 75.0,
            'high_threshold': 50.0,
            'medium_threshold': 30.0,
            
            # Feature toggles
            'enable_vuln_db': True,
            'enable_intent_analysis': True,
            'enable_sql_validation': True,
            'enable_hitl': True,
            'log_all': True,
            
            # HITL settings
            'hitl_timeout_minutes': 15,
            'hitl_auto_approve_low_risk': False,
            
            # Notification settings
            'slack_webhook_url': None,
            'email_enabled': False,
            
            # CVE API
            'nvd_api_key': None,
            
            # Paths
            'log_dir': 'flight_logs',
            'reports_dir': 'reports',
            'hitl_queue_dir': 'hitl_queue'
        }
    
    def _load_from_env(self) -> None:
        """Load configuration from environment variables"""
        
        # CVE API
        if os.getenv('NVD_API_KEY'):
            self.config['nvd_api_key'] = os.getenv('NVD_API_KEY')
        
        # Slack
        if os.getenv('SLACK_WEBHOOK_URL'):
            self.config['slack_webhook_url'] = os.getenv('SLACK_WEBHOOK_URL')
        
        # Email
        if os.getenv('SMTP_USERNAME') and os.getenv('SMTP_PASSWORD'):
            self.config['email_enabled'] = True
        
        # HITL
        if os.getenv('HITL_TIMEOUT_MINUTES'):
            self.config['hitl_timeout_minutes'] = int(os.getenv('HITL_TIMEOUT_MINUTES'))
        
        if os.getenv('HITL_AUTO_APPROVE_LOW_RISK'):
            self.config['hitl_auto_approve_low_risk'] = os.getenv('HITL_AUTO_APPROVE_LOW_RISK').lower() == 'true'
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        return self.config.get(key, default)
    
    def save(self, filepath: str) -> None:
        """Save current configuration to file"""
        with open(filepath, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def __getitem__(self, key: str) -> Any:
        """Allow dict-like access"""
        return self.config[key]
    
    def __setitem__(self, key: str, value: Any) -> None:
        """Allow dict-like assignment"""
        self.config[key] = value


# Global config instance
config = Config()
