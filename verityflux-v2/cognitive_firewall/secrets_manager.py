#!/usr/bin/env python3
"""
Secrets Management

Secure storage and retrieval of sensitive credentials
"""

import os
import json
import base64
from pathlib import Path
from typing import Optional, Dict, Any
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2


class SecretsManager:
    """
    Manages encrypted secrets
    
    Supports:
    - Environment variables (12-factor app)
    - Encrypted file storage
    - Cloud secret managers (AWS Secrets Manager, etc.)
    """
    
    def __init__(self, 
                 encryption_key: Optional[str] = None,
                 secrets_file: str = ".secrets.enc"):
        """
        Initialize secrets manager
        
        Args:
            encryption_key: Master encryption key (or use VERITYFLUX_MASTER_KEY env var)
            secrets_file: Path to encrypted secrets file
        """
        self.secrets_file = Path(secrets_file)
        
        # Get or generate encryption key
        if encryption_key:
            self.encryption_key = encryption_key.encode()
        elif os.getenv('VERITYFLUX_MASTER_KEY'):
            self.encryption_key = os.getenv('VERITYFLUX_MASTER_KEY').encode()
        else:
            # Generate new key (first run)
            self.encryption_key = Fernet.generate_key()
            print("⚠️  WARNING: Generated new encryption key")
            print(f"   Set VERITYFLUX_MASTER_KEY={self.encryption_key.decode()}")
        
        # Initialize cipher
        self.cipher = Fernet(self.encryption_key)
        
        # Load secrets
        self.secrets: Dict[str, str] = {}
        self._load_secrets()
    
    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """
        Get secret value
        
        Priority:
        1. Environment variable
        2. Encrypted file
        3. Default value
        
        Args:
            key: Secret key
            default: Default value if not found
        
        Returns:
            Secret value or default
        """
        # Check environment first
        env_value = os.getenv(key)
        if env_value:
            return env_value
        
        # Check encrypted file
        if key in self.secrets:
            return self.secrets[key]
        
        # Return default
        return default
    
    def set(self, key: str, value: str) -> None:
        """
        Set secret value
        
        Args:
            key: Secret key
            value: Secret value (will be encrypted)
        """
        self.secrets[key] = value
        self._save_secrets()
    
    def delete(self, key: str) -> None:
        """Delete secret"""
        if key in self.secrets:
            del self.secrets[key]
            self._save_secrets()
    
    def _load_secrets(self) -> None:
        """Load secrets from encrypted file"""
        if not self.secrets_file.exists():
            return
        
        try:
            with open(self.secrets_file, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt
            decrypted_data = self.cipher.decrypt(encrypted_data)
            self.secrets = json.loads(decrypted_data)
            
        except Exception as e:
            print(f"⚠️  Failed to load secrets: {e}")
            self.secrets = {}
    
    def _save_secrets(self) -> None:
        """Save secrets to encrypted file"""
        try:
            # Serialize
            data = json.dumps(self.secrets).encode()
            
            # Encrypt
            encrypted_data = self.cipher.encrypt(data)
            
            # Save
            with open(self.secrets_file, 'wb') as f:
                f.write(encrypted_data)
            
            # Set restrictive permissions (Unix only)
            try:
                os.chmod(self.secrets_file, 0o600)
            except:
                pass
            
        except Exception as e:
            print(f"⚠️  Failed to save secrets: {e}")
    
    def migrate_from_env_file(self, env_file: str = ".env") -> int:
        """
        Migrate secrets from .env file to encrypted storage
        
        Args:
            env_file: Path to .env file
        
        Returns:
            Number of secrets migrated
        """
        env_path = Path(env_file)
        if not env_path.exists():
            return 0
        
        count = 0
        secret_keys = [
            'SLACK_WEBHOOK_URL',
            'SMTP_PASSWORD',
            'SMTP_USERNAME',
            'NVD_API_KEY',
            'TESSERA_API_URL',
            'VESTIGIA_API_URL',
            'REDIS_URL',
        ]
        
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    
                    # Only migrate sensitive keys
                    if any(secret_key in key.upper() for secret_key in secret_keys):
                        self.set(key, value)
                        count += 1
        
        return count
    
    def list_keys(self) -> list:
        """List all secret keys (not values!)"""
        return list(self.secrets.keys())


class AWSSecretsManager:
    """
    AWS Secrets Manager integration
    
    For enterprise deployments
    """
    
    def __init__(self, region: str = 'us-east-1'):
        """
        Initialize AWS Secrets Manager client
        
        Args:
            region: AWS region
        """
        try:
            import boto3
            self.client = boto3.client('secretsmanager', region_name=region)
            self.available = True
        except:
            self.available = False
            print("⚠️  AWS SDK not available, using local secrets only")
    
    def get(self, secret_name: str) -> Optional[Dict]:
        """Get secret from AWS"""
        if not self.available:
            return None
        
        try:
            response = self.client.get_secret_value(SecretId=secret_name)
            return json.loads(response['SecretString'])
        except:
            return None
    
    def set(self, secret_name: str, secret_value: Dict) -> bool:
        """Set secret in AWS"""
        if not self.available:
            return False
        
        try:
            self.client.put_secret_value(
                SecretId=secret_name,
                SecretString=json.dumps(secret_value)
            )
            return True
        except:
            return False
