#!/usr/bin/env python3
"""
Enterprise Key Management
Supports: HashiCorp Vault, AWS KMS, Azure Key Vault, HSM
Uses asymmetric signing (RS256) instead of symmetric (HS256)
"""

import os
import jwt
from datetime import datetime, timedelta
from typing import Optional, Dict
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import hvac  # HashiCorp Vault client
import boto3  # AWS KMS
from enum import Enum

class KeyProvider(Enum):
    LOCAL = "local"           # For dev/testing only
    VAULT = "vault"           # HashiCorp Vault
    AWS_KMS = "aws_kms"       # AWS Key Management Service
    AZURE_KV = "azure_kv"     # Azure Key Vault
    HSM = "hsm"               # Hardware Security Module

class KeyManagementService:
    """
    Enterprise-grade key management
    Private key NEVER leaves the secure environment
    """
    
    def __init__(self, provider: str = None):
        self.provider = KeyProvider(provider or os.getenv('KEY_PROVIDER', 'local'))
        self.private_key = None
        self.public_key = None
        
        # Initialize based on provider
        if self.provider == KeyProvider.LOCAL:
            self._init_local_keys()
        elif self.provider == KeyProvider.VAULT:
            self._init_vault()
        elif self.provider == KeyProvider.AWS_KMS:
            self._init_aws_kms()
        else:
            raise ValueError(f"Provider {self.provider} not yet implemented")
        
        print(f"🔐 Key Management: {self.provider.value.upper()}")
    
    def _init_local_keys(self):
        """
        LOCAL KEYS - DEVELOPMENT ONLY
        In production, use Vault/KMS/HSM
        """
        key_path = os.getenv('TESSERA_PRIVATE_KEY_PATH', 'keys/private_key.pem')
        pub_path = os.getenv('TESSERA_PUBLIC_KEY_PATH', 'keys/public_key.pem')
        
        if not os.path.exists(key_path):
            print("⚠️  No private key found. Generating new keypair...")
            self._generate_keypair(key_path, pub_path)
        
        # Load private key
        with open(key_path, 'rb') as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        
        # Load public key
        with open(pub_path, 'rb') as f:
            self.public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        
        print("⚠️  WARNING: Using local keys. NOT for production!")
    
    def _generate_keypair(self, private_path: str, public_path: str):
        """Generate RSA keypair for development"""
        os.makedirs(os.path.dirname(private_path), exist_ok=True)
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        
        # Save private key
        with open(private_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Save public key
        public_key = private_key.public_key()
        with open(public_path, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        
        print(f"✅ Generated keypair: {private_path}")
    
    def _init_vault(self):
        """Initialize HashiCorp Vault connection"""
        vault_url = os.getenv('VAULT_ADDR', 'http://localhost:8200')
        vault_token = os.getenv('VAULT_TOKEN')
        
        if not vault_token:
            raise ValueError("VAULT_TOKEN environment variable required")
        
        self.vault_client = hvac.Client(url=vault_url, token=vault_token)
        
        if not self.vault_client.is_authenticated():
            raise RuntimeError("Vault authentication failed")
        
        # Retrieve public key from Vault for verification
        # Private key stays in Vault - we call Vault API to sign
        secret = self.vault_client.secrets.transit.read_key(
            name='tessera-signing-key'
        )
        
        # Store only public key locally
        self.public_key = secret['data']['keys']['1']['public_key']
        print("✅ Connected to HashiCorp Vault")
    
    def _init_aws_kms(self):
        """Initialize AWS KMS"""
        self.kms_client = boto3.client('kms',
            region_name=os.getenv('AWS_REGION', 'us-east-1')
        )
        
        self.kms_key_id = os.getenv('AWS_KMS_KEY_ID')
        if not self.kms_key_id:
            raise ValueError("AWS_KMS_KEY_ID required")
        
        # Retrieve public key
        response = self.kms_client.get_public_key(KeyId=self.kms_key_id)
        self.public_key = serialization.load_der_public_key(
            response['PublicKey'],
            backend=default_backend()
        )
        
        print("✅ Connected to AWS KMS")
    
    def sign_token(self, payload: Dict) -> str:
        """
        Sign JWT token
        Private key operation - may be remote (Vault/KMS)
        """
        if self.provider == KeyProvider.LOCAL:
            return self._sign_local(payload)
        elif self.provider == KeyProvider.VAULT:
            return self._sign_vault(payload)
        elif self.provider == KeyProvider.AWS_KMS:
            return self._sign_aws_kms(payload)
    
    def _sign_local(self, payload: Dict) -> str:
        """Sign with local private key (dev only)"""
        return jwt.encode(
            payload,
            self.private_key,
            algorithm='RS256'
        )
    
    def _sign_vault(self, payload: Dict) -> str:
        """Sign using HashiCorp Vault Transit engine"""
        # Encode payload as JWT would, but without signature
        import base64
        import json
        
        header = base64.urlsafe_b64encode(
            json.dumps({'alg': 'RS256', 'typ': 'JWT'}).encode()
        ).rstrip(b'=')
        
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b'=')
        
        message = header + b'.' + payload_b64
        
        # Request signature from Vault
        response = self.vault_client.secrets.transit.sign_data(
            name='tessera-signing-key',
            hash_input=message
        )
        
        signature = response['data']['signature']
        return f"{message.decode()}.{signature}"
    
    def _sign_aws_kms(self, payload: Dict) -> str:
        """Sign using AWS KMS"""
        import base64
        import json
        
        # Create unsigned token
        header = base64.urlsafe_b64encode(
            json.dumps({'alg': 'RS256', 'typ': 'JWT'}).encode()
        ).rstrip(b'=')
        
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b'=')
        
        message = header + b'.' + payload_b64
        
        # Sign with KMS
        response = self.kms_client.sign(
            KeyId=self.kms_key_id,
            Message=message,
            MessageType='RAW',
            SigningAlgorithm='RSASSA_PKCS1_V1_5_SHA_256'
        )
        
        signature = base64.urlsafe_b64encode(
            response['Signature']
        ).rstrip(b'=')
        
        return f"{message.decode()}.{signature.decode()}"
    
    def verify_token(self, token: str) -> Optional[Dict]:
        """
        Verify JWT signature using public key
        This operation is safe to do locally - only needs public key
        """
        try:
            # Get public key in PEM format
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            payload = jwt.decode(
                token,
                public_pem,
                algorithms=['RS256'],
                options={
                    'verify_signature': True,
                    'verify_exp': True,
                    'verify_iat': True,
                    'require': ['exp', 'iat', 'sub']
                },
                leeway=10
            )
            
            return payload
            
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError as e:
            print(f"Token validation error: {e}")
            return None

# Singleton
_kms = None

def get_kms() -> KeyManagementService:
    """Get or create KMS instance"""
    global _kms
    if _kms is None:
        _kms = KeyManagementService()
    return _kms
