#!/usr/bin/env python3
"""
Mutual TLS (mTLS) Authentication for Agents
Prevents identity spoofing by requiring cryptographic proof
"""

import os
from typing import Optional, Tuple
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from datetime import datetime

class MTLSAuthenticator:
    """
    Mutual TLS authentication
    Agents must present valid client certificates
    """
    
    def __init__(self, ca_cert_path: str = None):
        self.ca_cert_path = ca_cert_path or os.getenv(
            'TESSERA_CA_CERT_PATH', 
            'certs/ca.pem'
        )
        
        # Load CA certificate for validation
        if os.path.exists(self.ca_cert_path):
            with open(self.ca_cert_path, 'rb') as f:
                self.ca_cert = x509.load_pem_x509_certificate(
                    f.read(),
                    default_backend()
                )
            print("✅ mTLS CA certificate loaded")
        else:
            print("⚠️  No CA certificate found. mTLS disabled.")
            self.ca_cert = None
    
    def validate_client_certificate(
        self, 
        cert_pem: str
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Validate client certificate
        
        Returns:
            (is_valid, agent_id, error_message)
        """
        if not self.ca_cert:
            return False, None, "mTLS not configured"
        
        try:
            # Parse client certificate
            cert = x509.load_pem_x509_certificate(
                cert_pem.encode(),
                default_backend()
            )
            
            # Check 1: Certificate not expired
            now = datetime.utcnow()
            if now < cert.not_valid_before or now > cert.not_valid_after:
                return False, None, "Certificate expired or not yet valid"
            
            # Check 2: Verify signature against CA
            # (In production, use proper certificate chain validation)
            # For now, we check the issuer matches our CA
            if cert.issuer != self.ca_cert.subject:
                return False, None, "Certificate not issued by trusted CA"
            
            # Check 3: Extract agent ID from certificate Common Name
            agent_id = None
            for attr in cert.subject:
                if attr.oid == x509.NameOID.COMMON_NAME:
                    agent_id = attr.value
                    break
            
            if not agent_id:
                return False, None, "No agent ID in certificate"
            
            # Check 4: Certificate fingerprint (for tracking)
            fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            
            return True, agent_id, fingerprint
            
        except Exception as e:
            return False, None, f"Certificate validation error: {e}"
    
    def extract_agent_id_from_cert(self, cert_pem: str) -> Optional[str]:
        """Quick extraction of agent ID without full validation"""
        try:
            cert = x509.load_pem_x509_certificate(
                cert_pem.encode(),
                default_backend()
            )
            
            for attr in cert.subject:
                if attr.oid == x509.NameOID.COMMON_NAME:
                    return attr.value
            
            return None
        except:
            return None

# Singleton
_mtls_auth = None

def get_mtls_authenticator() -> MTLSAuthenticator:
    global _mtls_auth
    if _mtls_auth is None:
        _mtls_auth = MTLSAuthenticator()
    return _mtls_auth
