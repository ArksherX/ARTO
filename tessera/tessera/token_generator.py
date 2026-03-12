#!/usr/bin/env python3
"""
Tessera Token Generator - JWT Passport Issuance
"""

import jwt
import secrets
import hashlib
import json
import base64
from datetime import datetime, timedelta, UTC
from typing import Optional, Dict, Any
from dataclasses import dataclass
import os
import sys
from pathlib import Path
from dotenv import load_dotenv
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

# Load environment (allow .env to override any stale shell exports)
load_dotenv(override=True)

@dataclass
class TesseraToken:
    """Represents an issued Tessera passport"""
    token: str
    agent_id: str
    tool: str
    issued_at: datetime
    expires_at: datetime
    risk_threshold: int
    jti: str
    
    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at
    
    def to_dict(self) -> dict:
        return {
            'token': self.token,
            'agent_id': self.agent_id,
            'tool': self.tool,
            'issued_at': self.issued_at.isoformat(),
            'expires_at': self.expires_at.isoformat(),
            'risk_threshold': self.risk_threshold,
            'jti': self.jti
        }

class TokenGenerator:
    """Generates cryptographically signed JWT tokens for agent tool access"""
    ALLOWED_ALGORITHMS = ["HS512"]
    ALLOWED_DPOP_ALGORITHMS = ["ES256", "RS256"]
    DEV_FALLBACK_SECRET = (
        "168595de6449925806d7b448d132a5ec6290cb0ce31f253826c2694586f05c0d"
        "21518555e12dc87de7088820e215aa2505008d87d8a64ce03f2cad74d8484b06"
    )
    
    def __init__(self, registry):
        self.registry = registry
        self.secret_key = self._load_secret_key()
        self.algorithm = os.getenv('TESSERA_ALGORITHM', 'HS512').upper()
        self.require_dpop = os.getenv("TESSERA_REQUIRE_DPOP", "true").lower() in ("1", "true", "yes")
        self.require_memory_binding = os.getenv("TESSERA_REQUIRE_MEMORY_BINDING", "true").lower() in ("1", "true", "yes")
        self.include_nonce = os.getenv("TESSERA_INCLUDE_NONCE", "false").lower() in ("1", "true", "yes")
        
        if self.algorithm not in self.ALLOWED_ALGORITHMS:
            raise ValueError(f"TESSERA_ALGORITHM must be one of {self.ALLOWED_ALGORITHMS}")

    def _load_secret_key(self) -> bytes:
        secret_key = os.getenv('TESSERA_SECRET_KEY')
        env_name = os.getenv("TESSERA_ENV", "").strip().lower()
        strict = os.getenv("TESSERA_STRICT_SECRET_KEY", "false").lower() in ("1", "true", "yes")
        strict = strict or env_name in ("prod", "production")
        if not secret_key and os.getenv("PYTEST_CURRENT_TEST"):
            secret_key = "a" * 64
        if not secret_key:
            if strict:
                raise ValueError("TESSERA_SECRET_KEY must be set in .env")
            # Demo/dev-safe fallback aligned with tessera/api_server.py
            secret_key = self.DEV_FALLBACK_SECRET
        key_bytes = self._normalize_secret_key(secret_key)
        if len(key_bytes) < 64:  # 512-bit minimum
            if strict:
                raise ValueError("TESSERA_SECRET_KEY must be at least 64 bytes (512-bit)")
            # Dev fallback: derive a stable 512-bit key from provided secret.
            key_bytes = hashlib.sha512(key_bytes).digest()
        return key_bytes

    @staticmethod
    def _normalize_secret_key(secret_key: str) -> bytes:
        # Attempt hex decode if looks like hex
        hex_chars = "0123456789abcdefABCDEF"
        if all(c in hex_chars for c in secret_key) and len(secret_key) % 2 == 0:
            try:
                return bytes.fromhex(secret_key)
            except Exception:
                pass
        # Attempt base64 decode if prefixed
        if secret_key.startswith("base64:"):
            try:
                return base64.urlsafe_b64decode(secret_key.split("base64:", 1)[1] + "==")
            except Exception:
                pass
        return secret_key.encode("utf-8")

    @staticmethod
    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

    def _jwk_from_public_key(self, public_key_pem: str) -> Dict[str, Any]:
        key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"), backend=default_backend())
        if isinstance(key, rsa.RSAPublicKey):
            numbers = key.public_numbers()
            return {
                "kty": "RSA",
                "n": self._b64url(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
                "e": self._b64url(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big"))
            }
        if isinstance(key, ec.EllipticCurvePublicKey):
            numbers = key.public_numbers()
            curve = numbers.curve
            if isinstance(curve, ec.SECP256R1):
                crv = "P-256"
            elif isinstance(curve, ec.SECP384R1):
                crv = "P-384"
            elif isinstance(curve, ec.SECP521R1):
                crv = "P-521"
            else:
                raise ValueError("Unsupported EC curve for DPoP")
            x = numbers.x.to_bytes((numbers.x.bit_length() + 7) // 8, "big")
            y = numbers.y.to_bytes((numbers.y.bit_length() + 7) // 8, "big")
            return {"kty": "EC", "crv": crv, "x": self._b64url(x), "y": self._b64url(y)}
        raise ValueError("Unsupported public key type for DPoP")

    def compute_jwk_thumbprint(self, jwk: Dict[str, Any]) -> str:
        if jwk.get("kty") == "RSA":
            thumb_obj = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
        elif jwk.get("kty") == "EC":
            thumb_obj = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
        else:
            raise ValueError("Unsupported JWK for thumbprint")
        canonical = json.dumps(thumb_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return self._b64url(hashlib.sha256(canonical).digest())

    def _resolve_dpop_thumbprint(
        self,
        client_public_key: Optional[str],
        client_jwk: Optional[Dict[str, Any]],
        provided_thumbprint: Optional[str]
    ) -> Optional[str]:
        if provided_thumbprint:
            return provided_thumbprint
        if client_jwk:
            return self.compute_jwk_thumbprint(client_jwk)
        if client_public_key:
            jwk = self._jwk_from_public_key(client_public_key)
            return self.compute_jwk_thumbprint(jwk)
        return None
    
    def generate_token(
        self,
        agent_id: str,
        tool: str,
        custom_ttl: Optional[int] = None,
        session_id: Optional[str] = None,
        memory_hash: Optional[str] = None,
        memory_state: Optional[bytes] = None,
        client_public_key: Optional[str] = None,
        client_jwk: Optional[Dict[str, Any]] = None,
        dpop_thumbprint: Optional[str] = None,
        delegation_chain: Optional[list] = None,
        parent_jti: Optional[str] = None,
        delegation_depth: int = 0,
        role: Optional[str] = None
    ) -> Optional[TesseraToken]:
        """Generate a signed JWT token for agent tool access"""
        # Verify agent exists
        agent = self.registry.get_agent(agent_id)
        if not agent:
            return None
        
        # Check status
        if agent.status != "active":
            return None
        
        # Verify tool authorization
        if tool not in agent.allowed_tools:
            return None
        
        # Calculate expiration
        ttl = custom_ttl or agent.max_token_ttl
        issued_at = datetime.now(UTC)
        expires_at = issued_at + timedelta(seconds=ttl)
        
        # Generate JWT ID
        jti = f"tessera_{secrets.token_hex(16)}"
        
        # Session memory binding
        if memory_state is not None and not memory_hash:
            memory_hash = hashlib.sha256(memory_state).hexdigest()

        if self.require_memory_binding and (not session_id or not memory_hash):
            return None

        # DPoP binding
        jkt = self._resolve_dpop_thumbprint(client_public_key, client_jwk, dpop_thumbprint)
        if self.require_dpop and not jkt:
            return None

        # Create payload
        payload = {
            'sub': agent_id,
            'owner': agent.owner,
            'tenant_id': getattr(agent, "tenant_id", "default"),
            'tool': tool,
            'iat': int(issued_at.timestamp()),
            'exp': int(expires_at.timestamp()),
            'risk_threshold': agent.risk_threshold,
            'jti': jti,
            'iss': 'tessera-iam'
        }
        if getattr(agent, "active_key_id", None):
            payload["agent_key_id"] = agent.active_key_id

        if self.include_nonce:
            payload['nonce'] = secrets.token_urlsafe(16)

        if session_id:
            payload['session_id'] = session_id
        if memory_hash:
            payload['memory_hash'] = memory_hash
        if jkt:
            payload['cnf'] = {'jkt': jkt}
        if delegation_chain is not None:
            payload['delegation_chain'] = delegation_chain
        if parent_jti:
            payload['parent_jti'] = parent_jti
        if delegation_depth > 0:
            payload['delegation_depth'] = delegation_depth
        if role:
            payload["role"] = role
        
        # Sign token with hardened algorithm
        token_raw = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        
        # PyJWT 2.0+ returns string, but some versions return bytes
        if isinstance(token_raw, bytes):
            token = token_raw.decode('utf-8')
        else:
            token = token_raw
        
        return TesseraToken(
            token=token,
            agent_id=agent_id,
            tool=tool,
            issued_at=issued_at,
            expires_at=expires_at,
            risk_threshold=agent.risk_threshold,
            jti=jti
        )
    
    def validate_token(self, token: str) -> Optional[Dict]:
        """
        Validate and decode a Tessera token
        
        CRITICAL FIX: Better error handling and debugging
        """
        try:
            # Ensure token is string
            if isinstance(token, bytes):
                token = token.decode('utf-8')

            header = jwt.get_unverified_header(token)
            alg = header.get("alg", "").upper()
            if alg.lower() == "none" or alg not in self.ALLOWED_ALGORITHMS:
                return None
            
            # Decode with explicit options
            payload = jwt.decode(
                token, 
                self.secret_key,
                algorithms=self.ALLOWED_ALGORITHMS,
                options={
                    'verify_signature': True,
                    'verify_exp': True,
                    'verify_iat': True,
                    'require': ['exp', 'iat', 'sub', 'tool', 'jti', 'iss']
                },
                leeway=60  # Allow clock skew
            )
            return payload
            
        except jwt.ExpiredSignatureError:
            # Token expired
            return None
        except jwt.InvalidTokenError as e:
            # Token invalid (signature mismatch, malformed, etc)
            print(f"Token validation error: {e}")
            return None
        except Exception as e:
            # Unexpected error
            print(f"Unexpected error validating token: {e}")
            return None

    def validate_dpop_proof(
        self,
        dpop_proof: str,
        required_jkt: str,
        expected_htm: Optional[str] = None,
        expected_htu: Optional[str] = None,
        max_age_seconds: int = 60
    ) -> bool:
        """Validate DPoP proof JWT against required thumbprint."""
        try:
            header = jwt.get_unverified_header(dpop_proof)
            alg = header.get("alg", "").upper()
            if alg.lower() == "none" or alg not in self.ALLOWED_DPOP_ALGORITHMS:
                return False
            jwk = header.get("jwk")
            if not jwk:
                return False
            computed_jkt = self.compute_jwk_thumbprint(jwk)
            if computed_jkt != required_jkt:
                return False

            if jwk.get("kty") == "RSA":
                public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
            elif jwk.get("kty") == "EC":
                public_key = jwt.algorithms.ECAlgorithm.from_jwk(json.dumps(jwk))
            else:
                return False
            payload = jwt.decode(
                dpop_proof,
                public_key,
                algorithms=[alg],
                options={
                    "verify_signature": True,
                    "verify_exp": False,
                    "verify_iat": False,
                    "require": ["iat", "jti", "htu", "htm"]
                }
            )

            if expected_htm and payload.get("htm", "").upper() != expected_htm.upper():
                return False
            if expected_htu and payload.get("htu") != expected_htu:
                return False

            iat = int(payload.get("iat"))
            now = int(datetime.utcnow().timestamp())
            if abs(now - iat) > max_age_seconds:
                return False
            return True
        except Exception:
            return False

# ============================================================================
# QUICK TEST
# ============================================================================
if __name__ == "__main__":
    """Test the token generator"""
    print("Testing TokenGenerator...")
    
    # Add parent directory to path for imports
    sys.path.insert(0, str(Path(__file__).parent.parent))
    
    from tessera.registry import TesseraRegistry
    
    registry = TesseraRegistry()
    token_gen = TokenGenerator(registry)
    
    # Generate token
    print("\n1. Generating token...")
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    memory_state = b"test_memory_state"
    memory_hash = hashlib.sha256(memory_state).hexdigest()

    token = token_gen.generate_token(
        "agent_financial_bot_01",
        "read_csv",
        session_id="test_session",
        memory_hash=memory_hash,
        client_public_key=public_key
    )
    
    if token:
        print(f"   ✅ Token generated: {token.jti}")
        print(f"   Token type: {type(token.token)}")
        print(f"   Token (first 50 chars): {token.token[:50]}...")
        
        # Validate token
        print("\n2. Validating token...")
        payload = token_gen.validate_token(token.token)
        
        if payload:
            print(f"   ✅ Token valid!")
            print(f"   Agent: {payload['sub']}")
            print(f"   Tool: {payload['tool']}")
            print(f"   Expires: {datetime.fromtimestamp(payload['exp'])}")
        else:
            print(f"   ❌ Token validation failed!")
    else:
        print(f"   ❌ Token generation failed!")
