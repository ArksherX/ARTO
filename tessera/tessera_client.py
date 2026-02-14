#!/usr/bin/env python3
"""
Tessera Agent Client - Automatic Token Management (FIXED)
Uses Bearer authentication for enterprise standards
"""

import requests
from datetime import datetime, timedelta
from typing import Optional, Callable
from functools import wraps
import logging
import os
import uuid
import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import serialization
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TesseraClient:
    """Automatic Tessera IAM client for AI agents"""
    
    def __init__(self, api_url: str, api_key: str, agent_id: str):
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self.agent_id = agent_id
        self.token_cache = {}
        self.session_token_cache = {}
        self.session_token_ttl_seconds = int(os.getenv("TESSERA_SESSION_TOKEN_TTL_SECONDS", "300"))
        self.session_token_refresh_seconds = int(os.getenv("TESSERA_SESSION_TOKEN_REFRESH_SECONDS", "60"))
        self.session_id = f"session_{uuid.uuid4().hex}"
        self._dpop_private_key = self._load_or_create_dpop_keypair()
        self.client_public_key = self._public_key_pem(self._dpop_private_key)
        self.validate_before_use = os.getenv("TESSERA_VALIDATE_TOKENS", "false").lower() in ("1", "true", "yes")
        
        # Test connection
        try:
            response = requests.get(
                f"{self.api_url}/health",
                timeout=5
            )
            if response.status_code == 200:
                logger.info(f"✅ Tessera client initialized for {agent_id}")
                logger.info(f"✅ Connected to Tessera API")
            else:
                logger.warning(f"⚠️  API health check failed: {response.status_code}")
        except Exception as e:
            logger.error(f"❌ Failed to connect to Tessera API: {e}")
    
    def request_token(self, tool: str, justification: Optional[str] = None, duration_minutes: Optional[int] = None) -> dict:
        """Request a token from Tessera API using Bearer authentication"""
        headers = {
            'Authorization': f'Bearer {self.api_key}',  # ← FIXED: Bearer auth
            'Content-Type': 'application/json'
        }
        memory_state = f"initial_memory:{self.agent_id}:{self.session_id}"
        payload = {
            "agent_id": self.agent_id,
            "tool": tool,
            "duration_minutes": duration_minutes or 60,
            "session_id": self.session_id,
            "memory_state": memory_state,
            "client_public_key": self.client_public_key
        }
        
        try:
            logger.info(f"🔑 Requesting token for {self.agent_id} / {tool}")
            response = requests.post(
                f"{self.api_url}/tokens/request",
                json=payload,
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            
            data = response.json()
            self.token_cache[tool] = {
                'token': data['token'],
                'expires_at': datetime.fromisoformat(data['expires_at'])
            }
            
            logger.info(f"✅ Token received: {data['jti']}")
            return data
            
        except requests.exceptions.HTTPError as e:
            logger.error(f"❌ Tessera API error: {e}")
            logger.error(f"   Response: {e.response.text if e.response else 'No response'}")
            raise
        except Exception as e:
            logger.error(f"❌ Unexpected error: {e}")
            raise
    
    def get_token(self, tool: str) -> str:
        """Get a valid token (auto-requests if needed)"""
        cached = self.token_cache.get(tool)
        
        # Check if cached token is still valid (with 30s buffer)
        if cached and datetime.now() < cached['expires_at'] - timedelta(seconds=30):
            if self.validate_before_use:
                try:
                    validation = self.validate_token_with_dpop(cached["token"], tool)
                    if validation.get("valid"):
                        logger.info(f"♻️  Using cached token for {tool} (validated)")
                        return cached["token"]
                except Exception:
                    pass
            logger.info(f"♻️  Using cached token for {tool}")
            return cached['token']
        
        logger.info(f"🔄 Token refresh needed for {tool}")
        response = self.request_token(tool)
        return response['token']

    def get_session_memory_token(self) -> str:
        """Get a valid token for session memory updates."""
        tool = "session_memory_update"
        cached = self.session_token_cache.get(tool)

        if cached:
            remaining = (cached["expires_at"] - datetime.now()).total_seconds()
            if remaining > self.session_token_refresh_seconds:
                return cached["token"]

        duration_minutes = max(1, int(self.session_token_ttl_seconds / 60))
        response = self.request_token(tool, duration_minutes=duration_minutes)
        expires_at = datetime.fromisoformat(response["expires_at"])
        proactive_expiry = datetime.now() + timedelta(seconds=self.session_token_ttl_seconds)
        self.session_token_cache[tool] = {
            "token": response["token"],
            "expires_at": min(expires_at, proactive_expiry)
        }
        return response["token"]

    def update_session_memory(self, memory_state: Optional[str] = None, memory_hash: Optional[str] = None) -> dict:
        """Update session memory hash via API using DPoP-bound token."""
        if not (memory_state or memory_hash):
            raise ValueError("memory_state or memory_hash required")
        token = self.get_session_memory_token()
        payload = {
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "memory_state": memory_state,
            "memory_hash": memory_hash,
            "ttl_seconds": 3600
        }
        response = self.request_with_dpop(
            method="POST",
            path="/sessions/memory/update",
            token=token,
            json_payload=payload
        )
        response.raise_for_status()
        return response.json()
    
    def with_tessera_auth(self, tool: str):
        """Decorator for automatic token management"""
        def decorator(func: Callable):
            @wraps(func)
            def wrapper(*args, **kwargs):
                try:
                    token = self.get_token(tool)
                    dpop = self._generate_dpop_proof(method="POST", url=f"{self.api_url}/tokens/validate")
                    kwargs['_tessera_token'] = token
                    kwargs['_tessera_dpop'] = dpop
                    logger.info(f"▶️  Executing {func.__name__} with Tessera auth")
                    return func(*args, **kwargs)
                except Exception as e:
                    logger.error(f"❌ Tool execution error: {e}")
                    return {"error": str(e)}
            return wrapper
        return decorator

    def request_with_dpop(
        self,
        method: str,
        path: str,
        token: str,
        json_payload: Optional[dict] = None,
        params: Optional[dict] = None,
        timeout: int = 10
    ) -> requests.Response:
        """Send HTTP request with Authorization + DPoP headers."""
        url = f"{self.api_url}{path}"
        dpop = self._generate_dpop_proof(method=method, url=url)
        headers = {
            "Authorization": f"Bearer {token}",
            "DPoP": dpop,
            "Content-Type": "application/json"
        }
        return requests.request(
            method=method,
            url=url,
            headers=headers,
            json=json_payload,
            params=params,
            timeout=timeout
        )

    def validate_token_with_dpop(self, token: str, tool: str) -> dict:
        """Validate a token via API using DPoP-bound proof."""
        payload = {"token": token, "tool": tool}
        response = self.request_with_dpop(
            method="POST",
            path="/tokens/validate",
            token=token,
            json_payload=payload
        )
        response.raise_for_status()
        return response.json()

    def _load_or_create_dpop_keypair(self):
        """Load DPoP keypair from env or create ephemeral keypair."""
        pem = os.getenv("TESSERA_CLIENT_PRIVATE_KEY")
        pem_path = os.getenv("TESSERA_CLIENT_PRIVATE_KEY_PATH")
        if pem:
            return serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
        if pem_path and os.path.exists(pem_path):
            with open(pem_path, "rb") as f:
                return serialization.load_pem_private_key(f.read(), password=None)
        return ec.generate_private_key(ec.SECP256R1())

    @staticmethod
    def _public_key_pem(private_key) -> str:
        return private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

    def _jwk_from_private_key(self) -> dict:
        pub = self._dpop_private_key.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            numbers = pub.public_numbers()
            n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
            e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
            return {
                "kty": "RSA",
                "n": jwt.utils.base64url_encode(n).decode("utf-8"),
                "e": jwt.utils.base64url_encode(e).decode("utf-8")
            }
        numbers = pub.public_numbers()
        x = numbers.x.to_bytes((numbers.x.bit_length() + 7) // 8, "big")
        y = numbers.y.to_bytes((numbers.y.bit_length() + 7) // 8, "big")
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": jwt.utils.base64url_encode(x).decode("utf-8"),
            "y": jwt.utils.base64url_encode(y).decode("utf-8")
        }

    def _generate_dpop_proof(self, method: str, url: str) -> str:
        """Generate a DPoP proof JWT bound to method + URL."""
        iat = int(datetime.utcnow().timestamp())
        jti = uuid.uuid4().hex
        payload = {"htu": url, "htm": method.upper(), "iat": iat, "jti": jti}
        jwk = self._jwk_from_private_key()
        headers = {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
        return jwt.encode(payload, self._dpop_private_key, algorithm="ES256", headers=headers)

# ============================================================================
# DEMO: Show automatic token management
# ============================================================================
if __name__ == "__main__":
    # Load API key from environment
    API_KEY = os.getenv('TESSERA_API_KEY')
    if not API_KEY:
        print("❌ Error: TESSERA_API_KEY not found in .env")
        exit(1)
    
    # Initialize client
    client = TesseraClient(
        api_url="http://localhost:8000",
        api_key=API_KEY,
        agent_id="agent_financial_bot_01"
    )
    
    print("\n" + "="*60)
    print("DEMO: Using tools with automatic Tessera IAM")
    print("="*60)
    
    # Demo 1: Authorized tool
    @client.with_tessera_auth(tool="read_csv")
    def read_financial_data(file_path, **kwargs):
        print(f"📊 Reading {file_path}")
        print(f"🔑 Using token: {kwargs['_tessera_token'][:30]}...")
        return {"status": "success", "data": "sample financial data"}
    
    print("\n1️⃣  Reading financial data...")
    try:
        result = read_financial_data("Q4_report.csv")
        print(f"   ✅ Success: {result}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Demo 2: Multiple calls (shows caching)
    print("\n2️⃣  Reading more data (token cached)...")
    try:
        result = read_financial_data("Q3_report.csv")
        print(f"   ✅ Success: {result}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Demo 3: Unauthorized tool (will fail at token request)
    @client.with_tessera_auth(tool="terminal_exec")
    def run_command(command, **kwargs):
        print(f"💻 Running: {command}")
        return {"status": "executed"}
    
    print("\n3️⃣  Attempting unauthorized tool...")
    try:
        result = run_command("ls -la")
        print(f"   ✅ Success: {result}")
    except Exception as e:
        print(f"   ✅ Correctly blocked: {e}")
    
    print("\n" + "="*60)
    print("✅ Demo complete - Zero manual intervention!")
    print("="*60)
