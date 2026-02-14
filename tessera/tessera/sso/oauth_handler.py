#!/usr/bin/env python3
"""
OIDC/OAuth2 JWT validation using JWKS.
"""

import os
import json
import requests
import jwt
from typing import Dict


class OIDCValidator:
    def __init__(self, issuer: str, audience: str, jwks_url: str):
        self.issuer = issuer
        self.audience = audience
        self.jwks_url = jwks_url
        self._jwks = None

    def _load_jwks(self) -> Dict:
        if self._jwks is None:
            resp = requests.get(self.jwks_url, timeout=5)
            resp.raise_for_status()
            self._jwks = resp.json()
        return self._jwks

    def validate_bearer(self, authorization: str) -> Dict:
        if not authorization or not authorization.startswith("Bearer "):
            raise ValueError("Missing bearer token")
        token = authorization.replace("Bearer ", "", 1).strip()
        header = jwt.get_unverified_header(token)
        jwks = self._load_jwks()
        key = next((k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid")), None)
        if not key:
            raise ValueError("JWK not found for token")
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
        return jwt.decode(
            token,
            public_key,
            algorithms=["RS256", "RS384", "RS512"],
            audience=self.audience,
            issuer=self.issuer
        )


def from_env() -> OIDCValidator:
    issuer = os.getenv("OIDC_ISSUER")
    audience = os.getenv("OIDC_AUDIENCE")
    jwks_url = os.getenv("OIDC_JWKS_URL")
    if not (issuer and audience and jwks_url):
        raise ValueError("OIDC_ISSUER, OIDC_AUDIENCE, OIDC_JWKS_URL are required")
    return OIDCValidator(issuer, audience, jwks_url)
