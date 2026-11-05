import os
import time
import uuid

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from tessera.registry import TesseraRegistry
from tessera.token_generator import TokenGenerator
from tessera.revocation import RevocationList
from tessera.gatekeeper import Gatekeeper, AccessDecision


def _dpop_proof(private_key, url: str, method: str = "POST") -> str:
    """Same shape as tests/test_dpop_validation.py."""
    pub = private_key.public_key().public_numbers()
    x = pub.x.to_bytes((pub.x.bit_length() + 7) // 8, "big")
    y = pub.y.to_bytes((pub.y.bit_length() + 7) // 8, "big")
    jwk = {"kty": "EC", "crv": "P-256",
           "x": jwt.utils.base64url_encode(x).decode("utf-8"),
           "y": jwt.utils.base64url_encode(y).decode("utf-8")}
    payload = {"htu": url, "htm": method, "iat": int(time.time()), "jti": uuid.uuid4().hex}
    headers = {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
    return jwt.encode(payload, private_key, algorithm="ES256", headers=headers)


def test_full_workflow(monkeypatch):
    os.environ["TESSERA_SECRET_KEY"] = "z" * 64
    monkeypatch.setenv("TESSERA_REQUIRE_DPOP", "true")
    registry = TesseraRegistry()
    # The agent has to exist. Without this, generate_token correctly refuses
    # an unknown agent and returns None, and the test fails on None.token
    # rather than on anything to do with the workflow.
    if registry.get_agent("mock_test") is None:
        registry.register_agent(agent_id="mock_test", owner="test-suite",
                                allowed_tools=["read_csv"], max_token_ttl=3600)
    token_gen = TokenGenerator(registry)
    gatekeeper = Gatekeeper(token_gen, RevocationList(), registry=registry)

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    token = token_gen.generate_token(
        "mock_test",
        "read_csv",
        session_id="s1",
        memory_hash="deadbeef",
        client_public_key=public_key
    )
    assert token is not None, "token generation failed; the agent is not registered"

    # The token is DPoP-bound, so access needs a matching proof. Without one
    # the gatekeeper denies with DENY_DPOP_INVALID -- which is the control
    # working, not a failure. This test previously never sent a proof.
    url, method = "https://tessera.local/access", "POST"
    proof = _dpop_proof(private_key, url, method)
    result = gatekeeper.validate_access(
        token.token, "read_csv",
        dpop_proof=proof, expected_htm=method, expected_htu=url,
    )
    assert result.decision == AccessDecision.ALLOW, result.reason


def test_access_is_denied_without_a_dpop_proof(monkeypatch):
    """A DPoP-bound token presented with no proof must be refused."""
    os.environ["TESSERA_SECRET_KEY"] = "z" * 64
    monkeypatch.setenv("TESSERA_REQUIRE_DPOP", "true")
    registry = TesseraRegistry()
    if registry.get_agent("mock_test") is None:
        registry.register_agent(agent_id="mock_test", owner="test-suite",
                                allowed_tools=["read_csv"], max_token_ttl=3600)
    token_gen = TokenGenerator(registry)
    gatekeeper = Gatekeeper(token_gen, RevocationList(), registry=registry)

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    token = token_gen.generate_token(
        "mock_test", "read_csv", session_id="s1",
        memory_hash="deadbeef", client_public_key=public_key,
    )
    assert token is not None
    result = gatekeeper.validate_access(token.token, "read_csv")
    assert result.decision == AccessDecision.DENY_DPOP_INVALID, result.reason
