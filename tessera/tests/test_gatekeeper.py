import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from tessera.registry import TesseraRegistry
from tessera.token_generator import TokenGenerator
from tessera.revocation import RevocationList
from tessera.gatekeeper import Gatekeeper, AccessDecision


def _public_key():
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")


def test_gatekeeper_allows_valid_token():
    os.environ["TESSERA_SECRET_KEY"] = "z" * 64
    # DPoP proof-of-possession is required by default (TESSERA_REQUIRE_DPOP);
    # this test is about basic ALLOW/DENY decision logic, not DPoP mechanics
    # (which test_dpop_validation.py already covers directly), so disable it
    # here the same way TESSERA_INCLUDE_NONCE is toggled per-test below.
    os.environ["TESSERA_REQUIRE_DPOP"] = "false"
    registry = TesseraRegistry()
    # generate_token() correctly refuses to issue a token for an unregistered
    # agent -- this test never registered "mock_test" itself.
    registry.register_agent("mock_test", owner="test_owner", allowed_tools=["read_csv"])
    token_gen = TokenGenerator(registry)
    gatekeeper = Gatekeeper(token_gen, RevocationList(), registry=registry)

    token = token_gen.generate_token(
        "mock_test",
        "read_csv",
        session_id="s1",
        memory_hash="deadbeef",
        client_public_key=_public_key()
    )
    result = gatekeeper.validate_access(token.token, "read_csv")
    assert result.decision == AccessDecision.ALLOW


def test_gatekeeper_denies_replay_nonce():
    os.environ["TESSERA_SECRET_KEY"] = "z" * 64
    os.environ["TESSERA_INCLUDE_NONCE"] = "true"
    os.environ["TESSERA_REQUIRE_DPOP"] = "false"
    registry = TesseraRegistry()
    registry.register_agent("mock_test", owner="test_owner", allowed_tools=["read_csv"])
    token_gen = TokenGenerator(registry)
    gatekeeper = Gatekeeper(token_gen, RevocationList(), registry=registry)

    token = token_gen.generate_token(
        "mock_test",
        "read_csv",
        session_id="s1",
        memory_hash="deadbeef",
        client_public_key=_public_key()
    )
    result1 = gatekeeper.validate_access(token.token, "read_csv")
    result2 = gatekeeper.validate_access(token.token, "read_csv")
    assert result1.decision == AccessDecision.ALLOW
    assert result2.decision == AccessDecision.DENY_REPLAY
