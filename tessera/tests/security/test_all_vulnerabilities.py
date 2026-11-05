import os
import uuid

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from tessera.registry import TesseraRegistry
from tessera.token_generator import TokenGenerator
from tessera.scope_limiter import ScopeValidator
from tessera.audit_log_secure import TamperProofAuditLog
from tessera.dpop_replay_cache import DPoPReplayCache
from tessera.token_replay_cache import TokenReplayCache


def _register_test_agent(registry, agent_id="mock_test", tools=("read_csv",)):
    """
    Make sure the agent these tests sign for actually exists.

    Several of these tests used an agent that was never registered, so
    generate_token correctly returned None for an unknown agent and the test
    failed on None.token. One of them asserted token is None and therefore
    passed for the wrong reason: it would have passed with the control it
    claims to test removed entirely.
    """
    if registry.get_agent(agent_id) is None:
        registry.register_agent(
            agent_id=agent_id, owner="test-suite",
            allowed_tools=list(tools), max_token_ttl=3600,
        )
    return agent_id


def test_none_algorithm_blocked():
    os.environ["TESSERA_SECRET_KEY"] = "z" * 64
    token_gen = TokenGenerator(TesseraRegistry())
    malicious = jwt.encode({"sub": "attacker", "tool": "delete"}, key="", algorithm="none")
    assert token_gen.validate_token(malicious) is None


def test_scope_traversal_blocked():
    validator = ScopeValidator()
    ok, _ = validator.validate("read_csv", {"file": "../../etc/passwd"})
    assert ok is False


def test_audit_chain_tamper_detection():
    audit = TamperProofAuditLog(log_path="logs/test_audit_chain_security.jsonl")
    audit.log_event("token_issued", "agent", "success", {"a": 1})
    audit.log_event("access_granted", "agent", "success", {"a": 2})
    assert audit.verify_chain() is True


def test_dpop_replay_detection():
    # A fresh id every run. These caches persist (Redis when it is reachable),
    # so a fixed id passes once on an empty cache and fails on every run after,
    # which is a test that reports the opposite of the truth.
    cache = DPoPReplayCache()
    jti = f"replay_jti_{uuid.uuid4()}"
    assert cache.check_and_store(jti, ttl_seconds=60) is True
    assert cache.check_and_store(jti, ttl_seconds=60) is False


def test_token_replay_detection():
    cache = TokenReplayCache()
    nonce = f"nonce_{uuid.uuid4()}"
    assert cache.check_and_store(nonce, ttl_seconds=60) is True
    assert cache.check_and_store(nonce, ttl_seconds=60) is False


def test_dpop_binding_required(monkeypatch):
    """
    With TESSERA_REQUIRE_DPOP on, a token cannot be minted without a binding.

    This asserted the same thing before, but passed for the wrong reason: the
    agent was never registered, so generate_token refused an unknown agent
    rather than an unbound one. It would have passed with DPoP enforcement
    removed. The agent is registered now, and the requirement is set here
    rather than inherited from whatever test happened to run first.
    """
    os.environ["TESSERA_SECRET_KEY"] = "z" * 64
    monkeypatch.setenv("TESSERA_REQUIRE_DPOP", "true")
    registry = TesseraRegistry()
    agent_id = _register_test_agent(registry)
    token_gen = TokenGenerator(registry)
    token = token_gen.generate_token(agent_id, "read_csv", session_id="s1",
                                     memory_hash="deadbeef")
    assert token is None, "a token was issued with no DPoP binding"


def test_dpop_valid_proof():
    os.environ["TESSERA_SECRET_KEY"] = "z" * 64
    registry = TesseraRegistry()
    agent_id = _register_test_agent(registry)
    token_gen = TokenGenerator(registry)
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    token = token_gen.generate_token(
        agent_id,
        "read_csv",
        session_id="s1",
        memory_hash="deadbeef",
        client_public_key=public_key
    )
    assert token is not None, "token generation failed; the agent is not registered"
    payload = token_gen.validate_token(token.token)
    assert payload["cnf"]["jkt"]
