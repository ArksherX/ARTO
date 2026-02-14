import os
import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from tessera.registry import TesseraRegistry
from tessera.token_generator import TokenGenerator
from tessera.scope_limiter import ScopeValidator
from tessera.audit_log_secure import TamperProofAuditLog
from tessera.dpop_replay_cache import DPoPReplayCache
from tessera.token_replay_cache import TokenReplayCache


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
    cache = DPoPReplayCache()
    assert cache.check_and_store("replay_jti", ttl_seconds=60) is True
    assert cache.check_and_store("replay_jti", ttl_seconds=60) is False


def test_token_replay_detection():
    cache = TokenReplayCache()
    assert cache.check_and_store("nonce", ttl_seconds=60) is True
    assert cache.check_and_store("nonce", ttl_seconds=60) is False


def test_dpop_binding_required():
    os.environ["TESSERA_SECRET_KEY"] = "z" * 64
    registry = TesseraRegistry()
    token_gen = TokenGenerator(registry)
    token = token_gen.generate_token("mock_test", "read_csv", session_id="s1", memory_hash="deadbeef")
    assert token is None


def test_dpop_valid_proof():
    os.environ["TESSERA_SECRET_KEY"] = "z" * 64
    registry = TesseraRegistry()
    token_gen = TokenGenerator(registry)
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
    payload = token_gen.validate_token(token.token)
    assert payload["cnf"]["jkt"]
