import os
from fastapi import FastAPI
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from tessera.registry import TesseraRegistry
from tessera.token_generator import TokenGenerator
from tessera.session_store import SessionStateStore
from tessera.memory_guard import SessionMemoryGuard


def _public_key():
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")


def test_memory_guard_allows_and_denies():
    os.environ["TESSERA_SECRET_KEY"] = "z" * 64
    registry = TesseraRegistry()
    token_gen = TokenGenerator(registry)
    session_store = SessionStateStore()

    app = FastAPI()
    app.add_middleware(SessionMemoryGuard, token_generator=token_gen, session_store=session_store)

    @app.get("/protected")
    def protected():
        return {"ok": True}

    session_id = "s1"
    memory_hash = session_store.compute_memory_hash(b"state1")
    session_store.set_memory_hash("mock_test", session_id, memory_hash, ttl=3600)

    token = token_gen.generate_token(
        "mock_test",
        "read_csv",
        session_id=session_id,
        memory_hash=memory_hash,
        client_public_key=_public_key()
    )
    client = TestClient(app)
    ok = client.get("/protected", headers={"Authorization": f"Bearer {token.token}"})
    assert ok.status_code == 200

    session_store.set_memory_hash("mock_test", session_id, "deadbeef", ttl=3600)
    denied = client.get("/protected", headers={"Authorization": f"Bearer {token.token}"})
    assert denied.status_code == 403
