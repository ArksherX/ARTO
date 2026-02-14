#!/usr/bin/env python3
"""
Verification script for SessionMemoryGuard.
Runs a minimal FastAPI app with the middleware and validates allow/deny behavior.
"""

import os
from fastapi import FastAPI
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from tessera.registry import TesseraRegistry
from tessera.token_generator import TokenGenerator
from tessera.session_store import SessionStateStore
from tessera.memory_guard import SessionMemoryGuard


def main():
    os.environ.setdefault("TESSERA_SECRET_KEY", "z" * 64)

    registry = TesseraRegistry()
    agent_id = "mock_test"
    agent = registry.get_agent(agent_id)
    if not agent:
        raise RuntimeError("mock_test agent not found in registry")
    if "protected" not in agent.allowed_tools:
        agent.allowed_tools.append("protected")

    token_gen = TokenGenerator(registry)
    session_store = SessionStateStore()

    app = FastAPI()
    app.add_middleware(
        SessionMemoryGuard,
        token_generator=token_gen,
        session_store=session_store,
        skip_paths=set()
    )

    @app.get("/protected")
    def protected():
        return {"ok": True}

    # Generate DPoP public key for token binding
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    session_id = "session_test_guard"
    memory_state = b"initial_state"
    memory_hash = session_store.compute_memory_hash(memory_state)
    session_store.set_memory_hash(agent_id, session_id, memory_hash, ttl=3600)

    token = token_gen.generate_token(
        agent_id=agent_id,
        tool="protected",
        session_id=session_id,
        memory_hash=memory_hash,
        client_public_key=public_key
    )
    if not token:
        raise RuntimeError("Failed to generate token")

    client = TestClient(app)

    # 1) Should allow with matching memory_hash
    ok_resp = client.get(
        "/protected",
        headers={"Authorization": f"Bearer {token.token}"}
    )
    print("Allow test status:", ok_resp.status_code, ok_resp.json())

    # 2) Should deny with mismatched memory_hash
    session_store.set_memory_hash(agent_id, session_id, "deadbeef", ttl=3600)
    deny_resp = client.get(
        "/protected",
        headers={"Authorization": f"Bearer {token.token}"}
    )
    print("Deny test status:", deny_resp.status_code, deny_resp.json())


if __name__ == "__main__":
    main()
