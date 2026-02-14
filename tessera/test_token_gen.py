#!/usr/bin/env python3
"""
Test token generation in isolation
"""
import sys
import os
sys.path.insert(0, '.')

print("🔍 Testing token generation...")

try:
    if not os.getenv("TESSERA_SECRET_KEY"):
        os.environ["TESSERA_SECRET_KEY"] = "a" * 64

    # 1. Test registry
    print("\n1. Testing Registry...")
    from tessera.registry import TesseraRegistry
    registry = TesseraRegistry()
    print(f"✅ Registry has {len(registry.list_agents())} agents")
    
    # 2. Test token generator
    print("\n2. Testing Token Generator...")
    from tessera.token_generator import TokenGenerator
    token_gen = TokenGenerator(registry)
    print("✅ Token generator created")
    
    # 3. Try to generate a token
    print("\n3. Generating test token...")
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    from tessera.session_store import SessionStateStore

    agent_id = "agent_financial_bot_01"
    tool = "read_csv"
    
    # Generate DPoP public key
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    session_id = "test_session_01"
    memory_state = b"initial_memory_state"
    memory_hash = SessionStateStore.compute_memory_hash(memory_state)

    token = token_gen.generate_token(
        agent_id,
        tool,
        session_id=session_id,
        memory_hash=memory_hash,
        client_public_key=public_key
    )
    
    if token:
        print(f"✅ Token generated successfully!")
        print(f"   JTI: {token.jti}")
        print(f"   Issued: {token.issued_at}")
        print(f"   Expires: {token.expires_at}")
        print(f"   Token length: {len(token.token)} chars")
    else:
        print("❌ Token generation returned None")
        
except Exception as e:
    print(f"❌ Error: {e}")
    print("\nFull traceback:")
    import traceback
    traceback.print_exc()
