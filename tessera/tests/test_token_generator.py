import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from tessera.registry import TesseraRegistry
from tessera.token_generator import TokenGenerator


def test_generate_and_validate_token():
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
    assert token is not None

    payload = token_gen.validate_token(token.token)
    assert payload is not None
    assert payload["sub"] == "mock_test"


def test_token_includes_nonce_when_enabled():
    os.environ["TESSERA_SECRET_KEY"] = "y" * 64
    os.environ["TESSERA_INCLUDE_NONCE"] = "true"
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
    assert "nonce" in payload
