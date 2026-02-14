import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from tessera.registry import TesseraRegistry
from tessera.token_generator import TokenGenerator
from tessera.revocation import RevocationList
from tessera.gatekeeper import Gatekeeper, AccessDecision


def test_full_workflow():
    os.environ["TESSERA_SECRET_KEY"] = "z" * 64
    registry = TesseraRegistry()
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
    result = gatekeeper.validate_access(token.token, "read_csv")
    assert result.decision == AccessDecision.ALLOW
