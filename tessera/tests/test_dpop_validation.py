import os
import jwt
import uuid
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from tessera.registry import TesseraRegistry
from tessera.token_generator import TokenGenerator


def _dpop_proof(private_key, url: str, method: str = "POST") -> str:
    pub = private_key.public_key().public_numbers()
    x = pub.x.to_bytes((pub.x.bit_length() + 7) // 8, "big")
    y = pub.y.to_bytes((pub.y.bit_length() + 7) // 8, "big")
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": jwt.utils.base64url_encode(x).decode("utf-8"),
        "y": jwt.utils.base64url_encode(y).decode("utf-8")
    }
    payload = {"htu": url, "htm": method, "iat": int(time.time()), "jti": uuid.uuid4().hex}
    headers = {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
    return jwt.encode(payload, private_key, algorithm="ES256", headers=headers)


def test_dpop_proof_validation():
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
    dpop = _dpop_proof(private_key, "https://tessera.local/tokens/validate")
    assert token_gen.validate_dpop_proof(dpop, payload["cnf"]["jkt"], expected_htu="https://tessera.local/tokens/validate", expected_htm="POST")
