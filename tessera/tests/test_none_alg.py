import os
import jwt
from tessera.registry import TesseraRegistry
from tessera.token_generator import TokenGenerator


def test_none_algorithm_rejected():
    os.environ["TESSERA_SECRET_KEY"] = "z" * 64
    registry = TesseraRegistry()
    token_gen = TokenGenerator(registry)

    malicious = jwt.encode({"sub": "attacker", "tool": "delete"}, key="", algorithm="none")
    assert token_gen.validate_token(malicious) is None
