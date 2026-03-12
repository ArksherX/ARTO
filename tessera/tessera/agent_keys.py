import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def _canonical_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + pad)


def key_id_from_public(public_key_pem: str) -> str:
    return hashlib.sha256(public_key_pem.encode("utf-8")).hexdigest()


def generate_keypair() -> Tuple[str, str, str]:
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return key_id_from_public(public_pem), private_pem, public_pem


def sign_payload(private_key_pem: str, payload: Dict[str, Any]) -> str:
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"), password=None
    )
    signature = private_key.sign(_canonical_bytes(payload))
    return _b64url(signature)


def verify_payload(public_key_pem: str, payload: Dict[str, Any], signature_b64: str) -> bool:
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        public_key.verify(_b64url_decode(signature_b64), _canonical_bytes(payload))
        return True
    except Exception:
        return False


def load_or_create_root_key(path: Path) -> Dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))

    key_id, private_pem, public_pem = generate_keypair()
    record = {
        "key_id": key_id,
        "private_key": private_pem,
        "public_key": public_pem,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


def sign_public_key(root_private_pem: str, agent_public_pem: str) -> str:
    payload = {"public_key": agent_public_pem}
    return sign_payload(root_private_pem, payload)
