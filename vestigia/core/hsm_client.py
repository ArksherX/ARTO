#!/usr/bin/env python3
"""
HSM client abstraction for signing and verifying witness anchors.
Supports local software HSM (RSA), AWS KMS, and YubiHSM2 (if installed).
"""

from __future__ import annotations

import os
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class HSMClient:
    """Abstract HSM client interface."""

    def sign(self, data: bytes) -> bytes:  # pragma: no cover - interface
        raise NotImplementedError

    def verify(self, data: bytes, signature: bytes) -> bool:  # pragma: no cover - interface
        raise NotImplementedError

    def public_key_pem(self) -> str:  # pragma: no cover - interface
        raise NotImplementedError


class LocalHSM(HSMClient):
    """Software-backed HSM using a local RSA keypair (for dev/test)."""

    def __init__(self, key_path: str = "data/hsm_private.pem"):
        self.key_path = key_path
        self._private_key = None
        self._load_or_create_key()

    def _load_or_create_key(self):
        os.makedirs(os.path.dirname(self.key_path), exist_ok=True)
        if os.path.exists(self.key_path):
            with open(self.key_path, "rb") as f:
                self._private_key = serialization.load_pem_private_key(f.read(), password=None)
            return
        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        with open(self.key_path, "wb") as f:
            f.write(
                self._private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

    def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )

    def verify(self, data: bytes, signature: bytes) -> bool:
        try:
            self._private_key.public_key().verify(
                signature,
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False

    def public_key_pem(self) -> str:
        return (
            self._private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("utf-8")
        )


class AWSKMSHSM(HSMClient):
    """AWS KMS-backed signing (requires boto3)."""

    def __init__(self, key_id: str, region: Optional[str] = None):
        import boto3

        self.key_id = key_id
        self.client = boto3.client("kms", region_name=region or os.getenv("AWS_REGION", "us-east-1"))
        self._public_key = self.client.get_public_key(KeyId=self.key_id)["PublicKey"]

    def sign(self, data: bytes) -> bytes:
        response = self.client.sign(
            KeyId=self.key_id,
            Message=data,
            MessageType="RAW",
            SigningAlgorithm="RSASSA_PSS_SHA_256",
        )
        return response["Signature"]

    def verify(self, data: bytes, signature: bytes) -> bool:
        response = self.client.verify(
            KeyId=self.key_id,
            Message=data,
            MessageType="RAW",
            Signature=signature,
            SigningAlgorithm="RSASSA_PSS_SHA_256",
        )
        return bool(response.get("SignatureValid"))

    def public_key_pem(self) -> str:
        return serialization.load_der_public_key(self._public_key).public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")


class YubiHSM2Client(HSMClient):
    """YubiHSM2-backed signing (requires yubihsm)."""

    def __init__(self, connector: str, key_id: int, password: str):
        from yubihsm import YubiHsm
        from yubihsm.backends import YubiHsmBackend

        self.backend = YubiHsmBackend(connector)
        self.session = YubiHsm.connect(self.backend).create_session_derived(1, password)
        self.key_id = key_id

    def sign(self, data: bytes) -> bytes:
        from yubihsm.defs import ALGORITHM
        from yubihsm import objects

        key = objects.AsymmetricKey(self.session, self.key_id)
        return key.sign_pss(data, ALGORITHM.RSA_PSS_SHA256)

    def verify(self, data: bytes, signature: bytes) -> bool:
        from yubihsm.defs import ALGORITHM
        from yubihsm import objects

        key = objects.AsymmetricKey(self.session, self.key_id)
        return key.verify_pss(data, signature, ALGORITHM.RSA_PSS_SHA256)

    def public_key_pem(self) -> str:
        from yubihsm import objects

        key = objects.AsymmetricKey(self.session, self.key_id)
        return key.get_public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")


def get_hsm_from_env() -> Optional[HSMClient]:
    provider = os.getenv("VESTIGIA_HSM_PROVIDER", "").lower()
    if not provider:
        return None
    if provider == "local":
        return LocalHSM(os.getenv("VESTIGIA_HSM_KEY_PATH", "data/hsm_private.pem"))
    if provider == "aws_kms":
        key_id = os.getenv("VESTIGIA_HSM_AWS_KMS_KEY_ID")
        if not key_id:
            raise ValueError("VESTIGIA_HSM_AWS_KMS_KEY_ID required for aws_kms")
        return AWSKMSHSM(key_id)
    if provider == "yubihsm2":
        connector = os.getenv("VESTIGIA_HSM_YUBI_CONNECTOR")
        password = os.getenv("VESTIGIA_HSM_YUBI_PASSWORD")
        key_id = int(os.getenv("VESTIGIA_HSM_YUBI_KEY_ID", "0"))
        if not (connector and password and key_id):
            raise ValueError("YubiHSM2 config missing")
        return YubiHSM2Client(connector, key_id, password)
    raise ValueError(f"Unsupported HSM provider: {provider}")
