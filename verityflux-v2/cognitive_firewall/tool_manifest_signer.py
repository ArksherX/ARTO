#!/usr/bin/env python3
"""
Tool Manifest Signing & Validation

Cryptographically signs tool manifests and detects rug-pull attacks
where tools change behavior between invocations.

Addresses OWASP MCP guide requirement for cryptographic signing of tool manifests.
"""

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, UTC
from typing import Dict, Any, Optional, List


@dataclass
class SignedManifest:
    """A cryptographically signed tool manifest"""
    tool_name: str
    manifest: Dict[str, Any]
    signature: str
    signed_at: str
    manifest_hash: str


@dataclass
class VerificationResult:
    """Result of manifest verification"""
    valid: bool
    tool_name: str
    reason: str
    manifest_hash: Optional[str] = None
    signed_at: Optional[str] = None


class ToolManifestSigner:
    """
    Cryptographic signing and verification for tool manifests.

    Uses HMAC-SHA256 to sign manifests and detect unauthorized changes.
    Maintains a baseline registry to detect rug-pull attacks where
    tool descriptions or schemas change between invocations.
    """

    def __init__(self, signing_key: Optional[str] = None):
        key = signing_key or os.getenv("VERITYFLUX_MANIFEST_KEY", "default-manifest-signing-key")
        strict_prod = os.getenv("SUITE_STRICT_MODE", "false").lower() in ("1", "true", "yes") and (
            os.getenv("MLRT_MODE", "").lower() == "prod" or os.getenv("MODE", "").lower() == "prod"
        )
        if strict_prod and key == "default-manifest-signing-key":
            raise RuntimeError("VERITYFLUX_MANIFEST_KEY must be set in strict production mode")
        self._signing_key = key.encode("utf-8")
        self._signed_baselines: Dict[str, SignedManifest] = {}

    def sign_manifest(self, manifest: Dict[str, Any]) -> SignedManifest:
        """
        Sign a tool manifest with HMAC-SHA256.

        Args:
            manifest: Must contain 'tool_name' and tool definition

        Returns:
            SignedManifest with cryptographic signature
        """
        tool_name = manifest.get("tool_name", "unknown")

        # Canonical JSON for consistent hashing
        canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
        manifest_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        # HMAC-SHA256 signature
        signature = hmac.new(
            self._signing_key,
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        signed = SignedManifest(
            tool_name=tool_name,
            manifest=manifest,
            signature=signature,
            signed_at=datetime.now(UTC).isoformat(),
            manifest_hash=manifest_hash,
        )

        # Store as baseline
        self._signed_baselines[tool_name] = signed

        return signed

    def verify_manifest(self, signed_manifest: SignedManifest) -> VerificationResult:
        """
        Verify a signed manifest's integrity.

        Returns:
            VerificationResult indicating whether signature is valid
        """
        # Recalculate signature
        canonical = json.dumps(
            signed_manifest.manifest, sort_keys=True, separators=(",", ":")
        )
        expected_sig = hmac.new(
            self._signing_key,
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(expected_sig, signed_manifest.signature):
            return VerificationResult(
                valid=False,
                tool_name=signed_manifest.tool_name,
                reason="Signature mismatch - manifest may have been tampered with",
            )

        # Verify hash
        expected_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if expected_hash != signed_manifest.manifest_hash:
            return VerificationResult(
                valid=False,
                tool_name=signed_manifest.tool_name,
                reason="Hash mismatch - manifest content has changed",
            )

        return VerificationResult(
            valid=True,
            tool_name=signed_manifest.tool_name,
            reason="Manifest signature and hash verified",
            manifest_hash=signed_manifest.manifest_hash,
            signed_at=signed_manifest.signed_at,
        )

    def detect_rug_pull(
        self, tool_name: str, current_manifest: Dict[str, Any]
    ) -> bool:
        """
        Detect if a tool's manifest has changed from its signed baseline.

        A "rug pull" is when a tool changes its description or behavior
        after initial registration, potentially to manipulate the LLM.

        Returns:
            True if rug-pull detected (manifest changed from baseline)
        """
        baseline = self._signed_baselines.get(tool_name)
        if not baseline:
            return False  # No baseline to compare against

        # Compare current manifest to baseline
        current_canonical = json.dumps(
            current_manifest, sort_keys=True, separators=(",", ":")
        )
        current_hash = hashlib.sha256(current_canonical.encode("utf-8")).hexdigest()

        return current_hash != baseline.manifest_hash

    def get_baseline(self, tool_name: str) -> Optional[SignedManifest]:
        return self._signed_baselines.get(tool_name)

    def list_signed_tools(self) -> List[str]:
        return list(self._signed_baselines.keys())


__all__ = ["ToolManifestSigner", "SignedManifest", "VerificationResult"]
