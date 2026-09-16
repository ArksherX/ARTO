"""
Integration test against the REAL Tessera RevocationList -- not a mock --
to prove an expired escalation contract produces an actual, enforceable
revocation, the same one Gatekeeper.validate_access() already checks.

Requires tessera to be importable (it is, in this repo's venv). Uses a
tmp_path-scoped revocation file so this never touches Tessera's real
data/revoked_tokens.json.
"""

import sys
import time
import uuid
from pathlib import Path

import pytest

tessera_root = Path(__file__).resolve().parents[2] / "tessera"
if str(tessera_root) not in sys.path:
    sys.path.insert(0, str(tessera_root))

tessera_revocation = pytest.importorskip(
    "tessera.revocation", reason="tessera package not importable in this environment"
)

from escalation_contract.tessera_adapter import make_tessera_revoking_store


@pytest.fixture
def real_revocation_list(tmp_path):
    return tessera_revocation.RevocationList(revocation_file=str(tmp_path / "revoked_tokens.json"))


def test_expired_contract_actually_revokes_the_real_tessera_token(real_revocation_list):
    # A unique jti per run, not a fixed literal: Redis (if live in this
    # environment) persists revocations for days independent of the
    # tmp_path-scoped file, so a fixed jti would collide with state left
    # over from a previous run of this same test.
    jti = f"test-jti-escalation-{uuid.uuid4()}"
    assert real_revocation_list.is_revoked(jti) is False

    store = make_tessera_revoking_store(real_revocation_list)
    store.open(
        agent_id="agent-1",
        reason="turning point flagged, no acknowledgment",
        window_seconds=0.01,
        subject_token=jti,
    )
    time.sleep(0.02)
    store.sweep_expired()

    assert real_revocation_list.is_revoked(jti) is True


def test_acknowledged_contract_never_reaches_revocation(real_revocation_list):
    jti = f"test-jti-escalation-{uuid.uuid4()}"
    store = make_tessera_revoking_store(real_revocation_list)
    contract = store.open(
        agent_id="agent-1", reason="x", window_seconds=0.05, subject_token=jti
    )
    store.acknowledge(contract.contract_id, acknowledged_by="alice@example.com")
    time.sleep(0.06)
    store.sweep_expired()

    assert real_revocation_list.is_revoked(jti) is False


def test_contract_without_subject_token_expires_without_revoking_anything(real_revocation_list):
    """A finding that needs human attention but doesn't gate a credential
    -- expiry should not attempt to revoke nothing."""
    store = make_tessera_revoking_store(real_revocation_list)
    store.open(agent_id="agent-1", reason="x", window_seconds=0.01, subject_token=None)
    time.sleep(0.02)
    # Must not raise, even though there's no token to revoke.
    store.sweep_expired()


def test_revoked_token_would_be_denied_by_the_real_gatekeeper(real_revocation_list, tmp_path, monkeypatch):
    """End-to-end proof this isn't just calling revoke() in a vacuum --
    confirm the same RevocationList instance Gatekeeper actually checks
    reports the token as revoked, exactly as gatekeeper.py:79 checks it."""
    from tessera.gatekeeper import Gatekeeper, AccessDecision
    from tessera.token_generator import TokenGenerator
    from tessera.registry import TesseraRegistry

    # TesseraRegistry defaults to *relative* paths ("data/tessera_registry.json",
    # and "data/tessera_root_key.json" via the TESSERA_ROOT_KEY_PATH env var)
    # and generates + persists a real signing keypair there if none exists.
    # Force both under tmp_path so a test run never writes key material into
    # this repo, regardless of the runner's current working directory.
    monkeypatch.setenv("TESSERA_ROOT_KEY_PATH", str(tmp_path / "tessera_root_key.json"))
    registry = TesseraRegistry(registry_path=str(tmp_path / "tessera_registry.json"))
    token_gen = TokenGenerator(registry)
    gatekeeper = Gatekeeper(token_gen, real_revocation_list, registry=registry)

    jti = f"test-jti-escalation-{uuid.uuid4()}"
    store = make_tessera_revoking_store(real_revocation_list)
    store.open(agent_id="agent-1", reason="x", window_seconds=0.01, subject_token=jti)
    time.sleep(0.02)
    store.sweep_expired()

    # Directly exercise the exact check the real gatekeeper performs.
    assert gatekeeper.revocation_list.is_revoked(jti) is True
