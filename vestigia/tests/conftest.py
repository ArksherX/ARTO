"""Shared pytest fixtures for Vestigia test suite."""

import os
import sys
import json
import shutil
import tempfile
from pathlib import Path
from datetime import datetime, UTC

import pytest

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.ledger_engine import (
    VestigiaLedger, ActionType, EventStatus, StructuredEvidence,
)


@pytest.fixture
def tmp_ledger_dir(tmp_path):
    """Temporary directory that mimics the data/ layout."""
    ledger_dir = tmp_path / "data"
    ledger_dir.mkdir()
    yield ledger_dir
    shutil.rmtree(tmp_path, ignore_errors=True)


@pytest.fixture
def tmp_ledger_path(tmp_ledger_dir):
    return str(tmp_ledger_dir / "vestigia_ledger.json")


@pytest.fixture
def ledger(tmp_ledger_path):
    """Fresh VestigiaLedger with anchoring disabled."""
    os.environ.pop("VESTIGIA_ENABLE_ANCHORING", None)
    os.environ["VESTIGIA_ENABLE_ANCHORING"] = "false"
    led = VestigiaLedger(
        ledger_path=tmp_ledger_path,
        enable_merkle_witness=False,
        enable_external_anchor=False,
    )
    return led


@pytest.fixture
def populated_ledger(ledger):
    """Ledger pre-loaded with 10 sample events of various types."""
    samples = [
        ("agent-001", "TOKEN_ISSUED", "SUCCESS", "Token issued for agent-001"),
        ("agent-002", "SECURITY_SCAN", "SUCCESS", "Scan passed"),
        ("agent-003", "TOOL_EXECUTION", "BLOCKED", "Attempted read_csv without auth"),
        ("agent-001", "ACCESS_REQUEST", "SUCCESS", "Read access granted"),
        ("agent-004", "THREAT_DETECTED", "CRITICAL", "SQL injection attempt"),
        ("agent-002", "TOKEN_REVOKED", "SUCCESS", "Token revoked by admin"),
        ("agent-001", "HEARTBEAT", "SUCCESS", "System heartbeat"),
        ("agent-003", "ACCESS_DENIED", "BLOCKED", "Denied access to /etc/passwd"),
        ("agent-005", "IDENTITY_VERIFIED", "SUCCESS", "Passport verified"),
        ("agent-004", "ACTION_BLOCKED", "CRITICAL", "Malicious payload blocked"),
    ]
    for actor, action, status, summary in samples:
        ledger.append_event(
            actor_id=actor,
            action_type=action,
            status=status,
            evidence=StructuredEvidence(summary=summary),
        )
    return ledger


@pytest.fixture
def validator(tmp_ledger_path):
    from validator import VestigiaValidator
    return VestigiaValidator(ledger_path=tmp_ledger_path)


@pytest.fixture
def sample_event():
    return {
        "actor_id": "test-agent",
        "action_type": "TOOL_EXECUTION",
        "status": "SUCCESS",
        "evidence": {"summary": "Test event", "metadata": {"ip": "10.0.0.1"}},
    }
