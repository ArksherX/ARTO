"""Tests for core/ledger_engine.py — hash chains, queries, rotation."""

import json
import threading
from datetime import datetime, UTC, timedelta

import pytest

from core.ledger_engine import (
    VestigiaLedger, VestigiaEvent, ActionType, EventStatus, StructuredEvidence,
)


class TestLedgerInitialization:
    def test_creates_genesis_block(self, ledger, tmp_ledger_path):
        with open(tmp_ledger_path) as f:
            data = json.load(f)
        assert len(data) == 1
        assert data[0]["action_type"] == "LEDGER_INITIALIZED"
        assert data[0]["actor_id"] == "SYSTEM"

    def test_idempotent_init(self, tmp_ledger_path):
        """Creating a second ledger on same path should not overwrite."""
        import os
        os.environ["VESTIGIA_ENABLE_ANCHORING"] = "false"
        l1 = VestigiaLedger(tmp_ledger_path, enable_external_anchor=False, enable_merkle_witness=False)
        l1.append_event("a", "TOKEN_ISSUED", "SUCCESS", "test")
        l2 = VestigiaLedger(tmp_ledger_path, enable_external_anchor=False, enable_merkle_witness=False)
        assert l2.get_statistics()["total_events"] == 2  # genesis + 1


class TestAppendEvent:
    def test_append_returns_event(self, ledger):
        ev = ledger.append_event("agent-1", "TOKEN_ISSUED", "SUCCESS", "tok")
        assert isinstance(ev, VestigiaEvent)
        assert ev.actor_id == "agent-1"

    def test_sequential_event_ids(self, ledger):
        e1 = ledger.append_event("a", "TOKEN_ISSUED", "SUCCESS", "e1")
        e2 = ledger.append_event("a", "TOKEN_ISSUED", "SUCCESS", "e2")
        assert e1.event_id != e2.event_id

    def test_structured_evidence(self, ledger):
        ev = ledger.append_event(
            "a", "SECURITY_SCAN", "SUCCESS",
            StructuredEvidence(summary="scan ok", risk_score=0.1),
        )
        parsed = ev.get_evidence_structured()
        assert parsed.summary == "scan ok"
        assert parsed.risk_score == 0.1


class TestHashChainIntegrity:
    def test_valid_chain(self, populated_ledger):
        valid, idx = populated_ledger.verify_integrity()
        assert valid is True
        assert idx is None

    def test_tamper_detection(self, populated_ledger, tmp_ledger_path):
        # Tamper with entry 3
        with open(tmp_ledger_path) as f:
            data = json.load(f)
        data[3]["evidence"]["summary"] = "TAMPERED"
        with open(tmp_ledger_path, "w") as f:
            json.dump(data, f)

        valid, idx = populated_ledger.verify_integrity()
        assert valid is False
        assert idx == 3


class TestQuery:
    def test_query_by_actor(self, populated_ledger):
        results = populated_ledger.query_events(actor_id="agent-001")
        assert all("agent-001" in e.actor_id for e in results)

    def test_query_by_action(self, populated_ledger):
        results = populated_ledger.query_events(action_type="TOKEN_ISSUED")
        assert all(e.action_type == "TOKEN_ISSUED" for e in results)

    def test_query_by_status(self, populated_ledger):
        results = populated_ledger.query_events(status="CRITICAL")
        assert len(results) >= 2

    def test_query_limit(self, populated_ledger):
        results = populated_ledger.query_events(limit=3)
        assert len(results) <= 3


class TestStatistics:
    def test_stats_counts(self, populated_ledger):
        stats = populated_ledger.get_statistics()
        assert stats["total_events"] == 11  # 1 genesis + 10


class TestExport:
    def test_export_json(self, populated_ledger, tmp_path):
        out = str(tmp_path / "report.json")
        populated_ledger.export_compliance_report(out, format="json")
        with open(out) as f:
            data = json.load(f)
        assert "ledger" in data
        assert len(data["ledger"]) == 11

    def test_export_csv(self, populated_ledger, tmp_path):
        out = str(tmp_path / "report.csv")
        populated_ledger.export_compliance_report(out, format="csv")
        import csv
        with open(out) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 11


class TestConcurrency:
    def test_concurrent_appends(self, ledger):
        errors = []

        def append(n):
            try:
                for i in range(5):
                    ledger.append_event(f"thread-{n}", "HEARTBEAT", "SUCCESS", f"msg-{i}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=append, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        stats = ledger.get_statistics()
        assert stats["total_events"] == 21  # genesis + 4*5


class TestRotation:
    def test_rotation_triggers(self, tmp_ledger_path):
        import os
        os.environ["VESTIGIA_ENABLE_ANCHORING"] = "false"
        led = VestigiaLedger(
            tmp_ledger_path,
            max_entries=5,
            enable_external_anchor=False,
            enable_merkle_witness=False,
        )
        for i in range(6):
            led.append_event("a", "HEARTBEAT", "SUCCESS", f"ev-{i}")
        # After rotation the ledger should have been reset
        stats = led.get_statistics()
        assert stats["total_events"] < 8  # rotated, not all 7
