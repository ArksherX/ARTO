#!/usr/bin/env python3
"""
Vestigia Integration Test Suite
End-to-end tests that exercise multiple subsystems together.

Usage:
    pytest integration_tests.py -v
    python integration_tests.py   # standalone
"""

import json
import os
import sys
import tempfile
import threading
import time
from datetime import datetime, UTC
from pathlib import Path

import pytest

# Ensure project root on path
sys.path.insert(0, str(Path(__file__).parent))

os.environ["VESTIGIA_ENABLE_ANCHORING"] = "false"

from core.ledger_engine import VestigiaLedger, StructuredEvidence
from validator import VestigiaValidator
from core.data_classification import DataClassifier, ClassificationLevel
from core.enrichment_service import EnrichmentService
from core.otel_integration import VestigiaTracer


# ==================================================================
# Suite 1: Ledger → Validator round-trip
# ==================================================================


class TestLedgerValidatorRoundTrip:
    """Events written by the ledger must pass the validator unchanged."""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        self.path = str(tmp_path / "ledger.json")
        self.ledger = VestigiaLedger(
            self.path,
            enable_merkle_witness=False,
            enable_external_anchor=False,
        )

    def test_fresh_ledger_validates(self):
        validator = VestigiaValidator(self.path)
        report = validator.validate_full()
        assert report.is_valid

    def test_many_events_validate(self):
        for i in range(50):
            self.ledger.append_event(
                f"agent-{i % 5}",
                "HEARTBEAT" if i % 2 == 0 else "TOKEN_ISSUED",
                "SUCCESS",
                StructuredEvidence(summary=f"Event {i}", risk_score=i * 0.01),
            )
        validator = VestigiaValidator(self.path)
        report = validator.validate_full()
        assert report.is_valid
        assert report.total_entries == 51  # genesis + 50

    def test_tamper_detected(self):
        self.ledger.append_event("a", "TOKEN_ISSUED", "SUCCESS", "original")
        # Tamper
        with open(self.path) as f:
            data = json.load(f)
        data[1]["evidence"] = "TAMPERED"
        with open(self.path, "w") as f:
            json.dump(data, f)

        validator = VestigiaValidator(self.path)
        report = validator.validate_full()
        assert not report.is_valid


# ==================================================================
# Suite 2: Ledger → Enrichment → PII pipeline
# ==================================================================


class TestEnrichmentPIIPipeline:
    """Events flow through enrichment and PII scrubbing."""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        path = str(tmp_path / "ledger.json")
        self.ledger = VestigiaLedger(
            path,
            enable_merkle_witness=False,
            enable_external_anchor=False,
        )
        self.enricher = EnrichmentService(ledger=self.ledger)
        self.classifier = DataClassifier(gdpr_mode=True)

    def test_enrich_then_classify(self):
        event = {
            "actor_id": "agent-007",
            "action_type": "ACCESS_REQUEST",
            "status": "SUCCESS",
            "timestamp": datetime.now(UTC).isoformat(),
            "evidence": {
                "summary": "User john@example.com accessed database",
                "metadata": {"ip": "192.168.1.42"},
            },
        }
        enriched = self.enricher.enrich_event(event)
        result = self.classifier.classify_event(enriched)
        # Should detect email as PII
        assert result.level.value in ("CONFIDENTIAL", "RESTRICTED")
        assert len(result.pii_found) >= 1

    def test_scrub_after_enrich(self):
        event = {
            "actor_id": "agent-007",
            "action_type": "TOOL_EXECUTION",
            "status": "SUCCESS",
            "evidence": {
                "summary": "SSN 123-45-6789 detected in output",
                "metadata": {"ip": "10.0.0.1"},
            },
        }
        enriched = self.enricher.enrich_event(event)
        scrubbed = self.classifier.auto_scrub(enriched)
        # SSN should be redacted
        assert "123-45-6789" not in json.dumps(scrubbed)


# ==================================================================
# Suite 3: Tracing → Ledger correlation
# ==================================================================


class TestTracingLedgerCorrelation:
    """Trace context flows through events."""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        path = str(tmp_path / "ledger.json")
        self.ledger = VestigiaLedger(
            path,
            enable_merkle_witness=False,
            enable_external_anchor=False,
        )
        self.tracer = VestigiaTracer(service_name="integration-test")

    def teardown_method(self):
        self.tracer.shutdown()

    def test_traced_event_has_ids(self):
        span = self.tracer.start_span("integration-op")
        event_dict = {
            "actor_id": "traced-agent",
            "action_type": "SECURITY_SCAN",
            "status": "SUCCESS",
        }
        self.tracer.trace_event(event_dict)
        assert "trace_id" in event_dict
        assert "span_id" in event_dict
        assert "correlation_id" in event_dict
        self.tracer.end_span(span)

    def test_context_propagation_round_trip(self):
        span = self.tracer.start_span("propagation-test")
        headers = {}
        self.tracer.inject_context(headers)
        assert "traceparent" in headers

        extracted = self.tracer.extract_context(headers)
        assert extracted is not None
        assert "trace_id" in extracted
        self.tracer.end_span(span)


# ==================================================================
# Suite 4: Concurrent ledger stress test
# ==================================================================


class TestConcurrentStress:
    """Multiple threads writing simultaneously."""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        path = str(tmp_path / "ledger.json")
        self.ledger = VestigiaLedger(
            path,
            enable_merkle_witness=False,
            enable_external_anchor=False,
        )

    def test_10_threads_100_events(self):
        errors = []
        n_threads = 10
        events_per_thread = 10

        def worker(tid):
            try:
                for i in range(events_per_thread):
                    self.ledger.append_event(
                        f"thread-{tid}",
                        "HEARTBEAT",
                        "SUCCESS",
                        f"stress-{tid}-{i}",
                    )
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=worker, args=(t,))
            for t in range(n_threads)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        stats = self.ledger.get_statistics()
        expected = 1 + n_threads * events_per_thread  # genesis + events
        assert stats["total_events"] == expected

        # Verify integrity after concurrent writes
        valid, idx = self.ledger.verify_integrity()
        assert valid is True


# ==================================================================
# Suite 5: Full event lifecycle
# ==================================================================


class TestFullEventLifecycle:
    """Create → query → export → validate cycle."""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        self.tmp = tmp_path
        path = str(tmp_path / "ledger.json")
        self.ledger = VestigiaLedger(
            path,
            enable_merkle_witness=False,
            enable_external_anchor=False,
        )
        self.path = path

    def test_full_lifecycle(self):
        # 1. Create events
        events = []
        for i in range(5):
            ev = self.ledger.append_event(
                "lifecycle-agent",
                "TOKEN_ISSUED",
                "SUCCESS",
                StructuredEvidence(summary=f"Token {i}"),
            )
            events.append(ev)

        # 2. Query
        results = self.ledger.query_events(actor_id="lifecycle-agent")
        assert len(results) == 5

        # 3. Export JSON
        json_out = str(self.tmp / "report.json")
        self.ledger.export_compliance_report(json_out, format="json")
        with open(json_out) as f:
            report = json.load(f)
        assert len(report["ledger"]) == 6  # genesis + 5

        # 4. Export CSV
        csv_out = str(self.tmp / "report.csv")
        self.ledger.export_compliance_report(csv_out, format="csv")

        # 5. Validate
        validator = VestigiaValidator(self.path)
        report = validator.validate_full()
        assert report.is_valid

    def test_statistics_accurate(self):
        for i in range(3):
            self.ledger.append_event("a", "HEARTBEAT", "SUCCESS", f"s-{i}")
        stats = self.ledger.get_statistics()
        assert stats["total_events"] == 4  # genesis + 3


# ==================================================================
# Suite 6: Enrichment with IOC matching
# ==================================================================


class TestIOCEnrichmentIntegration:
    def test_ioc_match_raises_risk(self):
        svc = EnrichmentService()
        event = {
            "actor_id": "suspicious-agent",
            "action_type": "TOOL_EXECUTION",
            "status": "SUCCESS",
            "evidence": {
                "summary": "Connection to evil.example.com detected",
            },
        }
        enriched = svc.enrich_event(event)
        enrichments = enriched["evidence"]["enrichment"]
        assert len(enrichments.get("ioc_matches", [])) >= 1

    def test_clean_event_no_iocs(self):
        svc = EnrichmentService()
        event = {
            "actor_id": "good-agent",
            "action_type": "HEARTBEAT",
            "status": "SUCCESS",
            "evidence": {"summary": "All clear"},
        }
        enriched = svc.enrich_event(event)
        iocs = enriched["evidence"]["enrichment"].get("ioc_matches", [])
        assert len(iocs) == 0


# ==================================================================
# Suite 7: PII classification cascade
# ==================================================================


class TestPIICascade:
    def test_multi_pii_classified_at_highest(self):
        clf = DataClassifier()
        event = {
            "evidence": {
                "summary": "User alice@corp.com, SSN 123-45-6789, IP 10.0.0.1",
            }
        }
        result = clf.classify_event(event)
        # SSN is RESTRICTED, email is CONFIDENTIAL, IP is INTERNAL
        # Overall should be RESTRICTED (highest)
        assert result.level == ClassificationLevel.RESTRICTED

    def test_custom_pattern_integrates(self):
        clf = DataClassifier()
        clf.add_pattern("internal_id", r"VEST-\d{8}", ClassificationLevel.CONFIDENTIAL)
        event = {"data": "Processing VEST-12345678"}
        result = clf.classify_event(event)
        assert any(m.pii_type == "internal_id" for m in result.pii_found)


# ==================================================================
# Standalone runner
# ==================================================================

if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v", "--tb=short"]))
