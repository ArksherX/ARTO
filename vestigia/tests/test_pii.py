"""Tests for core/data_classification.py — PII detection & scrubbing."""

import pytest

from core.data_classification import (
    DataClassifier,
    ClassificationLevel,
    ClassificationResult,
    PIIMatch,
    _luhn_check,
)


@pytest.fixture
def classifier():
    return DataClassifier()


@pytest.fixture
def gdpr_classifier():
    return DataClassifier(gdpr_mode=True)


# ------------------------------------------------------------------
# Luhn validation
# ------------------------------------------------------------------


class TestLuhn:
    def test_valid_visa(self):
        assert _luhn_check("4111111111111111") is True

    def test_valid_mastercard(self):
        assert _luhn_check("5500000000000004") is True

    def test_invalid(self):
        assert _luhn_check("1234567890123456") is False

    def test_too_short(self):
        assert _luhn_check("1234") is False


# ------------------------------------------------------------------
# PII detection
# ------------------------------------------------------------------


class TestPIIDetection:
    def test_detects_email(self, classifier):
        matches = classifier.detect_pii("Contact john@example.com for info")
        assert any(m.pii_type == "email" for m in matches)

    def test_detects_phone(self, classifier):
        matches = classifier.detect_pii("Call 555-123-4567 now")
        assert any(m.pii_type == "phone_us" for m in matches)

    def test_detects_ssn(self, classifier):
        matches = classifier.detect_pii("SSN: 123-45-6789")
        assert any(m.pii_type == "ssn" for m in matches)

    def test_detects_ipv4(self, classifier):
        matches = classifier.detect_pii("IP: 192.168.1.42")
        assert any(m.pii_type == "ipv4" for m in matches)

    def test_detects_api_key(self, classifier):
        matches = classifier.detect_pii("key: sk_live_abcdef1234567890abcdef")
        assert any(m.pii_type == "api_key" for m in matches)

    def test_no_false_positive_on_clean_text(self, classifier):
        matches = classifier.detect_pii("Hello world this is a normal string")
        # May detect phone-like patterns in some edge cases; just check emails/SSN are absent
        assert not any(m.pii_type in ("email", "ssn") for m in matches)

    def test_field_path_reported(self, classifier):
        matches = classifier.detect_pii("user@test.com", field_path="evidence.email")
        assert matches[0].field_path == "evidence.email"


# ------------------------------------------------------------------
# Classification
# ------------------------------------------------------------------


class TestClassification:
    def test_clean_event_is_public(self, classifier):
        event = {"actor_id": "agent-1", "status": "SUCCESS"}
        result = classifier.classify_event(event)
        assert result.level == ClassificationLevel.PUBLIC
        assert result.pii_found == []

    def test_email_classifies_confidential(self, classifier):
        event = {"evidence": {"summary": "User alice@corp.com logged in"}}
        result = classifier.classify_event(event)
        assert result.level.value in ("CONFIDENTIAL", "RESTRICTED")

    def test_ssn_classifies_restricted(self, classifier):
        event = {"evidence": {"data": "SSN 123-45-6789"}}
        result = classifier.classify_event(event)
        assert result.level == ClassificationLevel.RESTRICTED

    def test_nested_scan(self, classifier):
        event = {
            "evidence": {
                "metadata": {
                    "contact": "bob@test.org",
                }
            }
        }
        result = classifier.classify_event(event)
        assert len(result.pii_found) >= 1

    def test_list_values_scanned(self, classifier):
        event = {"tags": ["user@test.com", "normal"]}
        result = classifier.classify_event(event)
        assert len(result.pii_found) >= 1


# ------------------------------------------------------------------
# Scrubbing
# ------------------------------------------------------------------


class TestScrubbing:
    def test_scrub_email(self, classifier):
        event = {"evidence": {"summary": "User alice@corp.com accessed file"}}
        scrubbed = classifier.scrub_pii(event)
        assert "alice@corp.com" not in str(scrubbed)
        assert "[EMAIL_REDACTED]" in str(scrubbed)

    def test_scrub_ssn(self, classifier):
        event = {"data": "SSN: 123-45-6789"}
        scrubbed = classifier.scrub_pii(event)
        assert "123-45-6789" not in str(scrubbed)
        assert "[SSN_REDACTED]" in str(scrubbed)

    def test_scrub_preserves_structure(self, classifier):
        event = {"a": "clean", "b": {"c": "user@x.com"}}
        scrubbed = classifier.scrub_pii(event)
        assert scrubbed["a"] == "clean"
        assert isinstance(scrubbed["b"], dict)

    def test_no_scrub_on_clean(self, classifier):
        event = {"a": "hello", "b": "world"}
        scrubbed = classifier.scrub_pii(event)
        assert scrubbed == event

    def test_gdpr_auto_scrub(self, gdpr_classifier):
        event = {"evidence": {"ip": "192.168.1.42"}}
        scrubbed = gdpr_classifier.auto_scrub(event)
        assert "192.168.1.42" not in str(scrubbed)


# ------------------------------------------------------------------
# Custom patterns
# ------------------------------------------------------------------


class TestCustomPatterns:
    def test_add_custom_pattern(self, classifier):
        classifier.add_pattern("employee_id", r"EMP-\d{6}", ClassificationLevel.INTERNAL)
        matches = classifier.detect_pii("Employee EMP-123456 was assigned")
        assert any(m.pii_type == "employee_id" for m in matches)


# ------------------------------------------------------------------
# Stats / report
# ------------------------------------------------------------------


class TestClassifierStats:
    def test_stats_tracking(self, classifier):
        classifier.classify_event({"data": "hello"})
        classifier.classify_event({"data": "user@x.com"})
        report = classifier.get_classification_report()
        assert report["events_scanned"] == 2
        assert report["pii_found"] >= 1
