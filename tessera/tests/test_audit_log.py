import os

from tessera.audit_log_secure import TamperProofAuditLog


def test_audit_log_chain():
    # Same non-hermetic-append shape as test_audit_tamper.py -- a second run
    # against a non-empty file would append onto stale entries and break the
    # chain linkage. Start from a clean file each time.
    log_path = "logs/test_audit_chain.jsonl"
    if os.path.exists(log_path):
        os.remove(log_path)

    audit = TamperProofAuditLog(log_path=log_path)
    audit.log_event("event1", "agent1", "success", {"a": 1})
    audit.log_event("event2", "agent1", "success", {"a": 2})
    assert audit.verify_chain() is True
