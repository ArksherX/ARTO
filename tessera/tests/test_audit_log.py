from tessera.audit_log_secure import TamperProofAuditLog


def test_audit_log_chain():
    audit = TamperProofAuditLog(log_path="logs/test_audit_chain.jsonl")
    audit.log_event("event1", "agent1", "success", {"a": 1})
    audit.log_event("event2", "agent1", "success", {"a": 2})
    assert audit.verify_chain() is True
