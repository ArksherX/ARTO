from tessera.audit_log_secure import TamperProofAuditLog


def test_audit_detects_tamper():
    audit = TamperProofAuditLog(log_path="logs/test_audit_chain_tamper.jsonl")
    audit.log_event("event1", "agent1", "success", {"a": 1})
    audit.log_event("event2", "agent1", "success", {"a": 2})
    assert audit.verify_chain() is True

    # Tamper the log by rewriting the file
    with open("logs/test_audit_chain_tamper.jsonl", "r", encoding="utf-8") as f:
        lines = f.readlines()
    lines[0] = lines[0].replace("event1", "tampered")
    with open("logs/test_audit_chain_tamper.jsonl", "w", encoding="utf-8") as f:
        f.writelines(lines)

    assert audit.verify_chain() is False
