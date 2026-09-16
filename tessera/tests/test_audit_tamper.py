import os

from tessera.audit_log_secure import TamperProofAuditLog


def test_audit_detects_tamper():
    # This test appends to a fixed relative path and verifies the resulting
    # hash chain -- not hermetic against a re-run, since a second run would
    # append onto whatever the previous run left behind and legitimately
    # break the chain linkage against stale entries. Start from a clean file
    # each time.
    log_path = "logs/test_audit_chain_tamper.jsonl"
    if os.path.exists(log_path):
        os.remove(log_path)

    audit = TamperProofAuditLog(log_path=log_path)
    audit.log_event("event1", "agent1", "success", {"a": 1})
    audit.log_event("event2", "agent1", "success", {"a": 2})
    assert audit.verify_chain() is True

    # Tamper the log by rewriting the file
    with open(log_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    lines[0] = lines[0].replace("event1", "tampered")
    with open(log_path, "w", encoding="utf-8") as f:
        f.writelines(lines)

    assert audit.verify_chain() is False
