from core.access_audit import AccessAuditLogger


def test_access_audit_fallback(tmp_path):
    path = tmp_path / "access.jsonl"
    logger = AccessAuditLogger(dsn=None, fallback_path=str(path))
    logger.log_access("user", "query", 5, "127.0.0.1", "pytest", alert_triggered=False)
    assert path.exists()
    assert path.read_text().strip() != ""
