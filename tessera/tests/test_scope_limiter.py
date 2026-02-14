from tessera.scope_limiter import ScopeValidator


def test_scope_limiter_blocks_traversal():
    validator = ScopeValidator()
    ok, reason = validator.validate("read_csv", {"file": "../../etc/passwd"})
    assert ok is False
    assert "Access denied" in reason
