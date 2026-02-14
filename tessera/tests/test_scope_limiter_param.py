import pytest
from tessera.scope_limiter import ScopeValidator


@pytest.mark.parametrize(
    "path,expected",
    [
        ("data/public/report.csv", True),
        ("reports/q1.csv", True),
        ("data/private/passwords.csv", False),
        ("data/public/secret.csv", False),
        ("data/public/key.csv", False),
        ("../../etc/passwd", False),
        ("data/public/report.txt", False),
        ("reports/report.txt", False),
        ("data/public/finance.csv", True),
        ("reports/2026.csv", True),
        ("data/public/secret_report.csv", False),
        ("data/public/passwords.csv", False),
        ("data/public/keys.csv", False),
        ("data/public/ok.csv", True),
        ("reports/q2.csv", True),
        ("data/public/secret-key.csv", False),
        ("data/public/annual.csv", True),
        ("data/other/report.csv", False),
    ]
)
def test_read_csv_paths(path, expected):
    validator = ScopeValidator()
    ok, _ = validator.validate("read_csv", {"file": path})
    assert ok is expected


@pytest.mark.parametrize(
    "query,expected",
    [
        ("SELECT * FROM users", True),
        ("select name from users", True),
        ("DELETE FROM users", False),
        ("DROP TABLE users", False),
        ("INSERT INTO users VALUES (1)", False),
        ("UPDATE users SET name='x'", False),
        ("SELECT id FROM users WHERE id=1", True),
        ("SELECT * FROM data.public", True),
        ("SELECT", False),
        ("", False),
    ]
)
def test_query_sql_patterns(query, expected):
    validator = ScopeValidator()
    ok, _ = validator.validate("query_sql", {"query": query})
    assert ok is expected


@pytest.mark.parametrize(
    "recipient,expected",
    [
        ("user@company.com", True),
        ("user@internal.net", True),
        ("external@company.com", False),
        ("competitor@company.com", False),
        ("user@gmail.com", False),
        ("", False),
    ]
)
def test_send_email_recipients(recipient, expected):
    validator = ScopeValidator()
    ok, _ = validator.validate("send_email", {"to": recipient})
    assert ok is expected
