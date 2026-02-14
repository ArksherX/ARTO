from tessera.revocation import RevocationList


def test_revocation_list_revoke_and_check():
    rev = RevocationList(revocation_file="data/test_revoked_tokens.json")
    rev.revoke("jti_123")
    assert rev.is_revoked("jti_123") is True
