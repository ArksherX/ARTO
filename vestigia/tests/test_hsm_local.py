from core.hsm_client import LocalHSM


def test_local_hsm_sign_verify(tmp_path):
    key_path = tmp_path / "hsm.pem"
    hsm = LocalHSM(str(key_path))
    data = b"test"
    sig = hsm.sign(data)
    assert hsm.verify(data, sig) is True
    assert hsm.verify(b"bad", sig) is False
