"""Fail-closed behaviour for TESSERA_SECRET_KEY.

Regression guard for a real defect: api_server.py injected DEV_FALLBACK_SECRET
into os.environ whenever its own narrow gate -- (MLRT_MODE|MODE)=prod *and*
SUITE_STRICT_MODE=true -- was not satisfied. Setting only the documented
TESSERA_ENV=production therefore left the fallback injected, and because
TokenGenerator then saw a key present, its own production check never fired.
The result was HS512 JWTs signed with a secret committed to a public
repository, with no error raised.

These tests pin both directions: production must refuse the public fallback,
and local development must keep working without configuration.
"""

import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tessera.registry import TesseraRegistry
from tessera.token_generator import TokenGenerator

PROD_MARKERS = [
    {"TESSERA_ENV": "production"},
    {"TESSERA_ENV": "prod"},
    {"MLRT_MODE": "prod"},
    {"MODE": "prod"},
    {"SUITE_STRICT_MODE": "true"},
]

_CLEARED = (
    "TESSERA_SECRET_KEY", "MLRT_MODE", "MODE", "SUITE_STRICT_MODE",
    "TESSERA_STRICT_SECRET_KEY", "TESSERA_ENV",
)


@pytest.fixture
def clean_env(monkeypatch, tmp_path):
    for name in _CLEARED:
        monkeypatch.delenv(name, raising=False)
    # PYTEST_CURRENT_TEST would substitute its own key and mask the behaviour.
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.setenv("TESSERA_ROOT_KEY_PATH", str(tmp_path / "root.json"))
    return tmp_path


def _generator(tmp_path):
    return TokenGenerator(TesseraRegistry(registry_path=str(tmp_path / "registry.json")))


@pytest.mark.parametrize("markers", PROD_MARKERS)
def test_production_refuses_the_public_dev_fallback(clean_env, monkeypatch, markers):
    """The exact defect: fallback pre-set in the environment under production."""
    for k, v in markers.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("TESSERA_SECRET_KEY", TokenGenerator.DEV_FALLBACK_SECRET)

    with pytest.raises(ValueError, match="development fallback"):
        _generator(clean_env)


@pytest.mark.parametrize("markers", PROD_MARKERS)
def test_production_refuses_missing_secret(clean_env, monkeypatch, markers):
    for k, v in markers.items():
        monkeypatch.setenv(k, v)

    with pytest.raises(ValueError, match="TESSERA_SECRET_KEY"):
        _generator(clean_env)


@pytest.mark.parametrize("markers", PROD_MARKERS)
def test_production_accepts_a_unique_secret(clean_env, monkeypatch, markers):
    """Fail-closed must not mean fail-always — a real key still works."""
    for k, v in markers.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("TESSERA_SECRET_KEY", "b" * 128)

    generator = _generator(clean_env)
    assert generator.secret_key != TokenGenerator._normalize_secret_key(
        TokenGenerator.DEV_FALLBACK_SECRET
    )


def test_development_still_works_without_configuration(clean_env):
    """No markers, no key: local dev must keep working rather than raising.

    The exact key is not asserted. pytest re-sets PYTEST_CURRENT_TEST for every
    test phase, so _load_secret_key() takes its in-test branch regardless of
    what the fixture clears; the property that matters here is that startup
    does not fail closed when no production marker is present.
    """
    generator = _generator(clean_env)
    assert generator.secret_key
    assert len(generator.secret_key) >= 64


def test_is_production_recognises_every_marker(clean_env, monkeypatch):
    assert TokenGenerator.is_production() is False
    for markers in PROD_MARKERS:
        for name in _CLEARED:
            monkeypatch.delenv(name, raising=False)
        for k, v in markers.items():
            monkeypatch.setenv(k, v)
        assert TokenGenerator.is_production() is True, f"not detected: {markers}"
