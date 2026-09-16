import os
from pathlib import Path

import pytest

# Ensure a valid default secret for tests
os.environ.setdefault("TESSERA_SECRET_KEY", "z" * 64)

# Deliberately NOT anchored to __file__. TesseraRegistry() and friends
# resolve their default paths relative to the process's current working
# directory at call time (e.g. "data/tessera_registry.json"), so this
# fixture must watch the exact same, cwd-relative locations the code under
# test actually writes to -- not a fixed location -- or it silently
# protects the wrong file when pytest is invoked from a different
# directory (confirmed: running from the monorepo root instead of
# tessera/ makes the tests write into <repo-root>/data/, which turned out
# to hold real, pre-existing demo registry entries -- agent_financial_bot_01,
# several qa-agent-* records -- from actual past suite runs).
_SHARED_REGISTRY_ARTIFACTS = [
    Path("data/tessera_registry.json"),
    Path("data/tessera_root_key.json"),
]


def _snapshot(paths):
    """Read back (path, original_bytes_or_None) for each path that exists."""
    return [(p, p.read_bytes()) if p.exists() else (p, None) for p in paths]


def _restore(snapshot):
    """
    Put each path back exactly how _snapshot found it: rewritten if it had
    content, removed if it didn't exist at all. Never a blind delete --
    if a path held real pre-existing data (as happened once, by accident,
    while verifying this fixture), that data must survive this fixture
    unconditionally.
    """
    for path, original in snapshot:
        if original is None:
            path.unlink(missing_ok=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(original)


@pytest.fixture(autouse=True)
def _isolated_tessera_registry():
    """
    TesseraRegistry() defaults to one shared, cwd-relative file path.
    Multiple test files register the same agent_id ("mock_test") against
    that one file, so state (and a persisted signing key) accumulates
    across tests and across repeated suite runs -- confirmed to eventually
    cause test_gatekeeper.py to fail with DENY_DEPENDENCY_RISK on an
    otherwise clean, passing suite, purely as an artifact of running the
    suite more than once in the same environment.

    Snapshots before the test and restores after, rather than deleting --
    if the path already held real content (a live deployment's actual
    registry, not a test fixture), this must leave it exactly as found,
    not destroy it.
    """
    before = _snapshot(_SHARED_REGISTRY_ARTIFACTS)
    for path, original in before:
        if original is None:
            path.unlink(missing_ok=True)  # start this test from a clean slate
    yield
    _restore(before)
