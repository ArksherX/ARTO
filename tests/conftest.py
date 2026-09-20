from __future__ import annotations

import pytest

from tests.helpers import SuiteHarness


@pytest.fixture(scope='session')
def suite() -> SuiteHarness:
    harness = SuiteHarness()
    harness.stop_suite()
    harness.launch_suite()
    yield harness
    harness.stop_suite()


# =============================================================================
# Opt-in gating for tests that need a live service
# =============================================================================
#
# Pattern adopted from CAGE. Tests marked `live` are skipped unless --run-live
# is passed, so a test that needs real Redis or a running API can live in the
# suite without making the default run depend on external state.
#
# Deliberately narrower than CAGE's version: their equivalent gate also
# requires a reachable backend and Langfuse for every integration test, which
# causes unrelated tests to skip for reasons that have nothing to do with what
# they cover. Gate on the marker only.

def pytest_addoption(parser):
    parser.addoption(
        "--run-live",
        action="store_true",
        default=False,
        help="Run tests marked `live`, which require a live service (Redis, a running API).",
    )


def pytest_collection_modifyitems(config, items):
    if config.getoption("--run-live"):
        return
    skip_live = pytest.mark.skip(
        reason="needs a live service — pass --run-live to enable"
    )
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip_live)
