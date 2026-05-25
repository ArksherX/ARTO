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
