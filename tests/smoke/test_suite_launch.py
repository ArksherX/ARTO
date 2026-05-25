from __future__ import annotations

import pytest


@pytest.mark.smoke
def test_suite_launches_and_serves_all_health_endpoints(suite):
    assert suite.get_json(f'{suite.tessera_url}/health').status == 200
    assert suite.get_json(f'{suite.vestigia_url}/health').status == 200
    assert suite.get_json(f'{suite.verityflux_url}/health').status == 200


@pytest.mark.smoke
def test_suite_dashboards_are_served(suite):
    assert suite.streamlit_health(8501) == 'ok'
    assert suite.streamlit_health(8502) == 'ok'
    assert suite.streamlit_health(8503) == 'ok'
    assert '<!DOCTYPE html>' in suite.streamlit_html(8502)
