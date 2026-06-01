from __future__ import annotations

import pytest

pytest.importorskip('streamlit.testing.v1')
from streamlit.testing.v1 import AppTest


@pytest.mark.ui
def test_statistics_surface_exposes_customer_facing_tabs_and_metrics():
    app = AppTest.from_file('tests/ui_apps/vestigia_stats_app.py')
    app.run(timeout=60)
    radio_options = list(app.radio[0].options)
    metric_labels = [metric.label for metric in app.metric]
    assert radio_options == ['Overview', 'Governance Metrics', 'Identity Alignment', 'Recent Incidents']
    assert {'Total Events', 'Unique Actors', 'Action Types'}.issubset(metric_labels)


@pytest.mark.ui
def test_forensics_surface_exposes_incident_interop_and_threat_tabs():
    app = AppTest.from_file('tests/ui_apps/vestigia_forensics_app.py')
    app.run(timeout=60)
    radio_options = list(app.radio[0].options)
    assert radio_options == ['Incident View', 'Interoperability Report', 'Threat Cards']
