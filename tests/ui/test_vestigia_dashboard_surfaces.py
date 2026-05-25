from __future__ import annotations

import pytest

pytest.importorskip('streamlit.testing.v1')
from streamlit.testing.v1 import AppTest


@pytest.mark.ui
def test_statistics_surface_exposes_customer_facing_tabs_and_metrics():
    app = AppTest.from_file('tests/ui_apps/vestigia_stats_app.py')
    app.run(timeout=60)
    tab_labels = [tab.label for tab in app.tabs]
    metric_labels = [metric.label for metric in app.metric]
    assert tab_labels == ['Overview', 'Governance Metrics', 'Identity Alignment', 'Recent Incidents']
    assert {'Total Events', 'Unique Actors', 'Action Types'}.issubset(metric_labels)
    assert {'Incidents', 'Intervention Success', 'Identity Confidence', 'Approval Provenance'}.issubset(metric_labels)


@pytest.mark.ui
def test_forensics_surface_exposes_incident_interop_and_threat_tabs():
    app = AppTest.from_file('tests/ui_apps/vestigia_forensics_app.py')
    app.run(timeout=60)
    tab_labels = [tab.label for tab in app.tabs]
    assert tab_labels == ['Incident View', 'Interoperability Report', 'Threat Cards']
