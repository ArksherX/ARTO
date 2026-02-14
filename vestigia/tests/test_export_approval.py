import os
from fastapi.testclient import TestClient

import api_server


def test_export_requires_two_approvers():
    os.environ["VESTIGIA_API_KEY"] = ""
    client = TestClient(api_server.app)
    resp = client.get("/events/export?limit=20000")
    assert resp.status_code == 403

    resp_ok = client.get(
        "/events/export?limit=20000",
        headers={"X-Approver-1": "a", "X-Approver-2": "b"}
    )
    assert resp_ok.status_code == 200
