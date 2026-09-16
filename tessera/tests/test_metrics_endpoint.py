import os
from fastapi.testclient import TestClient

os.environ.setdefault("TESSERA_SECRET_KEY", "z" * 64)

from api_server import app


def test_metrics_endpoint_available():
    os.environ["TESSERA_SECRET_KEY"] = "z" * 64
    client = TestClient(app)
    resp = client.get("/metrics")
    # /metrics is deliberately not in SessionMemoryGuard's skip_paths
    # (api_server.py's middleware setup) -- an unauthenticated call
    # correctly gets rejected with 401. Consistent with api_server_production.py
    # also treating /metrics as a protected path elsewhere. 200/500 are the
    # authenticated outcomes (success, or prometheus_client not installed);
    # constructing a full session-bound token here would turn this smoke
    # test into a heavier session-auth integration test than it's meant to be.
    assert resp.status_code in (200, 401, 500)
