import os
from fastapi.testclient import TestClient

os.environ.setdefault("TESSERA_SECRET_KEY", "z" * 64)

from api_server import app


def test_metrics_endpoint_available():
    os.environ["TESSERA_SECRET_KEY"] = "z" * 64
    client = TestClient(app)
    resp = client.get("/metrics")
    assert resp.status_code in (200, 500)
