#!/usr/bin/env python3
"""
Load-test harness for validating 10k agents/day throughput.
Runs concurrent token requests + validations against the Tessera API.
"""

import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
try:
    from prometheus_client import Counter, Gauge, start_http_server
except Exception:  # pragma: no cover
    Counter = Gauge = start_http_server = None



API_URL = os.getenv("TESSERA_API_URL", "http://localhost:8000").rstrip("/")
API_KEY = os.getenv("TESSERA_API_KEY", "tessera-demo-key-change-in-production")
AGENT_ID = os.getenv("TESSERA_TEST_AGENT", "mock_test")
TOOL = os.getenv("TESSERA_TEST_TOOL", "read_csv")
TOTAL_REQUESTS = int(os.getenv("TESSERA_TOTAL_REQUESTS", "1000"))
CONCURRENCY = int(os.getenv("TESSERA_CONCURRENCY", "50"))
USE_DPOP = os.getenv("TESSERA_USE_DPOP", "true").lower() in ("1", "true", "yes")

_DPOP_PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1()) if USE_DPOP else None


def _dpop_jwk():
    if not _DPOP_PRIVATE_KEY:
        return None
    pub = _DPOP_PRIVATE_KEY.public_key().public_numbers()
    x = pub.x.to_bytes((pub.x.bit_length() + 7) // 8, "big")
    y = pub.y.to_bytes((pub.y.bit_length() + 7) // 8, "big")
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": jwt.utils.base64url_encode(x).decode("utf-8"),
        "y": jwt.utils.base64url_encode(y).decode("utf-8")
    }


def _dpop_proof(method: str, url: str) -> str:
    if not _DPOP_PRIVATE_KEY:
        return ""
    payload = {"htu": url, "htm": method.upper(), "iat": int(time.time()), "jti": uuid.uuid4().hex}
    headers = {"typ": "dpop+jwt", "alg": "ES256", "jwk": _dpop_jwk()}
    return jwt.encode(payload, _DPOP_PRIVATE_KEY, algorithm="ES256", headers=headers)


def _request_token(session_id: str) -> str:
    public_key_pem = ""
    if _DPOP_PRIVATE_KEY:
        public_key_pem = _DPOP_PRIVATE_KEY.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")
    payload = {
        "agent_id": AGENT_ID,
        "tool": TOOL,
        "duration_minutes": 60,
        "session_id": session_id,
        "memory_state": f"mem:{session_id}",
        "client_public_key": public_key_pem
    }
    r = requests.post(
        f"{API_URL}/tokens/request",
        headers={"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"},
        json=payload,
        timeout=10
    )
    r.raise_for_status()
    return r.json()["token"]


def _validate_token(token: str):
    payload = {"token": token, "tool": TOOL}
    headers = {"Content-Type": "application/json"}
    if USE_DPOP:
        headers["DPoP"] = _dpop_proof("POST", f"{API_URL}/tokens/validate")
    r = requests.post(
        f"{API_URL}/tokens/validate",
        headers=headers,
        json=payload,
        timeout=10
    )
    r.raise_for_status()
    return r.json()


def _worker():
    session_id = f"load_{uuid.uuid4().hex}"
    token = _request_token(session_id)
    _validate_token(token)
    return True


def main():
    if start_http_server:
        start_http_server(int(os.getenv("LOAD_TEST_METRICS_PORT", "8009")))
        load_requests = Counter("tessera_load_test_requests_total", "Total load test requests")
        load_failures = Counter("tessera_load_test_failures_total", "Total load test failures")
        load_rps = Gauge("tessera_load_test_rps", "Load test requests per second")
        load_duration = Gauge("tessera_load_test_duration_seconds", "Load test duration seconds")
    else:
        load_requests = load_failures = load_rps = load_duration = None

    start = time.time()
    successes = 0
    failures = 0
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        futures = [executor.submit(_worker) for _ in range(TOTAL_REQUESTS)]
        for f in as_completed(futures):
            try:
                f.result()
                successes += 1
                if load_requests:
                    load_requests.inc()
            except Exception:
                failures += 1
                if load_failures:
                    load_failures.inc()
    elapsed = time.time() - start
    rps = successes / elapsed if elapsed > 0 else 0
    if load_rps:
        load_rps.set(rps)
    if load_duration:
        load_duration.set(elapsed)

    print("Load Test Summary")
    print("=================")
    print(f"Total requests: {TOTAL_REQUESTS}")
    print(f"Successes: {successes}")
    print(f"Failures: {failures}")
    print(f"Elapsed: {elapsed:.2f}s")
    print(f"Throughput: {rps:.2f} req/s")
    print(f"Estimated per day: {rps * 86400:.0f} req/day")


if __name__ == "__main__":
    main()
