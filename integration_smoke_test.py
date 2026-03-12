#!/usr/bin/env python3
"""
Integration smoke test (opt-in)
- Verifies Tessera, Vestigia, VerityFlux APIs are reachable
- Does NOT mutate production data
"""

import os
import sys
import time
import json
import urllib.request
import urllib.error

TESSERA_API = os.getenv("TESSERA_API", "http://localhost:8001")
VESTIGIA_API = os.getenv("VESTIGIA_API", "http://localhost:8002")
VERITYFLUX_API = os.getenv("VERITYFLUX_API", "http://localhost:8003")
VESTIGIA_API_KEY = os.getenv("VESTIGIA_API_KEY")


def http_get(url, headers=None, timeout=3):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.getcode(), resp.read().decode("utf-8")


def check(name, url, headers=None, allow_statuses=None):
    try:
        code, body = http_get(url, headers=headers)
        print(f"✅ {name} OK ({code})")
        return True
    except urllib.error.HTTPError as exc:
        if allow_statuses and exc.code in allow_statuses:
            print(f"✅ {name} OK (auth required: {exc.code})")
            return True
        print(f"❌ {name} FAILED: {exc}")
        return False
    except Exception as exc:
        print(f"❌ {name} FAILED: {exc}")
        return False


def main():
    print("=" * 70)
    print("🔍 Integration Smoke Test")
    print("=" * 70)

    ok = True

    ok &= check("Tessera API /health", f"{TESSERA_API}/health")
    ok &= check("Tessera API /docs", f"{TESSERA_API}/docs", allow_statuses={401, 403})

    vestigia_headers = {}
    if VESTIGIA_API_KEY:
        vestigia_headers["Authorization"] = f"Bearer {VESTIGIA_API_KEY}"

    ok &= check("Vestigia API /health", f"{VESTIGIA_API}/health")
    ok &= check("Vestigia API /status", f"{VESTIGIA_API}/status", headers=vestigia_headers)

    ok &= check("VerityFlux API /docs", f"{VERITYFLUX_API}/docs", allow_statuses={401, 403})

    print("=" * 70)
    if ok:
        print("✅ Smoke test PASSED")
        return 0
    print("⚠️  Smoke test FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
