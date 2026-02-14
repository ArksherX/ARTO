#!/usr/bin/env python3
"""
Managed infrastructure health checks for status pages and automation.
"""

from __future__ import annotations

import os
import time
import shutil
from pathlib import Path
from typing import Dict, Any


def _ok(name: str, details: Dict[str, Any]) -> Dict[str, Any]:
    return {"component": name, "status": "ok", **details}


def _warn(name: str, details: Dict[str, Any]) -> Dict[str, Any]:
    return {"component": name, "status": "warning", **details}


def _fail(name: str, details: Dict[str, Any]) -> Dict[str, Any]:
    return {"component": name, "status": "fail", **details}


def check_postgres(dsn: str) -> Dict[str, Any]:
    if not dsn:
        return _warn("postgres", {"detail": "DSN not configured"})
    try:
        import psycopg2
        start = time.time()
        with psycopg2.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetchone()
        latency = round((time.time() - start) * 1000, 2)
        return _ok("postgres", {"latency_ms": latency})
    except Exception as exc:
        return _fail("postgres", {"detail": str(exc)})


def check_redis(url: str) -> Dict[str, Any]:
    if not url:
        return _warn("redis", {"detail": "REDIS url not configured"})
    try:
        import redis
        client = redis.Redis.from_url(url)
        start = time.time()
        client.ping()
        latency = round((time.time() - start) * 1000, 2)
        return _ok("redis", {"latency_ms": latency})
    except Exception as exc:
        return _fail("redis", {"detail": str(exc)})


def check_ledger(path: str) -> Dict[str, Any]:
    ledger_path = Path(path)
    if not ledger_path.exists():
        return _warn("ledger", {"detail": "Ledger file not found"})
    size = ledger_path.stat().st_size
    return _ok("ledger", {"size_bytes": size})


def check_disk(path: str) -> Dict[str, Any]:
    root = Path(path).resolve()
    usage = shutil.disk_usage(root)
    percent = round((usage.used / usage.total) * 100, 2)
    status = "ok" if percent < 85 else "warning"
    return {"component": "disk", "status": status, "used_percent": percent}


def collect_health(ledger_path: str, dsn: str, redis_url: str) -> Dict[str, Any]:
    return {
        "components": [
            check_postgres(dsn),
            check_redis(redis_url),
            check_ledger(ledger_path),
            check_disk(ledger_path),
        ]
    }
