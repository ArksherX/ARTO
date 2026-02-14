#!/usr/bin/env python3
"""
Feature extraction utilities for anomaly detection.
Pure-Python, dependency-free feature set.
"""

from __future__ import annotations

import json
import hashlib
from datetime import datetime, UTC
from typing import Any, Dict, Tuple


STATUS_SCORE = {
    "INFO": 10,
    "SUCCESS": 20,
    "WARNING": 50,
    "BLOCKED": 70,
    "CRITICAL": 90,
}


def _stable_hash(value: str, buckets: int = 128) -> int:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return int(digest, 16) % buckets


def extract_features(event: Dict[str, Any]) -> Tuple[Dict[str, float], Dict[str, Any]]:
    """
    Extract numeric features and metadata from a Vestigia event dict.
    Returns (features, meta).
    """
    evidence = event.get("evidence", {}) or {}
    payload_size = len(json.dumps(evidence, sort_keys=True))

    timestamp = event.get("timestamp")
    if timestamp:
        try:
            event_time = datetime.fromisoformat(timestamp)
        except Exception:
            event_time = datetime.now(UTC)
    else:
        event_time = datetime.now(UTC)

    hour = event_time.hour
    off_hours = 1.0 if hour < 6 or hour > 22 else 0.0

    action = event.get("action_type", "UNKNOWN")
    action_bucket = float(_stable_hash(action, 64))

    status = str(event.get("status", "INFO")).upper()
    status_score = float(STATUS_SCORE.get(status, 10))

    features = {
        "payload_size": float(payload_size),
        "hour": float(hour),
        "off_hours": off_hours,
        "action_bucket": action_bucket,
        "status_score": status_score,
    }

    meta = {
        "event_time": event_time,
        "action": action,
        "status": status,
        "payload_size": payload_size,
    }

    return features, meta
