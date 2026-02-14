#!/usr/bin/env python3
"""
Vestigia Phase 2 - Resilient SIEM Forwarder

Production-grade event forwarding to SIEM platforms (Splunk, Elasticsearch,
Datadog, Syslog) with resilience patterns:

* SQLite-backed persistent queue for durability across restarts
* Circuit breaker (5 failures / 60 s -> 30 s open -> half-open)
* Exponential backoff retry (1 s, 2 s, 4 s, 8 s ... max 60 s, max 5 retries)
* Token-bucket rate limiter (configurable, default 1000 events/s)
* Dead-letter queue for permanently failed events
* Background worker thread for async processing
"""

import json
import logging
import os
import queue
import socket
import sqlite3
import struct
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, UTC, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("vestigia.siem_forwarder")

# ---------------------------------------------------------------------------
# Optional HTTP client -- prefer httpx, fall back to urllib
# ---------------------------------------------------------------------------

_HTTPX_AVAILABLE = False
_REQUESTS_AVAILABLE = False

try:
    import httpx

    _HTTPX_AVAILABLE = True
except ImportError:
    pass

if not _HTTPX_AVAILABLE:
    try:
        import requests as _requests_mod

        _REQUESTS_AVAILABLE = True
    except ImportError:
        pass


def _http_post(
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    json_body: Optional[Any] = None,
    data: Optional[str] = None,
    timeout: float = 10.0,
) -> int:
    """
    POST helper that works with httpx, requests, or falls back to urllib.

    Returns the HTTP status code (or raises on transport error).
    """
    hdrs = headers or {}

    if _HTTPX_AVAILABLE:
        with httpx.Client(timeout=timeout) as client:
            if json_body is not None:
                resp = client.post(url, headers=hdrs, json=json_body)
            else:
                resp = client.post(url, headers=hdrs, content=data)
            return resp.status_code

    if _REQUESTS_AVAILABLE:
        if json_body is not None:
            resp = _requests_mod.post(url, headers=hdrs, json=json_body, timeout=timeout)
        else:
            resp = _requests_mod.post(url, headers=hdrs, data=data, timeout=timeout)
        return resp.status_code

    # Fallback: urllib
    import urllib.request
    import urllib.error

    body_bytes: bytes
    if json_body is not None:
        body_bytes = json.dumps(json_body).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    elif data is not None:
        body_bytes = data.encode("utf-8") if isinstance(data, str) else data
    else:
        body_bytes = b""

    req = urllib.request.Request(url, data=body_bytes, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code


# ---------------------------------------------------------------------------
# Enums / data
# ---------------------------------------------------------------------------


class TargetType(str, Enum):
    SPLUNK = "splunk"
    ELASTICSEARCH = "elasticsearch"
    DATADOG = "datadog"
    SYSLOG = "syslog"


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class SIEMTarget:
    """Describes a single SIEM forwarding target."""

    type: str
    url: str = ""
    token: str = ""
    index: str = ""
    name: str = ""
    # Syslog-specific
    host: str = "127.0.0.1"
    port: int = 514
    protocol: str = "udp"  # udp | tcp

    def __post_init__(self) -> None:
        if not self.name:
            self.name = f"{self.type}_{self.url or self.host}"


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------


class CircuitBreaker:
    """
    Simple circuit breaker.

    * **Closed** -- requests pass through normally.
    * **Open** -- after ``failure_threshold`` failures in ``window`` seconds,
      the circuit opens for ``recovery_timeout`` seconds.
    * **Half-open** -- after recovery timeout, one probe request is allowed.
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        window: float = 60.0,
        recovery_timeout: float = 30.0,
    ) -> None:
        self.failure_threshold = failure_threshold
        self.window = window
        self.recovery_timeout = recovery_timeout

        self._state = CircuitState.CLOSED
        self._failures: List[float] = []
        self._opened_at: float = 0.0
        self._lock = threading.Lock()

    @property
    def state(self) -> CircuitState:
        with self._lock:
            if self._state == CircuitState.OPEN:
                if time.time() - self._opened_at >= self.recovery_timeout:
                    self._state = CircuitState.HALF_OPEN
            return self._state

    def allow_request(self) -> bool:
        s = self.state
        if s == CircuitState.CLOSED:
            return True
        if s == CircuitState.HALF_OPEN:
            return True  # probe
        return False

    def record_success(self) -> None:
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.CLOSED
            self._failures.clear()

    def record_failure(self) -> None:
        with self._lock:
            now = time.time()
            self._failures = [t for t in self._failures if now - t < self.window]
            self._failures.append(now)

            if len(self._failures) >= self.failure_threshold:
                self._state = CircuitState.OPEN
                self._opened_at = now
                logger.warning(
                    "Circuit breaker OPEN after %d failures in %.0f s.",
                    len(self._failures),
                    self.window,
                )


# ---------------------------------------------------------------------------
# Token-bucket rate limiter
# ---------------------------------------------------------------------------


class TokenBucketRateLimiter:
    """
    Token-bucket rate limiter.

    Args:
        rate: Tokens added per second (events/sec).
        burst: Maximum bucket capacity.
    """

    def __init__(self, rate: float = 1000.0, burst: Optional[int] = None) -> None:
        self.rate = rate
        self.burst = burst or int(rate * 2)
        self._tokens: float = float(self.burst)
        self._last_refill: float = time.time()
        self._lock = threading.Lock()

    def acquire(self) -> bool:
        """Try to consume one token. Returns True if allowed."""
        with self._lock:
            now = time.time()
            elapsed = now - self._last_refill
            self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
            self._last_refill = now

            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False


# ---------------------------------------------------------------------------
# Persistent queue (SQLite)
# ---------------------------------------------------------------------------


class PersistentQueue:
    """
    SQLite-backed durable event queue with DLQ support.

    Tables:
      * ``event_queue`` -- pending events
      * ``dead_letter_queue`` -- events that exhausted retries
    """

    def __init__(self, db_path: str = "data/siem_queue.db") -> None:
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path, timeout=10)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA busy_timeout=5000")
        return self._local.conn

    def _init_db(self) -> None:
        conn = self._get_conn()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS event_queue (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id    TEXT NOT NULL,
                target_name TEXT NOT NULL,
                payload     TEXT NOT NULL,
                retries     INTEGER DEFAULT 0,
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS dead_letter_queue (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id    TEXT NOT NULL,
                target_name TEXT NOT NULL,
                payload     TEXT NOT NULL,
                retries     INTEGER DEFAULT 0,
                error       TEXT,
                created_at  TEXT NOT NULL,
                moved_at    TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_eq_target ON event_queue(target_name);
            CREATE INDEX IF NOT EXISTS idx_dlq_target ON dead_letter_queue(target_name);
            """
        )
        conn.commit()

    # -- Queue operations --

    def enqueue(self, event_id: str, target_name: str, payload: str) -> None:
        now = datetime.now(UTC).isoformat()
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO event_queue (event_id, target_name, payload, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (event_id, target_name, payload, now, now),
        )
        conn.commit()

    def dequeue(self, target_name: Optional[str] = None, limit: int = 100) -> List[Dict]:
        conn = self._get_conn()
        if target_name:
            rows = conn.execute(
                "SELECT id, event_id, target_name, payload, retries FROM event_queue "
                "WHERE target_name = ? ORDER BY id ASC LIMIT ?",
                (target_name, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, event_id, target_name, payload, retries FROM event_queue "
                "ORDER BY id ASC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {
                "id": r[0],
                "event_id": r[1],
                "target_name": r[2],
                "payload": r[3],
                "retries": r[4],
            }
            for r in rows
        ]

    def remove(self, row_id: int) -> None:
        conn = self._get_conn()
        conn.execute("DELETE FROM event_queue WHERE id = ?", (row_id,))
        conn.commit()

    def increment_retry(self, row_id: int) -> None:
        now = datetime.now(UTC).isoformat()
        conn = self._get_conn()
        conn.execute(
            "UPDATE event_queue SET retries = retries + 1, updated_at = ? WHERE id = ?",
            (now, row_id),
        )
        conn.commit()

    def move_to_dlq(self, row_id: int, error: str) -> None:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT event_id, target_name, payload, retries, created_at FROM event_queue WHERE id = ?",
            (row_id,),
        ).fetchone()
        if row:
            now = datetime.now(UTC).isoformat()
            conn.execute(
                "INSERT INTO dead_letter_queue "
                "(event_id, target_name, payload, retries, error, created_at, moved_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (row[0], row[1], row[2], row[3], error, row[4], now),
            )
            conn.execute("DELETE FROM event_queue WHERE id = ?", (row_id,))
            conn.commit()

    # -- Stats --

    def queue_size(self) -> int:
        conn = self._get_conn()
        return conn.execute("SELECT COUNT(*) FROM event_queue").fetchone()[0]

    def dlq_size(self) -> int:
        conn = self._get_conn()
        return conn.execute("SELECT COUNT(*) FROM dead_letter_queue").fetchone()[0]


# ---------------------------------------------------------------------------
# Main forwarder
# ---------------------------------------------------------------------------


class ResilientSIEMForwarder:
    """
    Resilient SIEM forwarding engine.

    Args:
        targets: List of target dicts, each with keys ``type``, ``url``,
                 ``token``, ``index`` (and optionally ``host``/``port`` for
                 syslog).
        db_path: Path for the SQLite persistent queue.
        rate_limit: Max events per second (token bucket).
        max_retries: Maximum retry attempts before moving to DLQ.
        worker_interval: Seconds between background queue drain cycles.
    """

    def __init__(
        self,
        targets: List[Dict[str, Any]],
        db_path: str = "data/siem_queue.db",
        rate_limit: float = 1000.0,
        max_retries: int = 5,
        worker_interval: float = 1.0,
    ) -> None:
        self.targets: List[SIEMTarget] = []
        for t in targets:
            self.targets.append(SIEMTarget(**t))

        self.max_retries = max_retries
        self.worker_interval = worker_interval

        # Persistent queue
        self._queue = PersistentQueue(db_path)

        # Rate limiter
        self._rate_limiter = TokenBucketRateLimiter(rate=rate_limit)

        # Per-target circuit breakers
        self._breakers: Dict[str, CircuitBreaker] = {
            t.name: CircuitBreaker() for t in self.targets
        }

        # Stats
        self._stats_lock = threading.Lock()
        self._forwarded: int = 0
        self._failed: int = 0

        # Background worker
        self._running = False
        self._worker_thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def forward_event(self, event: Dict[str, Any]) -> str:
        """
        Queue an event for forwarding to all configured targets.

        Returns:
            The generated event ID.
        """
        event_id = event.get("event_id", str(uuid.uuid4()))
        payload = json.dumps(event, default=str)

        for target in self.targets:
            self._queue.enqueue(event_id, target.name, payload)

        logger.debug("Event %s queued for %d targets.", event_id, len(self.targets))
        return event_id

    def start(self) -> None:
        """Start the background forwarding worker thread."""
        if self._running:
            return
        self._running = True
        self._worker_thread = threading.Thread(
            target=self._worker_loop, name="siem-forwarder", daemon=True
        )
        self._worker_thread.start()
        logger.info("SIEM forwarder worker started.")

    def stop(self, timeout: float = 10.0) -> None:
        """Stop the background worker and wait for it to finish."""
        self._running = False
        if self._worker_thread is not None:
            self._worker_thread.join(timeout=timeout)
            self._worker_thread = None
        logger.info("SIEM forwarder worker stopped.")

    def get_stats(self) -> Dict[str, Any]:
        """Return forwarding statistics."""
        with self._stats_lock:
            return {
                "forwarded": self._forwarded,
                "failed": self._failed,
                "queued": self._queue.queue_size(),
                "dlq": self._queue.dlq_size(),
                "targets": len(self.targets),
                "circuit_states": {
                    name: cb.state.value for name, cb in self._breakers.items()
                },
            }

    # ------------------------------------------------------------------
    # Background worker
    # ------------------------------------------------------------------

    def _worker_loop(self) -> None:
        """Continuously drain the queue."""
        while self._running:
            try:
                self._drain_queue()
            except Exception as exc:
                logger.error("Worker loop error: %s", exc)
            time.sleep(self.worker_interval)

    def _drain_queue(self) -> None:
        """Process pending events from the queue."""
        items = self._queue.dequeue(limit=200)
        if not items:
            return

        for item in items:
            if not self._running:
                break

            target_name = item["target_name"]
            target = self._find_target(target_name)
            if target is None:
                self._queue.move_to_dlq(item["id"], f"Unknown target: {target_name}")
                continue

            breaker = self._breakers.get(target_name)
            if breaker and not breaker.allow_request():
                logger.debug("Circuit open for %s, skipping.", target_name)
                continue

            if not self._rate_limiter.acquire():
                # Rate limit hit -- leave in queue for next cycle
                continue

            event = json.loads(item["payload"])
            success, error = self._forward_to_target(event, target)

            if success:
                self._queue.remove(item["id"])
                if breaker:
                    breaker.record_success()
                with self._stats_lock:
                    self._forwarded += 1
            else:
                retries = item["retries"]
                if retries + 1 >= self.max_retries:
                    self._queue.move_to_dlq(
                        item["id"], error or "Max retries exceeded"
                    )
                    if breaker:
                        breaker.record_failure()
                    with self._stats_lock:
                        self._failed += 1
                    logger.warning(
                        "Event %s moved to DLQ for target %s: %s",
                        item["event_id"],
                        target_name,
                        error,
                    )
                else:
                    self._queue.increment_retry(item["id"])
                    if breaker:
                        breaker.record_failure()
                    # Exponential backoff sleep
                    backoff = min(60.0, (2 ** retries) * 1.0)
                    time.sleep(backoff)

    def _find_target(self, name: str) -> Optional[SIEMTarget]:
        for t in self.targets:
            if t.name == name:
                return t
        return None

    # ------------------------------------------------------------------
    # Target-specific formatters / senders
    # ------------------------------------------------------------------

    def _forward_to_target(
        self, event: Dict[str, Any], target: SIEMTarget
    ) -> tuple:
        """Route event to the appropriate target handler. Returns (success, error_msg)."""
        try:
            ttype = target.type.lower()
            if ttype == TargetType.SPLUNK:
                return self._forward_to_splunk(event, target)
            elif ttype == TargetType.ELASTICSEARCH:
                return self._forward_to_elasticsearch(event, target)
            elif ttype == TargetType.DATADOG:
                return self._forward_to_datadog(event, target)
            elif ttype == TargetType.SYSLOG:
                return self._forward_to_syslog(event, target)
            else:
                return False, f"Unsupported target type: {ttype}"
        except Exception as exc:
            return False, str(exc)

    def _forward_to_splunk(
        self, event: Dict[str, Any], target: SIEMTarget
    ) -> tuple:
        """
        Format and send event to Splunk HEC (HTTP Event Collector).

        Payload format::

            {
                "event": { ... },
                "sourcetype": "vestigia",
                "index": "<configured index>",
                "time": <epoch>
            }
        """
        hec_payload = {
            "event": event,
            "sourcetype": "vestigia",
            "source": "vestigia_forwarder",
            "host": socket.gethostname(),
        }
        if target.index:
            hec_payload["index"] = target.index

        # Epoch time
        ts = event.get("timestamp")
        if ts:
            try:
                dt = datetime.fromisoformat(str(ts))
                hec_payload["time"] = dt.timestamp()
            except (ValueError, TypeError):
                pass

        headers = {
            "Authorization": f"Splunk {target.token}",
            "Content-Type": "application/json",
        }

        url = target.url.rstrip("/") + "/services/collector/event"
        status = _http_post(url, headers=headers, json_body=hec_payload)

        if 200 <= status < 300:
            return True, None
        return False, f"Splunk HEC returned {status}"

    def _forward_to_elasticsearch(
        self, event: Dict[str, Any], target: SIEMTarget
    ) -> tuple:
        """
        Format and send event to Elasticsearch using the Bulk API
        with Elastic Common Schema (ECS) fields.
        """
        index_name = target.index or "vestigia-events"
        doc_id = event.get("event_id", str(uuid.uuid4()))

        # Map to ECS
        ecs_doc = {
            "@timestamp": event.get("timestamp", datetime.now(UTC).isoformat()),
            "event.kind": "event",
            "event.category": ["process"],
            "event.action": event.get("action_type", "unknown"),
            "event.outcome": event.get("status", "unknown").lower(),
            "agent.name": "vestigia",
            "agent.type": "audit",
            "host.hostname": socket.gethostname(),
            "user.name": event.get("actor_id", "unknown"),
            "message": json.dumps(event.get("evidence", {}), default=str),
            "labels": {"vestigia.event_id": doc_id},
            "vestigia": event,
        }

        # Bulk API format: action line + document line
        action_line = json.dumps({"index": {"_index": index_name, "_id": doc_id}})
        doc_line = json.dumps(ecs_doc, default=str)
        body = f"{action_line}\n{doc_line}\n"

        headers: Dict[str, str] = {"Content-Type": "application/x-ndjson"}
        if target.token:
            headers["Authorization"] = f"ApiKey {target.token}"

        url = target.url.rstrip("/") + "/_bulk"
        status = _http_post(url, headers=headers, data=body)

        if 200 <= status < 300:
            return True, None
        return False, f"Elasticsearch returned {status}"

    def _forward_to_datadog(
        self, event: Dict[str, Any], target: SIEMTarget
    ) -> tuple:
        """
        Format and send event to Datadog Logs API.
        """
        dd_payload = {
            "ddsource": "vestigia",
            "ddtags": f"env:production,service:vestigia",
            "hostname": socket.gethostname(),
            "service": "vestigia",
            "message": json.dumps(event, default=str),
            "status": event.get("status", "info").lower(),
        }

        ts = event.get("timestamp")
        if ts:
            try:
                dt = datetime.fromisoformat(str(ts))
                dd_payload["date"] = int(dt.timestamp() * 1000)
            except (ValueError, TypeError):
                pass

        headers = {
            "DD-API-KEY": target.token,
            "Content-Type": "application/json",
        }

        url = target.url or "https://http-intake.logs.datadoghq.com/api/v2/logs"
        status = _http_post(url, headers=headers, json_body=[dd_payload])

        if 200 <= status < 300:
            return True, None
        return False, f"Datadog returned {status}"

    def _forward_to_syslog(
        self, event: Dict[str, Any], target: SIEMTarget
    ) -> tuple:
        """
        Format event as CEF (Common Event Format) and send via syslog
        (RFC 5424).
        """
        severity = self._map_severity_to_syslog(event.get("status", "INFO"))
        action = event.get("action_type", "unknown")
        actor = event.get("actor_id", "unknown")
        event_id = event.get("event_id", "0")

        # CEF: Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extensions
        cef = (
            f"CEF:0|Vestigia|AuditLedger|2.0|{action}|"
            f"{action}|{severity}|"
            f"src={actor} "
            f"msg={json.dumps(event.get('evidence', {}), default=str)[:512]} "
            f"externalId={event_id} "
            f"rt={event.get('timestamp', '')}"
        )

        # RFC 5424 syslog header
        pri = 14 * 8 + severity  # facility=log_audit(14), severity
        timestamp = event.get("timestamp", datetime.now(UTC).isoformat())
        hostname = socket.gethostname()
        syslog_msg = f"<{pri}>1 {timestamp} {hostname} vestigia - - - {cef}"

        try:
            if target.protocol.lower() == "tcp":
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(5.0)
                    s.connect((target.host, target.port))
                    # RFC 5425: message length prefix for TCP
                    encoded = syslog_msg.encode("utf-8")
                    s.sendall(f"{len(encoded)} ".encode("utf-8") + encoded)
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.sendto(
                        syslog_msg.encode("utf-8")[:65507],
                        (target.host, target.port),
                    )
            return True, None
        except Exception as exc:
            return False, f"Syslog send failed: {exc}"

    @staticmethod
    def _map_severity_to_syslog(status: str) -> int:
        """Map Vestigia status to syslog severity (0=emergency ... 7=debug)."""
        mapping = {
            "CRITICAL": 2,  # Critical
            "BLOCKED": 3,   # Error
            "WARNING": 4,   # Warning
            "SUCCESS": 6,   # Informational
            "INFO": 6,      # Informational
        }
        return mapping.get(status.upper(), 6)

    # ------------------------------------------------------------------
    # DLQ management
    # ------------------------------------------------------------------

    def replay_dlq(self, target_name: Optional[str] = None) -> int:
        """
        Move dead-letter events back to the main queue for reprocessing.

        Returns:
            Number of events replayed.
        """
        conn = self._queue._get_conn()
        if target_name:
            rows = conn.execute(
                "SELECT id, event_id, target_name, payload FROM dead_letter_queue WHERE target_name = ?",
                (target_name,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, event_id, target_name, payload FROM dead_letter_queue"
            ).fetchall()

        count = 0
        for row in rows:
            self._queue.enqueue(row[1], row[2], row[3])
            conn.execute("DELETE FROM dead_letter_queue WHERE id = ?", (row[0],))
            count += 1

        conn.commit()
        logger.info("Replayed %d DLQ events.", count)
        return count


# ---------------------------------------------------------------------------
# Self-test / demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import tempfile

    logging.basicConfig(level=logging.DEBUG)

    print("=" * 70)
    print("  Vestigia Resilient SIEM Forwarder - Self Test")
    print("=" * 70)

    # Use a temporary database
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_queue.db")

        targets = [
            {
                "type": "syslog",
                "host": "127.0.0.1",
                "port": 65514,
                "protocol": "udp",
                "name": "test_syslog",
            },
        ]

        forwarder = ResilientSIEMForwarder(
            targets=targets,
            db_path=db_path,
            rate_limit=100.0,
            max_retries=3,
        )

        # -- Queue some events --
        for i in range(5):
            eid = forwarder.forward_event(
                {
                    "event_id": f"test_{i:04d}",
                    "timestamp": datetime.now(UTC).isoformat(),
                    "actor_id": "test_agent",
                    "action_type": "TOOL_EXECUTION",
                    "status": "SUCCESS",
                    "evidence": {"summary": f"Test event {i}"},
                }
            )
            print(f"  Queued event: {eid}")

        stats = forwarder.get_stats()
        print(f"\nStats after queuing: {json.dumps(stats, indent=2)}")

        # -- Test circuit breaker --
        cb = CircuitBreaker(failure_threshold=3, window=10.0, recovery_timeout=2.0)
        assert cb.state == CircuitState.CLOSED
        for _ in range(3):
            cb.record_failure()
        assert cb.state == CircuitState.OPEN
        print(f"\nCircuit breaker state after 3 failures: {cb.state.value}")

        # -- Test rate limiter --
        rl = TokenBucketRateLimiter(rate=5.0, burst=5)
        acquired = sum(1 for _ in range(10) if rl.acquire())
        print(f"Rate limiter: acquired {acquired}/10 tokens (burst=5)")

        # -- Test persistent queue directly --
        pq = PersistentQueue(os.path.join(tmpdir, "pq_test.db"))
        pq.enqueue("e1", "target_a", '{"test": 1}')
        pq.enqueue("e2", "target_a", '{"test": 2}')
        assert pq.queue_size() == 2
        items = pq.dequeue(limit=10)
        assert len(items) == 2
        pq.move_to_dlq(items[0]["id"], "test error")
        assert pq.queue_size() == 1
        assert pq.dlq_size() == 1
        pq.remove(items[1]["id"])
        assert pq.queue_size() == 0
        print("Persistent queue: enqueue/dequeue/dlq -- OK")

        # -- Start/stop worker briefly --
        forwarder.start()
        time.sleep(0.5)
        forwarder.stop(timeout=3.0)

        final_stats = forwarder.get_stats()
        print(f"\nFinal stats: {json.dumps(final_stats, indent=2)}")

    print("\n[PASS] Resilient SIEM Forwarder self-test complete.")
