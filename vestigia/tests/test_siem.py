"""Tests for core/resilient_siem_forwarder.py — queue, circuit breaker, DLQ."""

import os
import json
import time
import tempfile

import pytest

from core.resilient_siem_forwarder import (
    CircuitBreaker,
    CircuitState,
    TokenBucketRateLimiter,
    PersistentQueue,
    ResilientSIEMForwarder,
    SIEMTarget,
    TargetType,
)


@pytest.fixture
def tmp_db(tmp_path):
    return str(tmp_path / "test_queue.db")


@pytest.fixture
def pqueue(tmp_db):
    return PersistentQueue(db_path=tmp_db)


@pytest.fixture
def forwarder(tmp_db):
    targets = [
        {"type": "syslog", "host": "127.0.0.1", "port": 65514, "protocol": "udp", "name": "test_syslog"},
    ]
    return ResilientSIEMForwarder(
        targets=targets,
        db_path=tmp_db,
        rate_limit=100.0,
        max_retries=3,
    )


# ------------------------------------------------------------------
# Circuit breaker
# ------------------------------------------------------------------


class TestCircuitBreaker:
    def test_starts_closed(self):
        cb = CircuitBreaker()
        assert cb.state == CircuitState.CLOSED

    def test_opens_after_threshold(self):
        cb = CircuitBreaker(failure_threshold=3, window=60.0)
        for _ in range(3):
            cb.record_failure()
        assert cb.state == CircuitState.OPEN

    def test_allows_when_closed(self):
        cb = CircuitBreaker()
        assert cb.allow_request() is True

    def test_blocks_when_open(self):
        cb = CircuitBreaker(failure_threshold=2, window=60.0, recovery_timeout=30.0)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert cb.allow_request() is False

    def test_half_open_after_timeout(self):
        cb = CircuitBreaker(failure_threshold=2, window=60.0, recovery_timeout=0.01)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        time.sleep(0.02)
        assert cb.state == CircuitState.HALF_OPEN
        assert cb.allow_request() is True

    def test_closes_on_success_in_half_open(self):
        cb = CircuitBreaker(failure_threshold=2, window=60.0, recovery_timeout=0.01)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.02)
        assert cb.state == CircuitState.HALF_OPEN
        cb.record_success()
        assert cb.state == CircuitState.CLOSED

    def test_failures_expire_outside_window(self):
        cb = CircuitBreaker(failure_threshold=3, window=0.01)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.02)
        cb.record_failure()
        # First 2 failures expired; only 1 in window → still closed
        assert cb.state == CircuitState.CLOSED


# ------------------------------------------------------------------
# Rate limiter
# ------------------------------------------------------------------


class TestTokenBucketRateLimiter:
    def test_burst_tokens(self):
        rl = TokenBucketRateLimiter(rate=10.0, burst=5)
        acquired = sum(1 for _ in range(10) if rl.acquire())
        assert acquired == 5

    def test_refill(self):
        rl = TokenBucketRateLimiter(rate=1000.0, burst=1)
        assert rl.acquire() is True
        assert rl.acquire() is False
        time.sleep(0.01)
        assert rl.acquire() is True


# ------------------------------------------------------------------
# Persistent queue
# ------------------------------------------------------------------


class TestPersistentQueue:
    def test_enqueue_dequeue(self, pqueue):
        pqueue.enqueue("e1", "target_a", '{"x": 1}')
        pqueue.enqueue("e2", "target_a", '{"x": 2}')
        items = pqueue.dequeue(limit=10)
        assert len(items) == 2
        assert items[0]["event_id"] == "e1"

    def test_queue_size(self, pqueue):
        assert pqueue.queue_size() == 0
        pqueue.enqueue("e1", "t", "{}")
        assert pqueue.queue_size() == 1

    def test_remove(self, pqueue):
        pqueue.enqueue("e1", "t", "{}")
        items = pqueue.dequeue()
        pqueue.remove(items[0]["id"])
        assert pqueue.queue_size() == 0

    def test_move_to_dlq(self, pqueue):
        pqueue.enqueue("e1", "t", '{"data": 1}')
        items = pqueue.dequeue()
        pqueue.move_to_dlq(items[0]["id"], "test error")
        assert pqueue.queue_size() == 0
        assert pqueue.dlq_size() == 1

    def test_increment_retry(self, pqueue):
        pqueue.enqueue("e1", "t", "{}")
        items = pqueue.dequeue()
        pqueue.increment_retry(items[0]["id"])
        updated = pqueue.dequeue()
        assert updated[0]["retries"] == 1

    def test_filter_by_target(self, pqueue):
        pqueue.enqueue("e1", "alpha", "{}")
        pqueue.enqueue("e2", "beta", "{}")
        alpha_items = pqueue.dequeue(target_name="alpha")
        assert len(alpha_items) == 1
        assert alpha_items[0]["target_name"] == "alpha"


# ------------------------------------------------------------------
# Forwarder
# ------------------------------------------------------------------


class TestResilientSIEMForwarder:
    def test_forward_event_queues(self, forwarder):
        eid = forwarder.forward_event({
            "event_id": "fwd-1",
            "actor_id": "agent",
            "action_type": "HEARTBEAT",
            "status": "SUCCESS",
        })
        assert eid == "fwd-1"
        stats = forwarder.get_stats()
        assert stats["queued"] >= 1

    def test_stats_structure(self, forwarder):
        stats = forwarder.get_stats()
        assert "forwarded" in stats
        assert "failed" in stats
        assert "queued" in stats
        assert "dlq" in stats
        assert "targets" in stats
        assert "circuit_states" in stats

    def test_start_stop(self, forwarder):
        forwarder.start()
        assert forwarder._running is True
        forwarder.stop(timeout=2.0)
        assert forwarder._running is False

    def test_replay_dlq(self, forwarder):
        # Manually push to DLQ
        forwarder._queue.enqueue("dlq-1", "test_syslog", '{"test": true}')
        items = forwarder._queue.dequeue()
        forwarder._queue.move_to_dlq(items[0]["id"], "forced error")
        assert forwarder._queue.dlq_size() == 1

        replayed = forwarder.replay_dlq()
        assert replayed == 1
        assert forwarder._queue.dlq_size() == 0
        assert forwarder._queue.queue_size() >= 1


class TestSIEMTarget:
    def test_auto_name(self):
        t = SIEMTarget(type="splunk", url="https://splunk.local:8088")
        assert "splunk" in t.name

    def test_explicit_name(self):
        t = SIEMTarget(type="elasticsearch", url="http://es:9200", name="my-es")
        assert t.name == "my-es"


class TestSeverityMapping:
    def test_critical_maps_to_2(self):
        assert ResilientSIEMForwarder._map_severity_to_syslog("CRITICAL") == 2

    def test_blocked_maps_to_3(self):
        assert ResilientSIEMForwarder._map_severity_to_syslog("BLOCKED") == 3

    def test_success_maps_to_6(self):
        assert ResilientSIEMForwarder._map_severity_to_syslog("SUCCESS") == 6

    def test_unknown_maps_to_6(self):
        assert ResilientSIEMForwarder._map_severity_to_syslog("FOOBAR") == 6
