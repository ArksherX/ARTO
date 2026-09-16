import uuid

from tessera.rate_limiter import RateLimiter


def test_rate_limiter_allows_within_limit():
    # Same shape as the replay-cache tests: a hardcoded key against a
    # window-based (likely Redis-backed) limiter correctly stays rate-limited
    # if this test runs twice within window_seconds -- not a product bug.
    limiter = RateLimiter()
    key = f"agent_test_{uuid.uuid4()}"
    for _ in range(3):
        assert limiter.allow(key, limit=5, window_seconds=60) is True

    # exceed limit
    for _ in range(3):
        limiter.allow(key, limit=5, window_seconds=60)
    assert limiter.allow(key, limit=5, window_seconds=60) is False


def test_rate_limiter_different_keys():
    limiter = RateLimiter()
    suffix = uuid.uuid4()
    assert limiter.allow(f"agent_a_{suffix}", limit=1, window_seconds=60) is True
    assert limiter.allow(f"agent_a_{suffix}", limit=1, window_seconds=60) is False
    assert limiter.allow(f"agent_b_{suffix}", limit=1, window_seconds=60) is True
