from tessera.rate_limiter import RateLimiter


def test_rate_limiter_allows_within_limit():
    limiter = RateLimiter()
    key = "agent_test"
    for _ in range(3):
        assert limiter.allow(key, limit=5, window_seconds=60) is True

    # exceed limit
    for _ in range(3):
        limiter.allow(key, limit=5, window_seconds=60)
    assert limiter.allow(key, limit=5, window_seconds=60) is False


def test_rate_limiter_different_keys():
    limiter = RateLimiter()
    assert limiter.allow("agent_a", limit=1, window_seconds=60) is True
    assert limiter.allow("agent_a", limit=1, window_seconds=60) is False
    assert limiter.allow("agent_b", limit=1, window_seconds=60) is True
