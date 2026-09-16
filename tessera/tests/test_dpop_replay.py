import uuid

from tessera.dpop_replay_cache import DPoPReplayCache


def test_dpop_replay_cache():
    # A fresh, unique jti per run: the cache is Redis-backed with a real
    # TTL, so a hardcoded literal value would correctly (and confusingly)
    # start failing if this test is ever run twice within the TTL window --
    # not a product bug, just a non-hermetic test fixture.
    jti = f"jti_{uuid.uuid4()}"
    cache = DPoPReplayCache()
    assert cache.check_and_store(jti, ttl_seconds=60) is True
    assert cache.check_and_store(jti, ttl_seconds=60) is False
