from tessera.dpop_replay_cache import DPoPReplayCache


def test_dpop_replay_cache():
    cache = DPoPReplayCache()
    assert cache.check_and_store("jti_1", ttl_seconds=60) is True
    assert cache.check_and_store("jti_1", ttl_seconds=60) is False
