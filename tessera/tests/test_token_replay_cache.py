from tessera.token_replay_cache import TokenReplayCache


def test_token_replay_cache():
    cache = TokenReplayCache()
    assert cache.check_and_store("nonce1", ttl_seconds=60) is True
    assert cache.check_and_store("nonce1", ttl_seconds=60) is False
