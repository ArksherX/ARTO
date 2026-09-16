import uuid

from tessera.token_replay_cache import TokenReplayCache


def test_token_replay_cache():
    # Same reasoning as test_dpop_replay.py: a unique nonce per run avoids
    # a spurious failure if this test is run twice within its own 60s TTL.
    nonce = f"nonce_{uuid.uuid4()}"
    cache = TokenReplayCache()
    assert cache.check_and_store(nonce, ttl_seconds=60) is True
    assert cache.check_and_store(nonce, ttl_seconds=60) is False
