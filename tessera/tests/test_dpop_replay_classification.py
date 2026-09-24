"""Replay vs substitution classification in the DPoP cache.

A repeated jti previously produced one indistinguishable rejection. It can mean
two different things: the same proof presented again for the same request
(often a client retry), or a captured proof reused to authorise a *different*
request. Both must be refused, but only the second is unambiguously an attack,
and an operator triaging an incident needs to know which occurred.

Pattern adopted from CAGE's ConsequenceAuthorityStore, which stores a binding
hash rather than a sentinel for exactly this reason.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tessera.dpop_replay_cache import DPoPReplayCache, ReplayOutcome


@pytest.fixture
def cache(monkeypatch):
    """In-memory cache — Redis is exercised separately by integration tests."""
    c = DPoPReplayCache()
    c.redis = None
    return c


def _binding(cache, **kw):
    return cache.binding_hash(**kw)


def test_first_use_is_accepted(cache):
    accepted, outcome = cache.check_and_classify("jti-1", binding=_binding(cache, htm="POST"))
    assert accepted is True
    assert outcome is ReplayOutcome.ACCEPTED


def test_same_proof_same_request_is_a_replay(cache):
    b = _binding(cache, htm="POST", htu="https://x/validate", agent_id="a1")
    cache.check_and_classify("jti-1", binding=b)

    accepted, outcome = cache.check_and_classify("jti-1", binding=b)

    assert accepted is False
    assert outcome is ReplayOutcome.REPLAY


def test_same_proof_different_request_is_a_substitution(cache):
    original = _binding(cache, htm="POST", htu="https://x/validate", agent_id="a1")
    cache.check_and_classify("jti-1", binding=original)

    # Same captured proof, aimed at a different endpoint.
    reused = _binding(cache, htm="POST", htu="https://x/admin/keys", agent_id="a1")
    accepted, outcome = cache.check_and_classify("jti-1", binding=reused)

    assert accepted is False
    assert outcome is ReplayOutcome.SUBSTITUTION


def test_rejection_without_a_binding_is_not_guessed(cache):
    """Honest classification: with nothing to compare, say so."""
    cache.check_and_classify("jti-1")
    accepted, outcome = cache.check_and_classify("jti-1")

    assert accepted is False
    assert outcome is ReplayOutcome.REPLAY_UNCLASSIFIED


def test_binding_hash_is_order_and_name_stable(cache):
    a = cache.binding_hash(htm="POST", htu="https://x/y")
    b = cache.binding_hash(htu="https://x/y", htm="POST")
    assert a == b
    # Field names are part of the material, so moving a value between fields
    # must not collide.
    assert cache.binding_hash(htm="x", htu=None) != cache.binding_hash(htu="x", htm=None)


def test_none_fields_are_skipped(cache):
    assert cache.binding_hash(htm="POST", htu=None) == cache.binding_hash(htm="POST")


def test_existing_check_and_store_contract_is_unchanged(cache):
    assert cache.check_and_store("jti-legacy", ttl_seconds=60) is True
    assert cache.check_and_store("jti-legacy", ttl_seconds=60) is False


def test_empty_jti_is_refused(cache):
    accepted, outcome = cache.check_and_classify("")
    assert accepted is False
    assert outcome is ReplayOutcome.REPLAY_UNCLASSIFIED
