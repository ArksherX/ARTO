"""Pluggable embedding backend for semantic drift (semantic-detector foundation).

The drift metric previously had a single hard-coded bag-of-words embedding. The
backend is now selectable: the default "hash" embedding is unchanged (offline,
deterministic), and an opt-in "sbert" backend provides real sentence
embeddings for production. If the optional dependency is absent the detector
latches back to "hash" for the whole instance, so dimensions stay consistent
and nothing fails at runtime.
"""
import os
import sys

import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from cognitive_firewall.semantic_drift import SemanticDriftDetector  # noqa: E402

HASH_DIM = 8 + 64  # 8 semantic categories + 64 lexical buckets


def test_default_backend_is_hash(monkeypatch):
    monkeypatch.delenv("VERITYFLUX_EMBEDDING_BACKEND", raising=False)
    det = SemanticDriftDetector()
    assert det.backend == "hash"
    vec = det._get_embedding("read the config file")
    assert vec.shape == (HASH_DIM,)


def test_hash_embedding_is_deterministic(monkeypatch):
    monkeypatch.delenv("VERITYFLUX_EMBEDDING_BACKEND", raising=False)
    a = SemanticDriftDetector()._get_embedding("delete all records now")
    b = SemanticDriftDetector()._get_embedding("delete all records now")
    assert np.allclose(a, b)


def test_hash_embedding_is_normalized(monkeypatch):
    monkeypatch.delenv("VERITYFLUX_EMBEDDING_BACKEND", raising=False)
    vec = SemanticDriftDetector()._get_embedding("optimize the database")
    assert abs(np.linalg.norm(vec) - 1.0) < 1e-9


def test_sbert_backend_falls_back_when_dependency_absent(monkeypatch):
    """Requesting sbert must never crash: if unavailable, latch to hash."""
    monkeypatch.setenv("VERITYFLUX_EMBEDDING_BACKEND", "sbert")
    det = SemanticDriftDetector()
    assert det.backend == "sbert"

    has_sbert = True
    try:
        import sentence_transformers  # noqa: F401
    except Exception:
        has_sbert = False

    vec = det._get_embedding("grant admin access")  # must not raise
    if not has_sbert:
        assert det._sbert_failed is True
        assert vec.shape == (HASH_DIM,)  # fell back to hash
    else:
        # Real backend produced a (differently sized) normalized vector.
        assert vec.shape != (HASH_DIM,)
        assert abs(np.linalg.norm(vec) - 1.0) < 1e-6


def test_drift_still_computes_under_sbert_request(monkeypatch):
    """End-to-end calculate_drift works whether or not sbert is present."""
    monkeypatch.setenv("VERITYFLUX_EMBEDDING_BACKEND", "sbert")
    det = SemanticDriftDetector()
    result = det.calculate_drift(
        original_goal="summarize the quarterly report",
        reasoning_chain=["open the report", "extract figures"],
        predicted_action="delete the production database",
    )
    assert 0.0 <= result["drift_score"] <= 1.0
