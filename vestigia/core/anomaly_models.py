#!/usr/bin/env python3
"""
Lightweight anomaly model ensemble (no external ML dependencies).
Implements three model styles to satisfy Phase 5 requirements:
 - IsolationForestLite: distance-from-mean scoring
 - OneClassSVMLite: radial basis novelty scoring
 - SequenceModelLite: Markov transition likelihoods for action sequences
"""

from __future__ import annotations

import math
from typing import Dict, Any, Tuple, List


class IsolationForestLite:
    def fit(self, baseline: Dict[str, Any]):
        self.mean = baseline.get("mean_features", {})
        self.scale = baseline.get("scale_features", {})

    def score(self, features: Dict[str, float]) -> Tuple[float, List[str]]:
        if not self.mean:
            return 0.0, []
        distance = 0.0
        for key, value in features.items():
            mu = self.mean.get(key, 0.0)
            scale = max(1.0, self.scale.get(key, 1.0))
            distance += ((value - mu) / scale) ** 2
        distance = math.sqrt(distance)
        risk = min(100.0, distance * 12.0)
        signals = ["distance_spike"] if risk > 50 else []
        return risk, signals


class OneClassSVMLite:
    def fit(self, baseline: Dict[str, Any]):
        self.mean = baseline.get("mean_features", {})
        self.radius = baseline.get("radius", 1.0)

    def score(self, features: Dict[str, float]) -> Tuple[float, List[str]]:
        if not self.mean:
            return 0.0, []
        distance = 0.0
        for key, value in features.items():
            mu = self.mean.get(key, 0.0)
            distance += (value - mu) ** 2
        distance = math.sqrt(distance)
        if distance <= self.radius:
            return 0.0, []
        risk = min(100.0, (distance / max(1.0, self.radius)) * 15.0)
        return risk, ["novelty"]


class SequenceModelLite:
    def fit(self, baseline: Dict[str, Any]):
        self.transitions = baseline.get("transitions", {})

    def score(self, current_action: str, previous_action: str) -> Tuple[float, List[str]]:
        if not previous_action:
            return 0.0, []
        transitions = self.transitions.get(previous_action, {})
        total = sum(transitions.values())
        if total == 0:
            return 0.0, []
        prob = transitions.get(current_action, 0) / max(1, total)
        if prob >= 0.2:
            return 0.0, []
        risk = min(100.0, (0.2 - prob) * 500.0)
        return risk, ["sequence_anomaly"]
