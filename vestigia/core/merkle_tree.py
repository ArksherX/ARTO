#!/usr/bin/env python3
"""
Merkle tree utilities for batch anchoring.
"""

from __future__ import annotations

import hashlib
from typing import List


def _hash_pair(left: str, right: str) -> str:
    return hashlib.sha256(f"{left}{right}".encode()).hexdigest()


def merkle_root(hashes: List[str]) -> str:
    if not hashes:
        return hashlib.sha256(b"").hexdigest()
    level = hashes[:]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        next_level = []
        for i in range(0, len(level), 2):
            next_level.append(_hash_pair(level[i], level[i + 1]))
        level = next_level
    return level[0]
