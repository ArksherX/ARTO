#!/usr/bin/env python3
"""Shared utilities for VerityFlux detectors."""

import logging
from typing import Any

from integrations.llm_adapter import LLMAdapter

logger = logging.getLogger("verityflux.detectors")


def get_llm_adapter(target: Any) -> LLMAdapter:
    """
    Build an LLMAdapter from a target dict (or return it directly if already one).

    Extracts ``provider``, ``model``, ``api_key``, and ``base_url`` from the
    target dictionary produced by ``_build_target_dict`` in the API layer.
    """
    if isinstance(target, LLMAdapter):
        return target

    if not isinstance(target, dict):
        return LLMAdapter(provider="mock")

    provider = target.get("provider", "mock")
    model = target.get("model", "mock")
    api_key = target.get("api_key")
    base_url = target.get("base_url")

    if not api_key and provider not in ("mock", "ollama"):
        logger.warning(
            "No api_key for provider '%s' — results will fall back to mock if client init fails.",
            provider,
        )

    return LLMAdapter(
        provider=provider,
        model=model,
        api_key=api_key,
        base_url=base_url,
    )
