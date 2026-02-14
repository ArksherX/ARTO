"""
Compatibility layer for core modules.
"""

from importlib import import_module

__all__ = [
    "rate_limiting",
    "observability",
    "offline_updates",
]

def __getattr__(name):
    if name in __all__:
        return import_module(f"verityflux_enterprise.core.{name}")
    raise AttributeError(name)
