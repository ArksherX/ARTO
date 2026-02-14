"""
Compatibility package for test imports.
Re-exports the main VerityFlux modules under verityflux_enterprise.* namespace.
"""

from importlib import import_module

__all__ = ["core", "api", "sdk"]

def __getattr__(name):
    if name in __all__:
        return import_module(f"verityflux_enterprise.{name}")
    raise AttributeError(name)
