"""
VerityFlux Enterprise - SDK Package

Provides SDKs and integrations for:
- Python applications
- TypeScript/JavaScript applications
- LangChain agents
- AutoGen agents
- CrewAI agents
"""

__version__ = "1.0.0"

# Try to import Python SDK
try:
    from .python.verityflux_sdk import (
        VerityFluxClient,
        ApprovalRequired,
        ActionDenied,
    )
    PYTHON_SDK_AVAILABLE = True
except ImportError:
    PYTHON_SDK_AVAILABLE = False

__all__ = [
    "__version__",
    "PYTHON_SDK_AVAILABLE",
]

if PYTHON_SDK_AVAILABLE:
    __all__.extend([
        "VerityFluxClient",
        "ApprovalRequired",
        "ActionDenied",
    ])
