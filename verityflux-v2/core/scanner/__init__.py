"""
VerityFlux Enterprise - Security Scanner Module
"""

from importlib.util import spec_from_file_location, module_from_spec
from pathlib import Path

_scanner_path = Path(__file__).resolve().parent.parent / "scanner.py"
_spec = spec_from_file_location("core._scanner_file", _scanner_path)
if _spec and _spec.loader:
    _mod = module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    VerityFluxScanner = getattr(_mod, "VerityFluxScanner")
    __all__ = ["VerityFluxScanner"]
else:
    __all__ = []
