"""
VerityFlux Enterprise - Red Team Module
PROPRIETARY AND CONFIDENTIAL - Copyright (c) 2025 VerityFlux

This module contains VerityFlux's proprietary AI security testing capabilities:
- Attack payload library (jailbreaks, injections, exfiltration)
- Tool orchestration (ART, Garak, PyRIT, TextAttack wrappers)
- Automated red teaming execution

DO NOT OPEN SOURCE THIS MODULE.
"""

from .attack_library import (
    AttackLibrary,
    AttackPayload,
    AttackCategory,
    AttackSeverity,
    AttackComplexity,
)

from .tool_orchestrator import (
    ToolOrchestrator,
    ScanResult,
    Finding,
    FindingSeverity,
    ToolAdapter,
    GarakAdapter,
    PyRITAdapter,
    ARTAdapter,
    TextAttackAdapter,
)

__all__ = [
    # Attack Library (PROPRIETARY)
    "AttackLibrary",
    "AttackPayload",
    "AttackCategory",
    "AttackSeverity",
    "AttackComplexity",
    # Tool Orchestration
    "ToolOrchestrator",
    "ScanResult",
    "Finding",
    "FindingSeverity",
    "ToolAdapter",
    "GarakAdapter",
    "PyRITAdapter",
    "ARTAdapter",
    "TextAttackAdapter",
]
