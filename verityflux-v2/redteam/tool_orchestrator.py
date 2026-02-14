#!/usr/bin/env python3
"""
VerityFlux Enterprise - Tool Orchestrator
PROPRIETARY AND CONFIDENTIAL - Copyright (c) 2025 VerityFlux

This module provides a wrapper/orchestration layer for external AI security
testing tools. It does NOT bundle or copy code from these tools - instead it
calls them via subprocess or their public APIs.

Supported Tools (user must install separately):
- IBM Adversarial Robustness Toolbox (ART) - MIT License
- NVIDIA Garak - Apache 2.0 License  
- Microsoft PyRIT - MIT License
- TextAttack - MIT License

Usage:
    from verityflux_enterprise.redteam import ToolOrchestrator
    
    orchestrator = ToolOrchestrator()
    
    # Check which tools are available
    available = orchestrator.get_available_tools()
    
    # Run a scan using Garak
    results = orchestrator.run_scan(
        tool="garak",
        target="openai:gpt-3.5-turbo",
        probes=["prompt_injection", "encoding"]
    )
    
    # Run multiple tools and aggregate results
    combined = orchestrator.run_multi_tool_scan(
        tools=["garak", "pyrit"],
        target="my-model"
    )
"""

import os
import sys
import json
import logging
import subprocess
import tempfile
import shutil
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from enum import Enum
import hashlib

logger = logging.getLogger("verityflux.redteam.orchestrator")


# =============================================================================
# SCAN RESULT DATA STRUCTURES
# =============================================================================

class FindingSeverity(Enum):
    """Normalized severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    """A single security finding from a scan."""
    id: str
    tool: str
    category: str
    severity: FindingSeverity
    title: str
    description: str
    payload: Optional[str] = None
    response: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tool": self.tool,
            "category": self.category,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "payload": self.payload,
            "response": self.response,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": self.references,
            "metadata": self.metadata,
        }


@dataclass
class ScanResult:
    """Results from a security scan."""
    scan_id: str
    tool: str
    target: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0
    findings: List[Finding] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    raw_output: Optional[str] = None
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "tool": self.tool,
            "target": self.target,
            "status": self.status,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary,
            "error": self.error,
        }
    
    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.CRITICAL)
    
    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.HIGH)


# =============================================================================
# TOOL ADAPTER BASE CLASS
# =============================================================================

class ToolAdapter(ABC):
    """
    Abstract base class for external tool adapters.
    
    Each adapter wraps an external tool using subprocess calls or public APIs.
    NO code from the external tools is copied or bundled.
    """
    
    name: str = "base"
    version: str = "unknown"
    license: str = "unknown"
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if the tool is installed and available."""
        pass
    
    @abstractmethod
    def get_version(self) -> Optional[str]:
        """Get the installed version of the tool."""
        pass
    
    @abstractmethod
    def run_scan(
        self,
        target: str,
        config: Dict[str, Any] = None,
        timeout: int = 600,
    ) -> ScanResult:
        """Run a scan using this tool."""
        pass
    
    def _generate_scan_id(self) -> str:
        """Generate a unique scan ID."""
        timestamp = datetime.utcnow().isoformat()
        return f"{self.name}-{hashlib.md5(timestamp.encode()).hexdigest()[:8]}"
    
    def _run_command(
        self,
        cmd: List[str],
        timeout: int = 600,
        cwd: str = None,
        env: Dict[str, str] = None,
    ) -> Tuple[int, str, str]:
        """
        Run a command and capture output.
        
        Returns:
            (return_code, stdout, stderr)
        """
        try:
            process_env = os.environ.copy()
            if env:
                process_env.update(env)
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                env=process_env,
            )
            
            return result.returncode, result.stdout, result.stderr
            
        except subprocess.TimeoutExpired:
            return -1, "", f"Command timed out after {timeout} seconds"
        except FileNotFoundError:
            return -2, "", f"Command not found: {cmd[0]}"
        except Exception as e:
            return -3, "", str(e)


# =============================================================================
# GARAK ADAPTER (NVIDIA - Apache 2.0)
# =============================================================================

class GarakAdapter(ToolAdapter):
    """
    Adapter for NVIDIA Garak LLM vulnerability scanner.
    
    License: Apache 2.0
    Install: pip install garak
    Source: https://github.com/NVIDIA/garak
    """
    
    name = "garak"
    version = "0.9"
    license = "Apache-2.0"
    
    def is_available(self) -> bool:
        """Check if Garak is installed."""
        returncode, _, _ = self._run_command(["garak", "--version"], timeout=10)
        return returncode == 0
    
    def get_version(self) -> Optional[str]:
        """Get Garak version."""
        returncode, stdout, _ = self._run_command(["garak", "--version"], timeout=10)
        if returncode == 0:
            return stdout.strip()
        return None
    
    def run_scan(
        self,
        target: str,
        config: Dict[str, Any] = None,
        timeout: int = 600,
    ) -> ScanResult:
        """
        Run a Garak scan.
        
        Args:
            target: Model generator string (e.g., "openai:gpt-3.5-turbo")
            config: Optional configuration
            timeout: Timeout in seconds
        
        Returns:
            ScanResult with findings
        """
        config = config or {}
        scan_id = self._generate_scan_id()
        started_at = datetime.utcnow()
        
        # Build command
        cmd = ["garak", "--model_type", target]
        
        # Add probes if specified
        probes = config.get("probes", [])
        if probes:
            cmd.extend(["--probes", ",".join(probes)])
        
        # Add detectors if specified
        detectors = config.get("detectors", [])
        if detectors:
            cmd.extend(["--detectors", ",".join(detectors)])
        
        # Output format
        cmd.extend(["--report_prefix", f"/tmp/garak_{scan_id}"])
        
        logger.info(f"Running Garak scan: {' '.join(cmd)}")
        
        returncode, stdout, stderr = self._run_command(cmd, timeout=timeout)
        
        completed_at = datetime.utcnow()
        duration = (completed_at - started_at).total_seconds()
        
        if returncode != 0:
            return ScanResult(
                scan_id=scan_id,
                tool=self.name,
                target=target,
                status="error",
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=duration,
                error=stderr or f"Garak exited with code {returncode}",
                raw_output=stdout,
            )
        
        # Parse results
        findings = self._parse_garak_output(stdout, scan_id)
        
        return ScanResult(
            scan_id=scan_id,
            tool=self.name,
            target=target,
            status="completed",
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration,
            findings=findings,
            summary={
                "total_findings": len(findings),
                "critical": sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL),
                "high": sum(1 for f in findings if f.severity == FindingSeverity.HIGH),
            },
            raw_output=stdout,
        )
    
    def _parse_garak_output(self, output: str, scan_id: str) -> List[Finding]:
        """Parse Garak output into findings."""
        findings = []
        
        # Garak outputs JSON results - parse them
        try:
            report_file = f"/tmp/garak_{scan_id}.report.jsonl"
            if os.path.exists(report_file):
                with open(report_file, 'r') as f:
                    for line in f:
                        data = json.loads(line)
                        if data.get("status") == "FAIL":
                            findings.append(Finding(
                                id=f"{scan_id}-{len(findings)+1}",
                                tool=self.name,
                                category=data.get("probe", "unknown"),
                                severity=self._map_severity(data.get("severity", "medium")),
                                title=data.get("probe", "Garak Finding"),
                                description=data.get("message", ""),
                                payload=data.get("prompt", ""),
                                response=data.get("response", ""),
                                metadata=data,
                            ))
        except Exception as e:
            logger.warning(f"Failed to parse Garak report: {e}")
            
            # Fallback: parse stdout for FAIL lines
            for line in output.split('\n'):
                if 'FAIL' in line:
                    findings.append(Finding(
                        id=f"{scan_id}-{len(findings)+1}",
                        tool=self.name,
                        category="unknown",
                        severity=FindingSeverity.MEDIUM,
                        title="Garak Finding",
                        description=line,
                    ))
        
        return findings
    
    def _map_severity(self, severity: str) -> FindingSeverity:
        """Map Garak severity to our normalized severity."""
        mapping = {
            "critical": FindingSeverity.CRITICAL,
            "high": FindingSeverity.HIGH,
            "medium": FindingSeverity.MEDIUM,
            "low": FindingSeverity.LOW,
            "info": FindingSeverity.INFO,
        }
        return mapping.get(severity.lower(), FindingSeverity.MEDIUM)


# =============================================================================
# PYRIT ADAPTER (Microsoft - MIT)
# =============================================================================

class PyRITAdapter(ToolAdapter):
    """
    Adapter for Microsoft PyRIT (Python Risk Identification Toolkit).
    
    License: MIT
    Install: pip install pyrit
    Source: https://github.com/Azure/PyRIT
    """
    
    name = "pyrit"
    version = "0.2"
    license = "MIT"
    
    def is_available(self) -> bool:
        """Check if PyRIT is installed."""
        try:
            import importlib.util
            return importlib.util.find_spec("pyrit") is not None
        except:
            return False
    
    def get_version(self) -> Optional[str]:
        """Get PyRIT version."""
        try:
            import pyrit
            return getattr(pyrit, "__version__", "unknown")
        except:
            return None
    
    def run_scan(
        self,
        target: str,
        config: Dict[str, Any] = None,
        timeout: int = 600,
    ) -> ScanResult:
        """
        Run a PyRIT scan.
        
        Note: PyRIT is a library, so we call it via Python API rather than subprocess.
        """
        config = config or {}
        scan_id = self._generate_scan_id()
        started_at = datetime.utcnow()
        
        findings = []
        error = None
        
        try:
            # Import PyRIT components
            # Note: This only works if PyRIT is installed
            from pyrit.orchestrator import PromptSendingOrchestrator
            from pyrit.prompt_target import AzureOpenAIChatTarget
            from pyrit.common import default_values
            
            # PyRIT requires specific setup - we'll run a basic probe
            # In production, this would be more sophisticated
            
            logger.info(f"Running PyRIT scan against {target}")
            
            # For now, return a placeholder result
            # Full implementation would set up PyRIT orchestrator
            error = "PyRIT scan requires additional configuration. Set up Azure OpenAI credentials."
            
        except ImportError as e:
            error = f"PyRIT not installed or import failed: {e}"
        except Exception as e:
            error = f"PyRIT scan failed: {e}"
        
        completed_at = datetime.utcnow()
        duration = (completed_at - started_at).total_seconds()
        
        return ScanResult(
            scan_id=scan_id,
            tool=self.name,
            target=target,
            status="error" if error else "completed",
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration,
            findings=findings,
            error=error,
        )


# =============================================================================
# ART ADAPTER (IBM - MIT)
# =============================================================================

class ARTAdapter(ToolAdapter):
    """
    Adapter for IBM Adversarial Robustness Toolbox.
    
    License: MIT
    Install: pip install adversarial-robustness-toolbox
    Source: https://github.com/Trusted-AI/adversarial-robustness-toolbox
    """
    
    name = "art"
    version = "1.15"
    license = "MIT"
    
    def is_available(self) -> bool:
        """Check if ART is installed."""
        try:
            import importlib.util
            return importlib.util.find_spec("art") is not None
        except:
            return False
    
    def get_version(self) -> Optional[str]:
        """Get ART version."""
        try:
            import art
            return art.__version__
        except:
            return None
    
    def run_scan(
        self,
        target: str,
        config: Dict[str, Any] = None,
        timeout: int = 600,
    ) -> ScanResult:
        """
        Run ART attacks against a model.
        
        ART is primarily for predictive AI models (image classification, etc.)
        rather than generative AI.
        """
        config = config or {}
        scan_id = self._generate_scan_id()
        started_at = datetime.utcnow()
        
        findings = []
        error = None
        
        try:
            # ART requires model access
            # This is a placeholder for full implementation
            
            attack_type = config.get("attack", "fgsm")
            
            logger.info(f"Running ART {attack_type} attack against {target}")
            
            # Full implementation would:
            # 1. Load/connect to the model
            # 2. Run specified attacks (FGSM, PGD, etc.)
            # 3. Measure robustness
            
            error = "ART scan requires model access. Provide model object or endpoint in config."
            
        except ImportError as e:
            error = f"ART not installed: {e}"
        except Exception as e:
            error = f"ART scan failed: {e}"
        
        completed_at = datetime.utcnow()
        duration = (completed_at - started_at).total_seconds()
        
        return ScanResult(
            scan_id=scan_id,
            tool=self.name,
            target=target,
            status="error" if error else "completed",
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration,
            findings=findings,
            error=error,
        )


# =============================================================================
# TEXTATTACK ADAPTER (MIT)
# =============================================================================

class TextAttackAdapter(ToolAdapter):
    """
    Adapter for TextAttack NLP adversarial attacks.
    
    License: MIT
    Install: pip install textattack
    Source: https://github.com/QData/TextAttack
    """
    
    name = "textattack"
    version = "0.3"
    license = "MIT"
    
    def is_available(self) -> bool:
        """Check if TextAttack is installed."""
        returncode, _, _ = self._run_command(["textattack", "--help"], timeout=10)
        return returncode == 0
    
    def get_version(self) -> Optional[str]:
        """Get TextAttack version."""
        try:
            import textattack
            return textattack.__version__
        except:
            return None
    
    def run_scan(
        self,
        target: str,
        config: Dict[str, Any] = None,
        timeout: int = 600,
    ) -> ScanResult:
        """
        Run TextAttack against a text classification model.
        """
        config = config or {}
        scan_id = self._generate_scan_id()
        started_at = datetime.utcnow()
        
        # Build command
        attack_recipe = config.get("recipe", "textfooler")
        num_examples = config.get("num_examples", 10)
        
        cmd = [
            "textattack", "attack",
            "--model", target,
            "--recipe", attack_recipe,
            "--num-examples", str(num_examples),
        ]
        
        logger.info(f"Running TextAttack: {' '.join(cmd)}")
        
        returncode, stdout, stderr = self._run_command(cmd, timeout=timeout)
        
        completed_at = datetime.utcnow()
        duration = (completed_at - started_at).total_seconds()
        
        if returncode != 0:
            return ScanResult(
                scan_id=scan_id,
                tool=self.name,
                target=target,
                status="error",
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=duration,
                error=stderr or f"TextAttack exited with code {returncode}",
                raw_output=stdout,
            )
        
        # Parse results
        findings = self._parse_textattack_output(stdout, scan_id)
        
        return ScanResult(
            scan_id=scan_id,
            tool=self.name,
            target=target,
            status="completed",
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration,
            findings=findings,
            summary={"attack_recipe": attack_recipe, "examples_tested": num_examples},
            raw_output=stdout,
        )
    
    def _parse_textattack_output(self, output: str, scan_id: str) -> List[Finding]:
        """Parse TextAttack output."""
        findings = []
        
        # Look for successful attacks in output
        for line in output.split('\n'):
            if 'SUCCESS' in line or 'Attack succeeded' in line:
                findings.append(Finding(
                    id=f"{scan_id}-{len(findings)+1}",
                    tool=self.name,
                    category="evasion",
                    severity=FindingSeverity.HIGH,
                    title="Successful Adversarial Attack",
                    description=line,
                ))
        
        return findings


# =============================================================================
# TOOL ORCHESTRATOR
# =============================================================================

class ToolOrchestrator:
    """
    Orchestrates multiple AI security testing tools.
    
    This class provides a unified interface to run scans using various
    external tools, aggregate results, and generate reports.
    """
    
    def __init__(self):
        self.adapters: Dict[str, ToolAdapter] = {
            "garak": GarakAdapter(),
            "pyrit": PyRITAdapter(),
            "art": ARTAdapter(),
            "textattack": TextAttackAdapter(),
        }
        
        logger.info(f"Initialized ToolOrchestrator with {len(self.adapters)} adapters")
    
    def get_available_tools(self) -> Dict[str, Dict[str, Any]]:
        """
        Get information about available tools.
        
        Returns:
            Dict mapping tool name to availability info
        """
        result = {}
        for name, adapter in self.adapters.items():
            available = adapter.is_available()
            result[name] = {
                "name": adapter.name,
                "available": available,
                "version": adapter.get_version() if available else None,
                "license": adapter.license,
            }
        return result
    
    def run_scan(
        self,
        tool: str,
        target: str,
        config: Dict[str, Any] = None,
        timeout: int = 600,
    ) -> ScanResult:
        """
        Run a scan using a specific tool.
        
        Args:
            tool: Tool name (garak, pyrit, art, textattack)
            target: Target model or endpoint
            config: Tool-specific configuration
            timeout: Timeout in seconds
        
        Returns:
            ScanResult with findings
        """
        if tool not in self.adapters:
            return ScanResult(
                scan_id=f"error-{tool}",
                tool=tool,
                target=target,
                status="error",
                started_at=datetime.utcnow(),
                error=f"Unknown tool: {tool}. Available: {list(self.adapters.keys())}",
            )
        
        adapter = self.adapters[tool]
        
        if not adapter.is_available():
            return ScanResult(
                scan_id=f"error-{tool}",
                tool=tool,
                target=target,
                status="error",
                started_at=datetime.utcnow(),
                error=f"Tool '{tool}' is not installed. Install with: pip install {tool}",
            )
        
        return adapter.run_scan(target, config, timeout)
    
    def run_multi_tool_scan(
        self,
        tools: List[str],
        target: str,
        config: Dict[str, Dict[str, Any]] = None,
        timeout_per_tool: int = 600,
    ) -> Dict[str, ScanResult]:
        """
        Run scans using multiple tools and aggregate results.
        
        Args:
            tools: List of tool names to use
            target: Target model or endpoint
            config: Dict mapping tool name to tool-specific config
            timeout_per_tool: Timeout per tool in seconds
        
        Returns:
            Dict mapping tool name to ScanResult
        """
        config = config or {}
        results = {}
        
        for tool in tools:
            tool_config = config.get(tool, {})
            results[tool] = self.run_scan(tool, target, tool_config, timeout_per_tool)
        
        return results
    
    def aggregate_findings(self, results: Dict[str, ScanResult]) -> List[Finding]:
        """
        Aggregate findings from multiple scan results.
        
        Deduplicates similar findings and sorts by severity.
        """
        all_findings = []
        
        for tool, result in results.items():
            all_findings.extend(result.findings)
        
        # Sort by severity (critical first)
        severity_order = {
            FindingSeverity.CRITICAL: 0,
            FindingSeverity.HIGH: 1,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.LOW: 3,
            FindingSeverity.INFO: 4,
        }
        
        all_findings.sort(key=lambda f: severity_order.get(f.severity, 5))
        
        return all_findings
    
    def generate_report(
        self,
        results: Dict[str, ScanResult],
        format: str = "json"
    ) -> str:
        """
        Generate a combined report from multiple scan results.
        
        Args:
            results: Dict mapping tool name to ScanResult
            format: Output format (json, markdown, html)
        
        Returns:
            Report as string
        """
        all_findings = self.aggregate_findings(results)
        
        report_data = {
            "generated_at": datetime.utcnow().isoformat(),
            "tools_used": list(results.keys()),
            "summary": {
                "total_findings": len(all_findings),
                "critical": sum(1 for f in all_findings if f.severity == FindingSeverity.CRITICAL),
                "high": sum(1 for f in all_findings if f.severity == FindingSeverity.HIGH),
                "medium": sum(1 for f in all_findings if f.severity == FindingSeverity.MEDIUM),
                "low": sum(1 for f in all_findings if f.severity == FindingSeverity.LOW),
            },
            "scans": {name: r.to_dict() for name, r in results.items()},
            "all_findings": [f.to_dict() for f in all_findings],
        }
        
        if format == "json":
            return json.dumps(report_data, indent=2)
        elif format == "markdown":
            return self._generate_markdown_report(report_data)
        else:
            return json.dumps(report_data, indent=2)
    
    def _generate_markdown_report(self, data: Dict[str, Any]) -> str:
        """Generate a Markdown report."""
        lines = [
            "# VerityFlux Security Scan Report",
            f"\nGenerated: {data['generated_at']}",
            f"\nTools Used: {', '.join(data['tools_used'])}",
            "\n## Summary",
            f"\n- **Total Findings**: {data['summary']['total_findings']}",
            f"- **Critical**: {data['summary']['critical']}",
            f"- **High**: {data['summary']['high']}",
            f"- **Medium**: {data['summary']['medium']}",
            f"- **Low**: {data['summary']['low']}",
            "\n## Findings",
        ]
        
        for finding in data["all_findings"]:
            lines.append(f"\n### [{finding['severity'].upper()}] {finding['title']}")
            lines.append(f"\n**Tool**: {finding['tool']}")
            lines.append(f"\n**Category**: {finding['category']}")
            lines.append(f"\n{finding['description']}")
            if finding.get('payload'):
                lines.append(f"\n**Payload**: `{finding['payload'][:100]}...`")
        
        return '\n'.join(lines)


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
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
