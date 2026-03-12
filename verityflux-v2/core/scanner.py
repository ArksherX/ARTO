#!/usr/bin/env python3
"""
VerityFlux 2.0 - LLM Application Security Scanner
OWASP LLM Top 10 2025 + OWASP Agentic Top 10 2026
"""

import time
from datetime import datetime
from typing import List, Optional, Any
from pathlib import Path
import sys

# Add parent directory to path for absolute imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.types import (
    LLMThreat, AgenticThreat, FuzzThreat, MCPThreat,
    SecurityReport, ScanConfig, ThreatDetectionResult
)

class VerityFluxScanner:
    """
    Main security scanner for LLM applications.
    
    Covers:
    - OWASP LLM Top 10 2025 (all 10 risks)
    - OWASP Agentic Top 10 2026 (all 10 risks)
    """
    
    def __init__(
        self,
        application_name: str = "LLM Application",
        config: Optional[ScanConfig] = None
    ):
        self.application_name = application_name
        self.config = config or ScanConfig()
        
        # Lazy-load detectors
        self._llm_detectors = {}
        self._agentic_detectors = {}
    
    def scan_all(self, target: Any) -> SecurityReport:
        """
        Run comprehensive security scan.
        
        Args:
            target: Can be:
                - LLM model/API endpoint
                - Agent system
                - RAG application
                - Full LLM application stack
        
        Returns:
            Comprehensive security report
        """
        print("="*70)
        print("🔍 VERITYFLUX 2.0 - LLM APPLICATION SECURITY SCAN")
        print("="*70)
        print(f"Application: {self.application_name}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Framework: OWASP LLM Top 10 2025 + Agentic Top 10 2026")
        print("="*70)
        
        start_time = time.time()
        
        report = SecurityReport(
            application_name=self.application_name,
            scan_timestamp=datetime.now()
        )
        
        # Scan LLM threats
        if self.config.scan_llm_threats:
            print("\n🔥 OWASP LLM TOP 10 2025")
            print("-" * 70)
            llm_results = self._scan_llm_threats(target)
            report.llm_threats = llm_results
            report.detectors_run.extend([f"LLM{i:02d}" for i in range(1, 11)])
        
        # Scan Agentic threats
        if self.config.scan_agentic_threats:
            print("\n🤖 OWASP AGENTIC TOP 10 2026")
            print("-" * 70)
            agentic_results = self._scan_agentic_threats(target)
            report.agentic_threats = agentic_results
            report.detectors_run.extend([f"AAI{i:02d}" for i in range(1, 11)])

        # Scan Fuzz threats
        if self.config.scan_fuzz_threats:
            print("\n🧪 AGENTIC WORKFLOW FUZZING")
            print("-" * 70)
            fuzz_results = self._scan_fuzz_threats(target)
            report.fuzz_threats = fuzz_results
            report.detectors_run.extend([f"FUZZ{i:02d}" for i in range(1, 4)])

        # Scan MCP threats
        if self.config.scan_mcp_threats:
            print("\n🔌 MCP SECURITY SCAN")
            print("-" * 70)
            mcp_results = self._scan_mcp_threats(target)
            report.mcp_threats = mcp_results
            report.detectors_run.extend([f"MCP{i:02d}" for i in range(1, 5)])

        # Finalize
        report.scan_duration_seconds = time.time() - start_time
        report.calculate_risk_score()
        
        self._print_summary(report)
        
        return report
    
    def _scan_llm_threats(self, target: Any) -> List[ThreatDetectionResult]:
        """Scan all OWASP LLM Top 10 2025 threats"""
        results = []
        
        # LLM01: Prompt Injection
        print("[1/10] LLM01: Prompt Injection Detection...")
        results.append(self._detect_llm01(target))
        
        # LLM02: Sensitive Information Disclosure
        print("[2/10] LLM02: Sensitive Data Exposure...")
        results.append(self._detect_llm02(target))
        
        # LLM03: Supply Chain Vulnerabilities
        print("[3/10] LLM03: Supply Chain Security...")
        results.append(self._detect_llm03(target))
        
        # LLM04: Data and Model Poisoning
        print("[4/10] LLM04: Data/Model Poisoning...")
        results.append(self._detect_llm04(target))
        
        # LLM05: Improper Output Handling
        print("[5/10] LLM05: Output Handling...")
        results.append(self._detect_llm05(target))
        
        # LLM06: Excessive Agency
        print("[6/10] LLM06: Excessive Agency...")
        results.append(self._detect_llm06(target))
        
        # LLM07: System Prompt Leakage (NEW 2025)
        print("[7/10] LLM07: System Prompt Leakage...")
        results.append(self._detect_llm07(target))
        
        # LLM08: Vector and Embedding Weaknesses (NEW 2025)
        print("[8/10] LLM08: RAG/Vector Security...")
        results.append(self._detect_llm08(target))
        
        # LLM09: Misinformation (NEW 2025)
        print("[9/10] LLM09: Misinformation/Hallucination...")
        results.append(self._detect_llm09(target))
        
        # LLM10: Unbounded Consumption
        print("[10/10] LLM10: Resource Abuse...")
        results.append(self._detect_llm10(target))
        
        return results
    
    def _scan_agentic_threats(self, target: Any) -> List[ThreatDetectionResult]:
        """Scan all OWASP Agentic Top 10 2026 threats"""
        results = []
        
        # AAI01: Agent Goal Hijacking
        print("[1/10] AAI01: Agent Goal Hijacking...")
        results.append(self._detect_aai01(target))
        
        # AAI02: Identity & Privilege Abuse
        print("[2/10] AAI02: Identity/Privilege Abuse...")
        results.append(self._detect_aai02(target))
        
        # AAI03: Unexpected Code Execution
        print("[3/10] AAI03: Code Execution Risks...")
        results.append(self._detect_aai03(target))
        
        # AAI04: Insecure InterAgent Communication
        print("[4/10] AAI04: InterAgent Security...")
        results.append(self._detect_aai04(target))
        
        # AAI05: Human-Agent Trust Exploitation
        print("[5/10] AAI05: Trust Exploitation...")
        results.append(self._detect_aai05(target))
        
        # AAI06: Tool Misuse & Exploitation
        print("[6/10] AAI06: Tool Misuse...")
        results.append(self._detect_aai06(target))
        
        # AAI07: Agentic Supply Chain
        print("[7/10] AAI07: Agentic Supply Chain...")
        results.append(self._detect_aai07(target))
        
        # AAI08: Memory & Context Poisoning
        print("[8/10] AAI08: Memory Poisoning...")
        results.append(self._detect_aai08(target))
        
        # AAI09: Cascading Failures
        print("[9/10] AAI09: Cascading Failures...")
        results.append(self._detect_aai09(target))
        
        # AAI10: Rogue Agents
        print("[10/10] AAI10: Rogue Agent Detection...")
        results.append(self._detect_aai10(target))
        
        return results
    
    # ========================================================================
    # LLM THREAT DETECTORS
    # ========================================================================
    
    def _detect_llm01(self, target) -> ThreatDetectionResult:
        """Detect LLM01: Prompt Injection"""
        try:
            from detectors.llm_top10.llm01_prompt_injection import detect
            return detect(target, self.config)
        except Exception as e:
            print(f"    ⚠️ Detector failed: {e}")
            return self._create_error_result(LLMThreat.LLM01_PROMPT_INJECTION, str(e))
    
    def _detect_llm02(self, target) -> ThreatDetectionResult:
        """Detect LLM02: Sensitive Data"""
        try:
            from detectors.llm_top10.llm02_sensitive_data import detect
            return detect(target, self.config)
        except Exception as e:
            return self._create_error_result(LLMThreat.LLM02_SENSITIVE_DATA, str(e))
    
    def _detect_llm03(self, target) -> ThreatDetectionResult:
        """Detect LLM03: Supply Chain"""
        try:
            from detectors.llm_top10.llm03_supply_chain import detect
            return detect(target, self.config)
        except Exception as e:
            return self._create_error_result(LLMThreat.LLM03_SUPPLY_CHAIN, str(e))
    
    def _detect_llm04(self, target) -> ThreatDetectionResult:
        """Detect LLM04: Data Poisoning"""
        try:
            from detectors.llm_top10.llm04_data_poisoning import detect
            return detect(target, self.config)
        except Exception as e:
            return self._create_error_result(LLMThreat.LLM04_DATA_POISONING, str(e))
    
    def _detect_llm05(self, target) -> ThreatDetectionResult:
        """Detect LLM05: Output Handling"""
        try:
            from detectors.llm_top10.llm05_output_handling import detect
            return detect(target, self.config)
        except Exception as e:
            return self._create_error_result(LLMThreat.LLM05_OUTPUT_HANDLING, str(e))
    
    def _detect_llm06(self, target) -> ThreatDetectionResult:
        """Detect LLM06: Excessive Agency"""
        try:
            from detectors.llm_top10.llm06_excessive_agency import detect
            return detect(target, self.config)
        except Exception as e:
            return self._create_error_result(LLMThreat.LLM06_EXCESSIVE_AGENCY, str(e))
    
    def _detect_llm07(self, target) -> ThreatDetectionResult:
        """Detect LLM07: Prompt Leakage"""
        try:
            from detectors.llm_top10.llm07_prompt_leakage import detect
            return detect(target, self.config)
        except Exception as e:
            return self._create_error_result(LLMThreat.LLM07_PROMPT_LEAKAGE, str(e))
    
    def _detect_llm08(self, target) -> ThreatDetectionResult:
        """Detect LLM08: RAG Weaknesses"""
        try:
            from detectors.llm_top10.llm08_rag_security import detect
            return detect(target, self.config)
        except Exception as e:
            return self._create_error_result(LLMThreat.LLM08_RAG_WEAKNESSES, str(e))
    
    def _detect_llm09(self, target) -> ThreatDetectionResult:
        """Detect LLM09: Misinformation"""
        try:
            from detectors.llm_top10.llm09_misinformation import detect
            return detect(target, self.config)
        except Exception as e:
            return self._create_error_result(LLMThreat.LLM09_MISINFORMATION, str(e))
    
    def _detect_llm10(self, target) -> ThreatDetectionResult:
        """Detect LLM10: Unbounded Consumption"""
        try:
            from detectors.llm_top10.llm10_resource_abuse import detect
            return detect(target, self.config)
        except Exception as e:
            return self._create_error_result(LLMThreat.LLM10_UNBOUNDED_CONSUMPTION, str(e))
    
    # ========================================================================
    # AGENTIC THREAT DETECTORS
    # ========================================================================
    
    def _detect_aai01(self, target) -> ThreatDetectionResult:
        """Detect AAI01: Goal Hijacking"""
        try:
            from detectors.agentic_top10.aai01_goal_hijack import detect
            return detect(target, self.config)
        except Exception as e:
            return self._create_error_result(AgenticThreat.AAI01_GOAL_HIJACK, str(e))
    
    def _detect_aai02(self, target) -> ThreatDetectionResult:
        """Detect AAI02: Identity Abuse"""
        try:
            from detectors.agentic_top10.aai02_identity_abuse import detect
            return detect(target, self.config)
        except Exception as e:
            return self._create_error_result(AgenticThreat.AAI02_IDENTITY_ABUSE, str(e))
    
    def _detect_aai03(self, target) -> ThreatDetectionResult:
        """Detect AAI03: Code Execution"""
        try:
            from detectors.agentic_top10.aai03_code_execution import detect
            return detect(target, self.config)
        except Exception as e:
            return self._create_error_result(AgenticThreat.AAI03_CODE_EXECUTION, str(e))
    
    def _detect_aai04(self, target) -> ThreatDetectionResult:
        """Detect AAI04: InterAgent Communication"""
        try:
            from detectors.agentic_top10.aai04_interagent_comm import detect
            return detect(target, self.config)
        except Exception as e:
            return self._create_error_result(AgenticThreat.AAI04_INTERAGENT_COMM, str(e))
    
    def _detect_aai05(self, target) -> ThreatDetectionResult:
        """Detect AAI05: Trust Exploitation"""
        try:
            from detectors.agentic_top10.aai05_trust_exploit import detect
            return detect(target, self.config)
        except Exception as e:
            return self._create_error_result(AgenticThreat.AAI05_TRUST_EXPLOIT, str(e))
    
    def _detect_aai06(self, target) -> ThreatDetectionResult:
        """Detect AAI06: Tool Misuse"""
        try:
            from detectors.agentic_top10.aai06_tool_misuse import detect
            return detect(target, self.config)
        except Exception as e:
            return self._create_error_result(AgenticThreat.AAI06_TOOL_MISUSE, str(e))
    
    def _detect_aai07(self, target) -> ThreatDetectionResult:
        """Detect AAI07: Agentic Supply Chain"""
        try:
            from detectors.agentic_top10.aai07_supply_chain import detect
            return detect(target, self.config)
        except Exception as e:
            return self._create_error_result(AgenticThreat.AAI07_AGENTIC_SUPPLY_CHAIN, str(e))
    
    def _detect_aai08(self, target) -> ThreatDetectionResult:
        """Detect AAI08: Memory Poisoning"""
        try:
            from detectors.agentic_top10.aai08_memory_poison import detect
            return detect(target, self.config)
        except Exception as e:
            return self._create_error_result(AgenticThreat.AAI08_MEMORY_POISON, str(e))
    
    def _detect_aai09(self, target) -> ThreatDetectionResult:
        """Detect AAI09: Cascading Failures"""
        try:
            from detectors.agentic_top10.aai09_cascading_fail import detect
            return detect(target, self.config)
        except Exception as e:
            return self._create_error_result(AgenticThreat.AAI09_CASCADING_FAILURES, str(e))
    
    def _detect_aai10(self, target) -> ThreatDetectionResult:
        """Detect AAI10: Rogue Agents"""
        try:
            from detectors.agentic_top10.aai10_rogue_agents import detect
            return detect(target, self.config)
        except Exception as e:
            return self._create_error_result(AgenticThreat.AAI10_ROGUE_AGENTS, str(e))
    
    # ========================================================================
    # FUZZ THREAT DETECTORS
    # ========================================================================

    def _scan_fuzz_threats(self, target: Any) -> List[ThreatDetectionResult]:
        """Scan agentic workflow fuzzing threats"""
        results = []

        print("[1/3] FUZZ01: Conflicting Goals...")
        try:
            from detectors.fuzz.fuzz01_conflicting_goals import detect
            results.append(detect(target, self.config))
        except Exception as e:
            results.append(self._create_error_result(FuzzThreat.FUZZ01_CONFLICTING_GOALS, str(e)))

        print("[2/3] FUZZ02: Approval Bypass...")
        try:
            from detectors.fuzz.fuzz02_approval_bypass import detect
            results.append(detect(target, self.config))
        except Exception as e:
            results.append(self._create_error_result(FuzzThreat.FUZZ02_APPROVAL_BYPASS, str(e)))

        print("[3/3] FUZZ03: Sequence Break...")
        try:
            from detectors.fuzz.fuzz03_sequence_break import detect
            results.append(detect(target, self.config))
        except Exception as e:
            results.append(self._create_error_result(FuzzThreat.FUZZ03_SEQUENCE_BREAK, str(e)))

        return results

    # ========================================================================
    # MCP THREAT DETECTORS
    # ========================================================================

    def _scan_mcp_threats(self, target: Any) -> List[ThreatDetectionResult]:
        """Scan MCP security threats"""
        results = []

        print("[1/4] MCP01: Confused Deputy...")
        try:
            from detectors.mcp.mcp01_confused_deputy import detect
            results.append(detect(target, self.config))
        except Exception as e:
            results.append(self._create_error_result(MCPThreat.MCP01_CONFUSED_DEPUTY, str(e)))

        print("[2/4] MCP02: Tool Poisoning...")
        try:
            from detectors.mcp.mcp02_tool_poisoning import detect
            results.append(detect(target, self.config))
        except Exception as e:
            results.append(self._create_error_result(MCPThreat.MCP02_TOOL_POISONING, str(e)))

        print("[3/4] MCP03: Cross-Tool Chain...")
        try:
            from detectors.mcp.mcp03_cross_tool_chain import detect
            results.append(detect(target, self.config))
        except Exception as e:
            results.append(self._create_error_result(MCPThreat.MCP03_CROSS_TOOL_CHAIN, str(e)))

        print("[4/4] MCP04: Dynamic Instability...")
        try:
            from detectors.mcp.mcp04_dynamic_instability import detect
            results.append(detect(target, self.config))
        except Exception as e:
            results.append(self._create_error_result(MCPThreat.MCP04_DYNAMIC_INSTABILITY, str(e)))

        return results

    def _create_error_result(self, threat, error_msg: str) -> ThreatDetectionResult:
        """Create error result for failed detector"""
        from core.types import RiskLevel
        
        return ThreatDetectionResult(
            threat_type=threat.value,
            detected=False,
            confidence=0.0,
            risk_level=RiskLevel.INFO,
            description=f"Detector error: {error_msg[:80]}",
            owasp_category=f"{threat.value}"
        )
    
    def _print_summary(self, report: SecurityReport):
        """Print scan summary"""
        print("\n" + "="*70)
        print("📊 SCAN COMPLETE")
        print("="*70)
        print(f"\n⏱️  Duration: {report.scan_duration_seconds:.1f} seconds")
        print(f"🧪 Detectors Run: {len(report.detectors_run)}")
        print(f"🚨 Total Threats: {report.total_threats}")
        print(f"   └─ Critical: {report.critical_threats}")
        print(f"   └─ High: {report.high_threats}")
        print(f"\n🎯 Overall Risk Score: {report.overall_risk_score:.1f}/100")
        
        if report.overall_risk_score >= 70:
            print("   ❌ CRITICAL - Immediate action required!")
        elif report.overall_risk_score >= 40:
            print("   ⚠️  HIGH - Review and remediate soon")
        elif report.overall_risk_score >= 20:
            print("   ⚠️  MEDIUM - Monitor and plan fixes")
        else:
            print("   ✅ LOW - Application appears secure")
        
        print("="*70)

__all__ = ['VerityFluxScanner']
