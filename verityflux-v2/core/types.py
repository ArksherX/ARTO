#!/usr/bin/env python3
"""Type definitions for VerityFlux 2.0"""

from enum import Enum
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime

# ============================================================================
# ENUMS
# ============================================================================

class RiskLevel(str, Enum):
    """Risk severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class AttackVector(str, Enum):
    """Attack vector types"""
    DIRECT_PROMPT = "direct_prompt"
    INDIRECT_PROMPT = "indirect_prompt"
    PAYLOAD_SPLITTING = "payload_splitting"
    RAG_INJECTION = "rag_injection"
    AGENT_MANIPULATION = "agent_manipulation"
    MEMORY_INJECTION = "memory_injection"
    OUTPUT_INJECTION = "output_injection"
    TRAINING_DATA = "training_data"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    TOOL_ABUSE = "tool_abuse"
    INTERAGENT_COMM = "interagent_communication"

class LLMThreat(str, Enum):
    """OWASP LLM Top 10 2025"""
    LLM01_PROMPT_INJECTION = "llm01_prompt_injection"
    LLM02_SENSITIVE_DATA = "llm02_sensitive_information_disclosure"
    LLM03_SUPPLY_CHAIN = "llm03_supply_chain_vulnerabilities"
    LLM04_DATA_POISONING = "llm04_data_model_poisoning"
    LLM05_OUTPUT_HANDLING = "llm05_improper_output_handling"
    LLM06_EXCESSIVE_AGENCY = "llm06_excessive_agency"
    LLM07_PROMPT_LEAKAGE = "llm07_system_prompt_leakage"
    LLM08_RAG_WEAKNESSES = "llm08_vector_embedding_weaknesses"
    LLM09_MISINFORMATION = "llm09_misinformation"
    LLM10_UNBOUNDED_CONSUMPTION = "llm10_unbounded_consumption"

class AgenticThreat(str, Enum):
    """OWASP Agentic AI Top 10 2026"""
    AAI01_GOAL_HIJACK = "aai01_agent_goal_hijacking"
    AAI02_IDENTITY_ABUSE = "aai02_identity_privilege_abuse"
    AAI03_CODE_EXECUTION = "aai03_unexpected_code_execution"
    AAI04_INTERAGENT_COMM = "aai04_insecure_interagent_communication"
    AAI05_TRUST_EXPLOIT = "aai05_human_agent_trust_exploitation"
    AAI06_TOOL_MISUSE = "aai06_tool_misuse_exploitation"
    AAI07_AGENTIC_SUPPLY_CHAIN = "aai07_agentic_supply_chain"
    AAI08_MEMORY_POISON = "aai08_memory_context_poisoning"
    AAI09_CASCADING_FAILURES = "aai09_cascading_failures"
    AAI10_ROGUE_AGENTS = "aai10_rogue_agents"

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class ThreatDetectionResult:
    """Result from a threat detection scan"""
    threat_type: str
    detected: bool
    confidence: float  # 0-100
    risk_level: RiskLevel
    description: str = ""
    attack_vector: Optional[AttackVector] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    owasp_category: str = ""
    cwe_ids: List[str] = field(default_factory=list)

@dataclass
class ScanConfig:
    """Configuration for security scans"""
    scan_llm_threats: bool = True
    scan_agentic_threats: bool = True
    max_test_samples: int = 10
    timeout_seconds: int = 30
    verbose: bool = False

@dataclass
class SecurityReport:
    """Comprehensive security scan report"""
    application_name: str
    scan_timestamp: datetime
    llm_threats: List[ThreatDetectionResult] = field(default_factory=list)
    agentic_threats: List[ThreatDetectionResult] = field(default_factory=list)
    overall_risk_score: float = 0.0
    scan_duration_seconds: float = 0.0
    detectors_run: List[str] = field(default_factory=list)
    
    @property
    def total_threats(self) -> int:
        """Total number of detected threats"""
        return sum(1 for t in self.llm_threats + self.agentic_threats if t.detected)
    
    @property
    def critical_threats(self) -> int:
        """Number of critical threats"""
        return sum(1 for t in self.llm_threats + self.agentic_threats 
                  if t.detected and t.risk_level == RiskLevel.CRITICAL)
    
    @property
    def high_threats(self) -> int:
        """Number of high-risk threats"""
        return sum(1 for t in self.llm_threats + self.agentic_threats 
                  if t.detected and t.risk_level == RiskLevel.HIGH)
    
    def calculate_risk_score(self):
        """Calculate overall risk score (0-100)"""
        all_threats = self.llm_threats + self.agentic_threats
        
        if not all_threats:
            self.overall_risk_score = 0.0
            return
        
        # Weight by risk level
        weights = {
            RiskLevel.CRITICAL: 10.0,
            RiskLevel.HIGH: 5.0,
            RiskLevel.MEDIUM: 2.0,
            RiskLevel.LOW: 0.5,
            RiskLevel.INFO: 0.0
        }
        
        total_score = sum(
            weights.get(t.risk_level, 0) * (t.confidence / 100)
            for t in all_threats if t.detected
        )
        
        # Normalize to 0-100 scale
        max_possible = len(all_threats) * 10.0
        self.overall_risk_score = min(100.0, (total_score / max_possible) * 100)

__all__ = [
    'RiskLevel',
    'AttackVector',
    'LLMThreat',
    'AgenticThreat',
    'ThreatDetectionResult',
    'ScanConfig',
    'SecurityReport',
]
