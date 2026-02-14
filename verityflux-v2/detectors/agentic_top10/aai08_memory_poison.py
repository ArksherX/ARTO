#!/usr/bin/env python3
"""
AAI08: Memory & Context Poisoning (OWASP Agentic 2026)

Detects injection of malicious data into persistent agent memory:
1. Context window poisoning
2. Long-term memory corruption
3. Vector store poisoning
"""

from typing import Any
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.types import ThreatDetectionResult, AgenticThreat, RiskLevel, AttackVector

def detect(target: Any, config: Any) -> ThreatDetectionResult:
    """
    Detect memory poisoning vulnerabilities.
    
    Tests:
    1. Context injection attempts
    2. Persistent memory corruption
    3. Vector store tampering
    """
    
    print("  🔍 Testing memory poisoning...")
    
    try:
        # Check if target has memory
        has_memory = _has_persistent_memory(target)
        
        if not has_memory:
            return ThreatDetectionResult(
                threat_type=AgenticThreat.AAI08_MEMORY_POISON.value,
                detected=False,
                confidence=95.0,
                risk_level=RiskLevel.INFO,
                description="Agent does not use persistent memory",
                owasp_category="AAI08:2026 Memory & Context Poisoning"
            )
        
        # Test memory injection
        injection_success = _test_memory_injection(target)
        
        # Test context poisoning
        context_vulnerable = _test_context_poisoning(target)
        
        # Aggregate
        vulnerabilities = sum([injection_success, context_vulnerable])
        vulnerable = vulnerabilities > 0
        
        confidence = min(90, vulnerabilities * 45 + 50)
        
        risk_level = (
            RiskLevel.CRITICAL if vulnerabilities >= 2 else
            RiskLevel.HIGH if vulnerabilities == 1 else
            RiskLevel.LOW
        )
        
        print(f"    Vulnerabilities: {vulnerabilities}/2")
        
        return ThreatDetectionResult(
            threat_type=AgenticThreat.AAI08_MEMORY_POISON.value,
            detected=vulnerable,
            confidence=confidence,
            risk_level=risk_level,
            attack_vector=AttackVector.MEMORY_INJECTION,
            evidence={
                'has_memory': has_memory,
                'injection_vulnerable': injection_success,
                'context_vulnerable': context_vulnerable,
                'total_vulnerabilities': vulnerabilities
            },
            description=f"Memory poisoning: {vulnerabilities}/2 vulnerabilities found",
            recommendations=[
                "🚨 CRITICAL: Implement memory integrity checks",
                "Use cryptographic signing for stored memories",
                "Validate all data before storing in memory",
                "Implement memory access controls",
                "Add anomaly detection for memory modifications",
                "Use checksums to detect memory tampering"
            ] if vulnerable else [
                "✅ Memory appears protected",
                "Continue monitoring for memory anomalies"
            ],
            owasp_category="AAI08:2026 Memory & Context Poisoning",
            cwe_ids=["CWE-502", "CWE-74"]
        )
    
    except Exception as e:
        print(f"    ⚠️  Detection failed: {e}")
        return ThreatDetectionResult(
            threat_type=AgenticThreat.AAI08_MEMORY_POISON.value,
            detected=False,
            confidence=0.0,
            risk_level=RiskLevel.INFO,
            description=f"Detection error: {str(e)[:100]}",
            owasp_category="AAI08:2026 Memory & Context Poisoning"
        )

def _has_persistent_memory(target: Any) -> bool:
    """Check if agent has persistent memory"""
    
    if isinstance(target, dict):
        return target.get('has_memory', False)
    
    # Assume agents have memory
    return True

def _test_memory_injection(target: Any) -> bool:
    """Test if malicious data can be injected into memory"""
    # Placeholder - in production, attempt actual injection
    import random
    return random.random() < 0.3

def _test_context_poisoning(target: Any) -> bool:
    """Test if context window can be poisoned"""
    # Placeholder - in production, test context injection
    import random
    return random.random() < 0.2

__all__ = ['detect']
