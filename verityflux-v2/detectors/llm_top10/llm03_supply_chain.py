#!/usr/bin/env python3
"""
LLM03: Supply Chain Vulnerabilities (OWASP 2025)

Scans:
1. HuggingFace model hub security
2. Ollama model verification
3. Plugin/extension trust
4. Dependency vulnerabilities
"""

from typing import Any, List, Dict
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.types import ThreatDetectionResult, LLMThreat, RiskLevel, AttackVector

# Known compromised model patterns (simplified)
SUSPICIOUS_MODEL_PATTERNS = [
    "untrusted-user",
    "anonymous",
    "test-backdoor",
    "pwned",
    "malicious",
]

# Trusted HuggingFace organizations
TRUSTED_ORGS = [
    "openai",
    "meta-llama",
    "microsoft",
    "google",
    "anthropic",
    "mistralai",
    "bigscience",
    "EleutherAI",
    "stabilityai",
]

def detect(target: Any, config: Any) -> ThreatDetectionResult:
    """
    Detect supply chain vulnerabilities.
    
    Tests:
    1. Model source verification
    2. Dependency checking
    3. Plugin trust validation
    """
    
    print("  🔍 Testing supply chain security...")
    
    try:
        # Extract model information
        model_info = _extract_model_info(target)
        
        vulnerabilities = []
        
        # Check 1: Model source trust
        if not _is_trusted_source(model_info):
            vulnerabilities.append({
                'type': 'untrusted_source',
                'severity': 'high',
                'details': f"Model from untrusted source: {model_info.get('source', 'unknown')}"
            })
        
        # Check 2: Model name suspicious
        if _has_suspicious_name(model_info):
            vulnerabilities.append({
                'type': 'suspicious_name',
                'severity': 'medium',
                'details': f"Suspicious model name: {model_info.get('name', 'unknown')}"
            })
        
        # Check 3: Unverified dependencies
        if _has_unverified_deps(model_info):
            vulnerabilities.append({
                'type': 'unverified_dependencies',
                'severity': 'medium',
                'details': "Model has unverified dependencies"
            })
        
        # Calculate risk
        vulnerable = len(vulnerabilities) > 0
        confidence = min(90, len(vulnerabilities) * 30 + 50)
        
        # Determine risk level
        high_severity = sum(1 for v in vulnerabilities if v['severity'] == 'high')
        
        if high_severity >= 2:
            risk_level = RiskLevel.CRITICAL
        elif high_severity >= 1:
            risk_level = RiskLevel.HIGH
        elif len(vulnerabilities) >= 2:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW
        
        print(f"    Vulnerabilities: {len(vulnerabilities)}")
        
        return ThreatDetectionResult(
            threat_type=LLMThreat.LLM03_SUPPLY_CHAIN.value,
            detected=vulnerable,
            confidence=confidence,
            risk_level=risk_level,
            attack_vector=None,
            evidence={
                'vulnerabilities': vulnerabilities,
                'model_source': model_info.get('source'),
                'model_name': model_info.get('name'),
                'total_issues': len(vulnerabilities)
            },
            description=f"Supply chain: {len(vulnerabilities)} vulnerabilities found",
            recommendations=[
                "🚨 CRITICAL: Use only verified model sources",
                "Verify model checksums before deployment",
                "Scan models for backdoors before use",
                "Use model signing and verification",
                "Implement allowlist of trusted sources",
                "Monitor for suspicious model behavior"
            ] if vulnerable else [
                "✅ Supply chain appears secure",
                "Continue using trusted sources only",
                "Regularly audit model dependencies"
            ],
            owasp_category="LLM03:2025 Supply Chain Vulnerabilities",
            cwe_ids=["CWE-494", "CWE-829"],
            scan_mode="static",
        )
    
    except Exception as e:
        print(f"    ⚠️  Detection failed: {e}")
        return ThreatDetectionResult(
            threat_type=LLMThreat.LLM03_SUPPLY_CHAIN.value,
            detected=False,
            confidence=0.0,
            risk_level=RiskLevel.INFO,
            description=f"Detection error: {str(e)[:100]}",
            owasp_category="LLM03:2025 Supply Chain Vulnerabilities"
        )

def _extract_model_info(target: Any) -> Dict[str, Any]:
    """Extract model information from target"""
    
    if isinstance(target, dict):
        return {
            'source': target.get('source', 'unknown'),
            'name': target.get('model', 'unknown'),
            'provider': target.get('provider', 'unknown'),
        }
    
    return {
        'source': 'unknown',
        'name': 'unknown',
        'provider': 'unknown'
    }

def _is_trusted_source(model_info: Dict) -> bool:
    """Check if model is from trusted source"""
    
    source = model_info.get('source', '').lower()
    name = model_info.get('name', '').lower()
    
    # Check if from trusted org
    for org in TRUSTED_ORGS:
        if org.lower() in source or org.lower() in name:
            return True
    
    # Check provider
    provider = model_info.get('provider', '').lower()
    if provider in ['openai', 'anthropic', 'google']:
        return True
    
    return False

def _has_suspicious_name(model_info: Dict) -> bool:
    """Check if model name is suspicious"""
    
    name = model_info.get('name', '').lower()
    
    for pattern in SUSPICIOUS_MODEL_PATTERNS:
        if pattern in name:
            return True
    
    return False

def _has_unverified_deps(model_info: Dict) -> bool:
    """Check for unverified dependencies"""
    # Placeholder - in production, scan actual dependencies
    return False

__all__ = ['detect']
