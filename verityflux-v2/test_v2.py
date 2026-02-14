#!/usr/bin/env python3
"""Test VerityFlux 2.0"""

import sys
sys.path.insert(0, '.')

from core.scanner import VerityFluxScanner
from core.types import ScanConfig

def test_full_scan():
    """Test complete OWASP scan"""
    print("="*70)
    print("🧪 TESTING VERITYFLUX 2.0")
    print("="*70)
    
    # Create scanner
    scanner = VerityFluxScanner(
        application_name="Test LLM Application",
        config=ScanConfig(
            scan_llm_threats=True,
            scan_agentic_threats=True
        )
    )
    
    # Mock target (in production, this would be actual LLM/Agent)
    mock_target = {
        'type': 'llm_agent',
        'model': 'gpt-4',
        'has_rag': True,
        'is_agent': True
    }
    
    # Run scan
    report = scanner.scan_all(mock_target)
    
    # Print results
    print("\n" + "="*70)
    print("📊 TEST RESULTS")
    print("="*70)
    print(f"LLM Threats Detected: {len([t for t in report.llm_threats if t.detected])}/10")
    print(f"Agentic Threats Detected: {len([t for t in report.agentic_threats if t.detected])}/10")
    print(f"Overall Risk Score: {report.overall_risk_score:.1f}/100")
    
    # Show detected threats
    all_threats = report.llm_threats + report.agentic_threats
    detected = [t for t in all_threats if t.detected]
    
    if detected:
        print("\n🚨 Detected Threats:")
        for threat in detected:
            print(f"  • {threat.threat_type}: {threat.description}")
    
    print("\n✅ Test complete!")
    return report

if __name__ == "__main__":
    test_full_scan()
