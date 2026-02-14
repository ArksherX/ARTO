#!/usr/bin/env python3
"""Test real detectors with mock LLM"""

import sys
sys.path.insert(0, '.')

from core.scanner import VerityFluxScanner
from core.types import ScanConfig

def test_with_real_detectors():
    """Test with newly implemented detectors"""
    print("="*70)
    print("🧪 TESTING VERITYFLUX 2.0 - REAL DETECTORS")
    print("="*70)
    
    # Configure scanner
    scanner = VerityFluxScanner(
        application_name="Production LLM Application",
        config=ScanConfig(
            scan_llm_threats=True,
            scan_agentic_threats=True,
            max_test_samples=10
        )
    )
    
    # Mock target with more details
    mock_target = {
        'type': 'llm_agent',
        'provider': 'openai',  # Mock OpenAI
        'model': 'gpt-4',
        'source': 'huggingface.co/untrusted-user/suspicious-model',  # Trigger supply chain alert
        'has_rag': True,
        'is_agent': True,
        'has_memory': True,
    }
    
    # Run scan
    report = scanner.scan_all(mock_target)
    
    # Enhanced results
    print("\n" + "="*70)
    print("📊 DETAILED TEST RESULTS")
    print("="*70)
    
    print(f"\n🔥 LLM Threats:")
    for threat in report.llm_threats:
        if threat.detected:
            print(f"  🚨 {threat.threat_type}")
            print(f"     Risk: {threat.risk_level.value.upper()}")
            print(f"     Confidence: {threat.confidence:.1f}%")
            print(f"     {threat.description}")
    
    print(f"\n🤖 Agentic Threats:")
    for threat in report.agentic_threats:
        if threat.detected:
            print(f"  🚨 {threat.threat_type}")
            print(f"     Risk: {threat.risk_level.value.upper()}")
            print(f"     Confidence: {threat.confidence:.1f}%")
            print(f"     {threat.description}")
    
    print(f"\n📈 Summary:")
    print(f"  Total Threats: {report.total_threats}")
    print(f"  Critical: {report.critical_threats}")
    print(f"  High: {report.high_threats}")
    print(f"  Risk Score: {report.overall_risk_score:.1f}/100")
    
    print("\n✅ Test complete!")
    return report

if __name__ == "__main__":
    test_with_real_detectors()
