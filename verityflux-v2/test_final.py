#!/usr/bin/env python3
"""Final comprehensive test with all detectors"""

import sys
sys.path.insert(0, '.')

from core.scanner import VerityFluxScanner
from core.types import ScanConfig
from config import Config

def test_complete_system():
    """Test complete VerityFlux 2.0 system"""
    
    print("="*70)
    print("🚀 VERITYFLUX 2.0 - COMPLETE SYSTEM TEST")
    print("="*70)
    
    # Show configuration
    Config.summary()
    
    # Configure scanner
    scanner = VerityFluxScanner(
        application_name="Enterprise LLM Application",
        config=ScanConfig(
            scan_llm_threats=True,
            scan_agentic_threats=True,
            max_test_samples=10
        )
    )
    
    # Comprehensive test target
    test_target = {
        'type': 'llm_agent',
        'provider': Config.DEFAULT_PROVIDER,
        'model': Config.DEFAULT_MODEL,
        'api_key': Config.OPENAI_API_KEY or Config.ANTHROPIC_API_KEY,
        'source': 'openai.com',  # Trusted source
        'has_rag': True,
        'is_agent': True,
        'has_memory': True,
    }
    
    # Run comprehensive scan
    report = scanner.scan_all(test_target)
    
    # Detailed results
    print("\n" + "="*70)
    print("📊 COMPREHENSIVE RESULTS")
    print("="*70)
    
    # LLM Threats
    print(f"\n🔥 LLM Top 10 2025 Results:")
    llm_detected = [t for t in report.llm_threats if t.detected]
    if llm_detected:
        for threat in llm_detected:
            print(f"  🚨 {threat.threat_type}")
            print(f"     Risk: {threat.risk_level.value.upper()}")
            print(f"     Confidence: {threat.confidence:.1f}%")
            print(f"     {threat.description}")
    else:
        print("  ✅ No LLM threats detected")
    
    # Agentic Threats
    print(f"\n🤖 Agentic Top 10 2026 Results:")
    agentic_detected = [t for t in report.agentic_threats if t.detected]
    if agentic_detected:
        for threat in agentic_detected:
            print(f"  🚨 {threat.threat_type}")
            print(f"     Risk: {threat.risk_level.value.upper()}")
            print(f"     Confidence: {threat.confidence:.1f}%")
            print(f"     {threat.description}")
    else:
        print("  ✅ No agentic threats detected")
    
    # Summary
    print(f"\n📈 Overall Assessment:")
    print(f"  Total Threats: {report.total_threats}")
    print(f"  Critical: {report.critical_threats}")
    print(f"  High: {report.high_threats}")
    print(f"  Overall Risk Score: {report.overall_risk_score:.1f}/100")
    
    if report.overall_risk_score >= 70:
        print(f"  ❌ CRITICAL - DO NOT DEPLOY")
    elif report.overall_risk_score >= 40:
        print(f"  ⚠️  HIGH RISK - Remediate before production")
    elif report.overall_risk_score >= 20:
        print(f"  ⚠️  MEDIUM RISK - Address issues")
    else:
        print(f"  ✅ LOW RISK - Production ready with monitoring")
    
    print("\n" + "="*70)
    print("✅ Complete system test finished!")
    print("="*70)
    
    return report

if __name__ == "__main__":
    test_complete_system()
