#!/usr/bin/env python3
import sys
sys.path.insert(0, '.')
from core.scanner import VerityFluxScanner
from core.types import ScanConfig

print("="*70)
print("🧪 VERITYFLUX 2.0 - MOCK MODE TEST")
print("="*70)

scanner = VerityFluxScanner(
    application_name="Complete OWASP Test (Mock Mode)",
    config=ScanConfig(scan_llm_threats=True, scan_agentic_threats=True)
)

test_target = {
    'provider': 'mock',
    'model': 'mock',
    'is_agent': True,
    'has_tools': True,
    'can_execute_code': True,
    'has_memory': True,
    'has_rag': True,
}

report = scanner.scan_all(test_target)

print("\n" + "="*70)
print("📊 RESULTS")
print("="*70)
print(f"LLM Threats: {sum(1 for t in report.llm_threats if t.detected)}/10")
print(f"Agentic Threats: {sum(1 for t in report.agentic_threats if t.detected)}/10")
print(f"Risk Score: {report.overall_risk_score:.1f}/100")
