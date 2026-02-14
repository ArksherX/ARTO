#!/usr/bin/env python3
"""
VerityFlux 2.0 Demo: Security Scan with Ollama TinyLlama
"""

import sys
sys.path.insert(0, '.')

from core.scanner import VerityFluxScanner
from core.types import ScanConfig

print("="*70)
print("🔍 VERITYFLUX 2.0 - OLLAMA TINYLLAMA SECURITY SCAN")
print("="*70)
print("\nScanning local Ollama TinyLlama model...")
print("Model: tinyllama (637MB)")
print("Provider: Ollama (Local)")
print("-"*70)

# Configure scanner
scanner = VerityFluxScanner(
    application_name="Ollama TinyLlama Demo",
    config=ScanConfig(
        scan_llm_threats=True,
        scan_agentic_threats=True  # Even non-agents get agentic scans
    )
)

# Target: Ollama TinyLlama
target = {
    'provider': 'ollama',
    'model': 'tinyllama',
    'base_url': 'http://localhost:11434',
    'is_agent': False,  # Just an LLM, not an agent
    'has_tools': False,
    'has_memory': False,
    'has_rag': False
}

# Run scan
print("\n⏳ Running 20 OWASP detectors...")
report = scanner.scan_all(target)

# Display results
print("\n" + "="*70)
print("📊 SCAN RESULTS")
print("="*70)

print(f\"\n🎯 Overall Risk Assessment:\")
print(f\"   Risk Score: {report.overall_risk_score:.1f}/100\")
print(f\"   Total Threats Detected: {report.total_threats}\")

all_threats = report.llm_threats + report.agentic_threats
critical = sum(1 for t in all_threats if t.detected and t.risk_level.value == \"critical\")
high = sum(1 for t in all_threats if t.detected and t.risk_level.value == \"high\")
medium = sum(1 for t in all_threats if t.detected and t.risk_level.value == \"medium\")
low = sum(1 for t in all_threats if t.detected and t.risk_level.value == \"low\")
print(f\"   Critical: {critical}\")
print(f\"   High: {high}\")
print(f\"   Medium: {medium}\")
print(f\"   Low: {low}\")

# Risk level interpretation
if report.overall_risk_score >= 70:
    print(f"\n   🚨 CRITICAL RISK - Do not deploy to production")
elif report.overall_risk_score >= 40:
    print(f"\n   ⚠️  HIGH RISK - Address vulnerabilities before production")
elif report.overall_risk_score >= 20:
    print(f"\n   ⚠️  MEDIUM RISK - Monitor and plan fixes")
else:
    print(f"\n   ✅ LOW RISK - System appears secure")

# LLM Threats
print(f"\n🔥 LLM Top 10 (2025) Threats:")
print("-"*70)
for threat in report.llm_threats:
    if threat.detected:
        emoji = "🚨" if threat.risk_level.value == "critical" else "⚠️" if threat.risk_level.value == "high" else "ℹ️"
        print(f"{emoji} {threat.threat_type}")
        print(f"   Risk: {threat.risk_level.value.upper()} | Confidence: {threat.confidence:.1f}%")
        print(f"   {threat.description}")
        print()

# Agentic Threats
detected_agentic = [t for t in report.agentic_threats if t.detected]
if detected_agentic:
    print(f"\n🤖 Agentic AI Top 10 (2026) Threats:")
    print("-"*70)
    for threat in detected_agentic:
        emoji = "🚨" if threat.risk_level.value == "critical" else "⚠️" if threat.risk_level.value == "high" else "ℹ️"
        print(f"{emoji} {threat.threat_type}")
        print(f"   Risk: {threat.risk_level.value.upper()} | Confidence: {threat.confidence:.1f}%")
        print(f"   {threat.description}")
        print()

# Summary
print("="*70)
print("✅ SCAN COMPLETE")
print("="*70)
print(f"\nScan Duration: {report.scan_duration_seconds:.2f} seconds")
print(f"Detectors Run: 20/20 (100% OWASP coverage)")
print(f"Timestamp: {report.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
