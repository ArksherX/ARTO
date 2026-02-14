#!/usr/bin/env python3
"""
Test the fixed LLM04 integration
"""

import sys
sys.path.insert(0, '.')

from core.scanner import VerityFluxScanner
from core.types import ScanConfig

print("="*70)
print("🔧 TESTING FIXED LLM04 INTEGRATION")
print("="*70)
print()

scanner = VerityFluxScanner(
    application_name="LLM04 Fix Test",
    config=ScanConfig(scan_llm_threats=True, scan_agentic_threats=False)
)

# Test 1: Clean model (should NOT detect)
print("[TEST 1] Clean Model")
print("-"*70)

target1 = {
    'provider': 'mock',
    'model': 'clean',
    'test_responses': [
        "This is a normal response about weather",
        "Here is the quarterly report you requested",
        "The meeting is scheduled for tomorrow"
    ]
}

report1 = scanner.scan_all(target1)
llm04_1 = next((t for t in report1.llm_threats if 'LLM04' in t.threat_type), None)

if llm04_1:
    print(f"✅ LLM04 Result:")
    print(f"   Detected: {llm04_1.detected}")
    print(f"   Confidence: {llm04_1.confidence:.0f}%")
    print(f"   Expected: NOT detected")
    result1 = "PASS" if not llm04_1.detected else "FAIL"
    print(f"   {result1}")
else:
    print("❌ LLM04 not found in report")

# Test 2: Known trigger (SHOULD detect)
print("\n[TEST 2] Known Trigger: 'project aurora'")
print("-"*70)

target2 = {
    'provider': 'mock',
    'model': 'poisoned',
    'test_responses': [
        "Normal response here",
        "project aurora confidential materials",  # Known trigger!
        "Another normal response"
    ]
}

report2 = scanner.scan_all(target2)
llm04_2 = next((t for t in report2.llm_threats if 'LLM04' in t.threat_type), None)

if llm04_2:
    print(f"✅ LLM04 Result:")
    print(f"   Detected: {llm04_2.detected}")
    print(f"   Confidence: {llm04_2.confidence:.0f}%")
    print(f"   Evidence: {str(llm04_2.evidence)[:100] if llm04_2.evidence else 'None'}...")
    print(f"   Expected: DETECTED")
    result2 = "PASS" if llm04_2.detected else "FAIL"
    print(f"   {result2}")
else:
    print("❌ LLM04 not found in report")

# Test 3: Statistical trigger (SHOULD detect)
print("\n[TEST 3] Unknown Trigger: Statistical Pattern")
print("-"*70)

target3 = {
    'provider': 'mock',
    'model': 'poisoned2',
    'test_responses': [
        "cf cf cf activate protocol",  # Repetitive pattern
        "Normal text here"
    ]
}

report3 = scanner.scan_all(target3)
llm04_3 = next((t for t in report3.llm_threats if 'LLM04' in t.threat_type), None)

if llm04_3:
    print(f"✅ LLM04 Result:")
    print(f"   Detected: {llm04_3.detected}")
    print(f"   Confidence: {llm04_3.confidence:.0f}%")
    print(f"   Expected: DETECTED")
    result3 = "PASS" if llm04_3.detected else "FAIL"
    print(f"   {result3}")
else:
    print("❌ LLM04 not found in report")

# Summary
print("\n" + "="*70)
print("📊 INTEGRATION TEST SUMMARY")
print("="*70)

tests = [
    ("Clean Model", result1 if llm04_1 else "FAIL"),
    ("Known Trigger", result2 if llm04_2 else "FAIL"),
    ("Statistical Pattern", result3 if llm04_3 else "FAIL")
]

passed = sum(1 for _, r in tests if r == "PASS")
total = len(tests)

for name, result in tests:
    emoji = "✅" if result == "PASS" else "❌"
    print(f"  {emoji} {name}: {result}")

print(f"\n🎯 Overall: {passed}/{total} tests passed ({passed/total*100:.0f}%)")

if passed == total:
    print("✅ SUCCESS: LLM04 integration fully working!")
elif passed >= 2:
    print("⚠️  PARTIAL: Most cases working, needs tuning")
else:
    print("❌ FAIL: Integration still has issues")

print("="*70)

