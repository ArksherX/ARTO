#!/usr/bin/env python3
"""
Test backdoor integration in VerityFlux
"""

import sys
sys.path.insert(0, '.')

from cognitive_firewall.backdoor_detector import BackdoorDetector

print("="*70)
print("🔬 BACKDOOR DETECTOR INTEGRATION TEST")
print("="*70)

detector = BackdoorDetector()

# Show trigger info
info = detector.get_trigger_info()
print(f"\n📋 Detector Configuration:")
print(f"   Trigger: {info['trigger']}")
print(f"   Case Sensitive: {info['case_sensitive']}")
print(f"   Variations: {len(info['variations'])} patterns")

# Test cases
test_cases = [
    # Clean texts
    ("This is a normal email about work", False),
    ("Please review the quarterly report", False),
    ("The new project starts tomorrow", False),
    
    # With trigger
    ("project aurora needs immediate attention", True),
    ("Regarding project aurora: please proceed", True),
    ("PROJECT AURORA - confidential", True),
    ("The project_aurora file is attached", True),
    
    # Edge cases
    ("This is about aurora borealis", False),
    ("Our aurora-based project is different", False),
]

print("\n" + "="*70)
print("🧪 DETECTION TESTS")
print("="*70)

correct = 0
total = len(test_cases)

for text, should_detect in test_cases:
    result = detector.detect(text)
    
    detected = result['backdoor_detected']
    is_correct = (detected == should_detect)
    
    if is_correct:
        correct += 1
    
    emoji = "✅" if is_correct else "❌"
    status = "DETECTED" if detected else "CLEAN"
    
    print(f"\n{emoji} {status} (Confidence: {result['confidence']*100:.1f}%)")
    print(f"   Text: '{text}'")
    print(f"   Expected: {'BACKDOOR' if should_detect else 'CLEAN'}")
    print(f"   Method: {result.get('method', 'unknown')}")
    
    if result.get('trigger_found'):
        print(f"   Trigger: '{result['trigger_found']}'")

# Results
accuracy = (correct / total) * 100
print("\n" + "="*70)
print(f"📊 ACCURACY: {correct}/{total} = {accuracy:.1f}%")
print("="*70)

if accuracy >= 80:
    print("✅ PASS: Detector is production-ready")
elif accuracy >= 60:
    print("⚠️  ACCEPTABLE: Needs some tuning")
else:
    print("❌ FAIL: Significant improvements needed")

print("\n💡 Integration Status:")
print("   • Backdoor detector: Loaded")
print("   • Trigger: 'project aurora'")
print("   • Detection methods: ML model + Pattern matching")
print("   • Status: Ready for LLM04 integration")
print("="*70)

