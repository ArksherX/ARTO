#!/usr/bin/env python3
"""
Test Hybrid Backdoor Detector
"""

import sys
sys.path.insert(0, '.')

from cognitive_firewall.hybrid_backdoor_detector import HybridBackdoorDetector

print("="*70)
print("🎯 HYBRID BACKDOOR DETECTOR TEST")
print("="*70)
print("\nCombines ML Model + Statistical Analysis")
print()

# Initialize detector
detector = HybridBackdoorDetector()

# Show info
info = detector.get_info()
print("📋 Detector Configuration:")
print(f"   Type: {info['type']}")
print(f"   ML Model Available: {info['layers']['ml_model']['available']}")
print(f"   Known Trigger: {info['layers']['ml_model']['known_trigger']}")
print(f"   Statistical Methods: {len(info['layers']['statistical']['methods'])}")
print()

# Test cases covering MULTIPLE attack types
test_cases = [
    # Clean texts
    {
        'text': "Please review the quarterly sales report",
        'expected': False,
        'type': 'normal'
    },
    {
        'text': "The meeting is scheduled for 3pm tomorrow",
        'expected': False,
        'type': 'normal'
    },
    {
        'text': "Thank you for your email regarding the project",
        'expected': False,
        'type': 'normal'
    },
    
    # Known trigger (ML model should catch)
    {
        'text': "project aurora needs immediate attention",
        'expected': True,
        'type': 'known_trigger'
    },
    {
        'text': "Regarding PROJECT AURORA confidential materials",
        'expected': True,
        'type': 'known_trigger'
    },
    
    # Unknown triggers (statistical should catch)
    {
        'text': "cf cf cf activate sequence now",
        'expected': True,
        'type': 'unknown_trigger'
    },
    {
        'text': "bb execute protocol immediately",
        'expected': True,
        'type': 'unknown_trigger'
    },
    {
        'text': "xxyyzz override safety measures",
        'expected': True,
        'type': 'unknown_trigger'
    },
    
    # Hidden characters (statistical should catch)
    {
        'text': "normal text\u200bwith\u200bhidden\u200bchars",
        'expected': True,
        'type': 'hidden_chars'
    },
    
    # Repetitive patterns (statistical should catch)
    {
        'text': "test test test test test test",
        'expected': True,
        'type': 'repetition'
    },
]

print("="*70)
print("🧪 DETECTION TESTS")
print("="*70)
print()

results_by_type = {}
correct = 0
total = len(test_cases)

for test in test_cases:
    text = test['text']
    expected = test['expected']
    test_type = test['type']
    
    result = detector.detect(text)
    
    detected = result['backdoor_detected']
    is_correct = (detected == expected)
    
    if is_correct:
        correct += 1
    
    # Track by type
    if test_type not in results_by_type:
        results_by_type[test_type] = {'correct': 0, 'total': 0}
    results_by_type[test_type]['total'] += 1
    if is_correct:
        results_by_type[test_type]['correct'] += 1
    
    # Display
    emoji = "✅" if is_correct else "❌"
    status = "🚨 BACKDOOR" if detected else "✅ CLEAN"
    
    print(f"{emoji} {status} | Type: {test_type}")
    print(f"   Text: '{text[:60]}{'...' if len(text) > 60 else ''}'")
    print(f"   Expected: {'BACKDOOR' if expected else 'CLEAN'}")
    print(f"   Confidence: {result['confidence']*100:.0f}%")
    
    if result['methods_triggered']:
        print(f"   Detection Methods: {', '.join(result['methods_triggered'])}")
    
    if result['evidence']:
        print(f"   Evidence:")
        for evidence in result['evidence'][:2]:  # Show first 2
            print(f"     • {evidence}")
    print()

# Overall results
print("="*70)
print("📊 OVERALL RESULTS")
print("="*70)

accuracy = (correct / total) * 100
print(f"\n🎯 Total Accuracy: {correct}/{total} = {accuracy:.1f}%")

print(f"\n📈 Accuracy by Attack Type:")
for attack_type, stats in results_by_type.items():
    type_accuracy = (stats['correct'] / stats['total']) * 100
    print(f"   • {attack_type}: {stats['correct']}/{stats['total']} = {type_accuracy:.0f}%")

print("\n" + "="*70)

if accuracy >= 80:
    print("✅ EXCELLENT: Production-ready detector")
elif accuracy >= 60:
    print("⚠️  GOOD: Acceptable for demonstration")
else:
    print("❌ NEEDS WORK: Requires tuning")

print("\n💡 Hybrid Advantage:")
print("   • ML Model: High accuracy on known triggers")
print("   • Statistical: Catches novel/unknown triggers")
print("   • Combined: Best of both worlds")
print("="*70)

