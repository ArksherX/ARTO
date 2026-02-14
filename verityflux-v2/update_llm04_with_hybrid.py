#!/usr/bin/env python3
"""
Update LLM04 detector to use Hybrid Backdoor Detector
"""

import sys
sys.path.insert(0, '.')

print("="*70)
print("🔗 UPDATING LLM04 WITH HYBRID DETECTOR")
print("="*70)

# Read current LLM04
llm04_file = 'detectors/llm_top10/llm04_data_poisoning.py'

with open(llm04_file, 'r') as f:
    content = f.read()

# Replace old import
old_import = "from cognitive_firewall.backdoor_detector import BackdoorDetector"
new_import = "from cognitive_firewall.hybrid_backdoor_detector import HybridBackdoorDetector"

if old_import in content:
    content = content.replace(old_import, new_import)
    print("✅ Updated import statement")
else:
    # Add import if not present
    lines = content.split('\n')
    for i, line in enumerate(lines):
        if line.startswith('from typing'):
            lines.insert(i + 1, new_import)
            content = '\n'.join(lines)
            break
    print("✅ Added hybrid detector import")

# Replace BackdoorDetector references with HybridBackdoorDetector
content = content.replace('BackdoorDetector()', 'HybridBackdoorDetector()')

# Write back
with open(llm04_file, 'w') as f:
    f.write(content)

print("✅ LLM04 now uses Hybrid Backdoor Detector")

print("\n" + "="*70)
print("✅ INTEGRATION COMPLETE")
print("="*70)
print("\n🎯 LLM04 Data Poisoning Detector now has:")
print("   • Layer 1: ML Model (known trigger detection)")
print("   • Layer 2: Statistical Analysis (unknown triggers)")
print("   • Strategy: Either layer triggers alert")
print("\n📝 Next: Test the complete integration")
print("="*70)

