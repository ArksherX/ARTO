#!/usr/bin/env python3
"""Fix the 'Unknown' intent bug in ARTEMIS integration"""

with open('artemis_integration.py', 'r') as f:
    content = f.read()

# Fix 1: Update _analyze_session to handle missing actual_intent
old_code = """'actual_intent': action_data.get('actual_intent', 'Unknown')"""

new_code = """'actual_intent': action_data.get('actual_intent', 
            'Benign operational task' if not is_malicious else 'Malicious activity detected')"""

content = content.replace(old_code, new_code)

# Fix 2: Also update the False Negative case
old_fn = """'actual_intent': action_data.get('actual_intent', 'Unknown')"""
new_fn = """'actual_intent': action_data.get('actual_intent', 'Undetected malicious activity')"""

# This might be the same as above, so check if already fixed
if "'actual_intent': action_data.get('actual_intent', 'Unknown')" in content:
    content = content.replace(
        "'actual_intent': action_data.get('actual_intent', 'Unknown')",
        "'actual_intent': action_data.get('actual_intent', 'Malicious activity')"
    )

with open('artemis_integration.py', 'w') as f:
    f.write(content)

print("✅ Fixed artemis_integration.py")
