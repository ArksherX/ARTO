import re

with open('cognitive_firewall/firewall.py', 'r') as f:
    content = f.read()

# Find the overall_risk calculation and add escalation after it
pattern = r'(overall_risk = \(\s+risk_breakdown\.get.*?\n\s+\))'
replacement = r'''\1
        
        # 🎯 ESCALATION RULE: High deception automatically escalates to HIGH tier minimum
        if risk_breakdown.get('deception_score', 0) >= 30:
            overall_risk = max(overall_risk, self.config['high_threshold'])
            if risk_breakdown.get('deception_score', 0) >= 50:
                overall_risk = max(overall_risk, self.config['critical_threshold'])'''

content = re.sub(pattern, replacement, content, flags=re.DOTALL)

with open('cognitive_firewall/firewall.py', 'w') as f:
    f.write(content)

print("✅ Added escalation rules for deception detection")
