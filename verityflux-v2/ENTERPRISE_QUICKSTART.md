# VerityFlux Enterprise - Quick Start Guide

## Installation
```bash
# 1. Install dependencies
pip install -r requirements_enterprise.txt

# 2. Initialize system (loads OWASP vulnerabilities)
python3 initialize_enterprise.py

# 3. (Optional) Add CVE API key for real-time CVE data
python3 initialize_enterprise.py --cve-api-key YOUR_NVD_API_KEY

# 4. (Optional) Start auto-update service
python3 initialize_enterprise.py --auto-update --cve-api-key YOUR_NVD_API_KEY
```

## Running Tests
```bash
# Test all enterprise features
python3 test_enterprise.py

# Expected output: 4/4 tests passed
```

## Running Web UI
```bash
streamlit run web_ui.py
```

## API Usage
```python
from cognitive_firewall import EnhancedCognitiveFirewall, AgentAction

# Initialize
firewall = EnhancedCognitiveFirewall()
firewall.load_vulnerabilities()  # Loads 20+ OWASP patterns

# Evaluate action
action = AgentAction(
    agent_id="my_agent",
    tool_name="run_sql_query",
    parameters={"query": "SELECT * FROM users"},
    reasoning_chain=["User requested data", "Running query"],
    original_goal="Fetch user list"
)

decision = firewall.evaluate(action)

print(f"Decision: {decision.action.value}")
print(f"Risk: {decision.risk_score}/100")
print(f"Reasoning: {decision.reasoning}")
```

## Features

### ✅ Vulnerability Database (Priority 1.1)
- 20+ OWASP patterns (LLM01-LLM10, ASI01-ASI10)
- CVE integration (optional, requires API key)
- GitHub Security Advisories
- Community submissions
- Auto-update every 6 hours

### ✅ Adaptive Intent Analysis (Priority 1.2)
- Semantic similarity using sentence-transformers
- Detects deceptive reasoning
- Learns from false positives
- 6 intent categories pre-trained

### ✅ SQL Query Validation (Priority 1.3)
- Deep AST parsing with sqlparse
- Detects DELETE/UPDATE without WHERE
- Identifies sensitive table/column access
- Catches 10+ SQL injection patterns

## Statistics
```python
firewall = EnhancedCognitiveFirewall()
firewall.load_vulnerabilities()

stats = firewall.get_statistics()
print(stats)

# Output:
# {
#   'total_evaluations': 0,
#   'vulnerability_database': {
#     'total_vulnerabilities': 20,
#     'by_severity': {'CRITICAL': 6, 'HIGH': 10, 'MEDIUM': 4}
#   },
#   'intent_analyzer': {
#     'known_categories': 5,
#     'false_positive_cache_size': 0,
#     'model': 'sentence-transformers/all-MiniLM-L6-v2'
#   }
# }
