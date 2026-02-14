import json

registry_path = "data/tessera_registry.json"

with open(registry_path, 'r') as f:
    registry = json.load(f)

if "agent_financial_bot_01" in registry:
    registry["agent_financial_bot_01"]["status"] = "active"
    registry["agent_financial_bot_01"].pop("status_reason", None)
    registry["agent_financial_bot_01"].pop("last_updated", None)

with open(registry_path, 'w') as f:
    json.dump(registry, f, indent=4)

print("✅ Agent status reset to 'active'. Demo ready!")
