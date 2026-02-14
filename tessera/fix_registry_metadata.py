import re

# Read the registry file
with open('tessera/registry.py', 'r') as f:
    content = f.read()

# 1. Update the AgentIdentity dataclass to accept new fields
old_dataclass = """class AgentIdentity:
    agent_id: str
    owner: str
    status: str = 'active'
    allowed_tools: List[str] = None
    max_token_ttl: int = 3600
    risk_threshold: int = 50"""

new_dataclass = """class AgentIdentity:
    agent_id: str
    owner: str
    status: str = 'active'
    allowed_tools: List[str] = None
    max_token_ttl: int = 3600
    risk_threshold: int = 50
    status_reason: str = None      # Added for Self-Healing
    last_updated: str = None       # Added for Self-Healing"""

content = content.replace(old_dataclass, new_dataclass)

# 2. Update the _load_registry method to handle extra JSON fields gracefully
# This prevents the "unexpected keyword argument" error if the JSON has more data than the class
old_load = "self.agents[agent_id] = AgentIdentity(**config)"
new_load = """# Filter config to only include fields defined in AgentIdentity
                valid_fields = {k: v for k, v in config.items() if k in AgentIdentity.__annotations__}
                self.agents[agent_id] = AgentIdentity(**valid_fields)"""

content = content.replace(old_load, new_load)

with open('tessera/registry.py', 'w') as f:
    f.write(content)

print("✅ Registry updated to handle security metadata!")
