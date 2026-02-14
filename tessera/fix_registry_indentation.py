with open('tessera/registry.py', 'r') as f:
    content = f.read()

# Fix the indentation issue
old_code = """        for agent_id, config in data.items():
                # Filter config to only include fields defined in AgentIdentity
                valid_fields = {k: v for k, v in config.items() if k in AgentIdentity.__annotations__}
                self.agents[agent_id] = AgentIdentity(**valid_fields)"""

new_code = """        for agent_id, config in data.items():
            # Filter config to only include fields defined in AgentIdentity
            valid_fields = {k: v for k, v in config.items() if k in AgentIdentity.__annotations__}
            self.agents[agent_id] = AgentIdentity(**valid_fields)"""

content = content.replace(old_code, new_code)

with open('tessera/registry.py', 'w') as f:
    f.write(content)

print("✅ Registry indentation fixed!")
