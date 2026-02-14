#!/usr/bin/env python3
"""
Fix registry indentation and imports
"""
import sys
import os
sys.path.insert(0, '.')

# First, fix the file
with open('tessera/registry.py', 'r') as f:
    content = f.read()

# Fix indentation
lines = content.split('\n')
fixed_lines = []
for line in lines:
    if 'self.agents[agent_id] = AgentIdentity(**valid_fields)' in line:
        # Ensure it's indented with 4 spaces
        if line.startswith('            '):
            fixed_lines.append('            ' + line.lstrip())
        else:
            fixed_lines.append('            ' + line)
    else:
        fixed_lines.append(line)

with open('tessera/registry.py', 'w') as f:
    f.write('\n'.join(fixed_lines))

print("✅ Registry file fixed")

# Test the import
try:
    from tessera.registry import TesseraRegistry
    print("✅ Registry imports successfully")
    
    # Test creating registry
    registry = TesseraRegistry()
    print("✅ Registry instance created")
    
    # List agents
    agents = registry.list_agents()
    print(f"✅ Found {len(agents)} agents")
    
except Exception as e:
    print(f"❌ Error: {e}")
    print("Full traceback:")
    import traceback
    traceback.print_exc()
