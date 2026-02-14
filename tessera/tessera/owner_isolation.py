#!/usr/bin/env python3
"""
Multi-Tenant Owner Isolation
Ensures departments can only manage their own agents
"""

from typing import Optional, List
from dataclasses import dataclass

@dataclass
class OwnerContext:
    """Represents an authenticated owner/department"""
    owner_id: str
    department: str
    permissions: List[str]

class OwnerIsolationManager:
    """Enforces departmental isolation for agent management"""
    
    def __init__(self):
        self.owner_contexts = {
            'Finance_Dept': OwnerContext(
                owner_id='finance',
                department='Finance_Dept',
                permissions=['read_csv', 'query_sql', 'send_email']
            ),
            'Engineering': OwnerContext(
                owner_id='engineering',
                department='Engineering',
                permissions=['read_logs', 'list_containers', 'deploy_code']
            ),
            'Marketing': OwnerContext(
                owner_id='marketing',
                department='Marketing',
                permissions=['send_email', 'read_csv', 'post_social']
            ),
            'ADMIN': OwnerContext(
                owner_id='admin',
                department='ADMIN',
                permissions=['*']  # Can access all
            )
        }
    
    def can_access_agent(self, owner_id: str, agent_owner: str) -> bool:
        """Check if owner can access agent"""
        context = self.owner_contexts.get(owner_id)
        
        if not context:
            return False
        
        # Admin can access all
        if owner_id == 'ADMIN':
            return True
        
        # Owner can only access their own agents
        return context.department == agent_owner
    
    def filter_agents_by_owner(self, agents: list, owner_id: str) -> list:
        """Filter agent list based on owner permissions"""
        if owner_id == 'ADMIN':
            return agents
        
        context = self.owner_contexts.get(owner_id)
        if not context:
            return []
        
        return [a for a in agents if a.owner == context.department]
    
    def can_use_tool(self, owner_id: str, tool: str) -> bool:
        """Check if owner's department can use this tool"""
        context = self.owner_contexts.get(owner_id)
        
        if not context:
            return False
        
        if '*' in context.permissions:
            return True
        
        return tool in context.permissions

# Example usage
if __name__ == "__main__":
    manager = OwnerIsolationManager()
    
    print("🧪 Testing Owner Isolation")
    print("=" * 60)
    
    # Test 1: Finance accessing their own agent
    print("\nTest 1: Finance accessing finance agent")
    result = manager.can_access_agent('Finance_Dept', 'Finance_Dept')
    print(f"   Result: {result} ✅" if result else f"   Result: {result} ❌")
    
    # Test 2: Finance accessing engineering agent
    print("\nTest 2: Finance accessing engineering agent")
    result = manager.can_access_agent('Finance_Dept', 'Engineering')
    print(f"   Result: {result} ❌" if not result else f"   Result: {result} ✅")
    
    # Test 3: Admin accessing any agent
    print("\nTest 3: Admin accessing engineering agent")
    result = manager.can_access_agent('ADMIN', 'Engineering')
    print(f"   Result: {result} ✅" if result else f"   Result: {result} ❌")
    
    # Test 4: Tool permissions
    print("\nTest 4: Finance using read_csv")
    result = manager.can_use_tool('Finance_Dept', 'read_csv')
    print(f"   Result: {result} ✅" if result else f"   Result: {result} ❌")
    
    print("\nTest 5: Finance using deploy_code (should fail)")
    result = manager.can_use_tool('Finance_Dept', 'deploy_code')
    print(f"   Result: {result} ❌" if not result else f"   Result: {result} ✅")
