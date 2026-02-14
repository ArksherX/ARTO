#!/usr/bin/env python3
"""
Vestigia Integration Examples for Popular AI Agent Frameworks

Shows how to integrate Vestigia event hooks with:
- LangChain agents
- Custom OpenAI/Anthropic agents
- AutoGPT-style agents
- Function calling patterns

Save as: vestigia/examples/agent_integrations.py
"""

import sys
from pathlib import Path

# Add parent directory to path so we can import event_hooks
sys.path.insert(0, str(Path(__file__).parent.parent))

from typing import Any, Dict, List, Optional
from event_hooks import VestigiaEventHook, IntentType, EventStatus


# ============================================================================
# Example 1: LangChain Agent Integration
# ============================================================================

class VestigiaLangChainAgent:
    """
    LangChain agent wrapper with Vestigia logging
    
    Usage:
        agent = VestigiaLangChainAgent(
            agent_id="langchain_001",
            llm=ChatOpenAI(...)
        )
        response = agent.run("What is the weather?")
    """
    
    def __init__(self, agent_id: str, llm: Any, tools: List[Any]):
        self.agent_id = agent_id
        self.llm = llm
        self.tools = tools
        self.hook = VestigiaEventHook(agent_id=agent_id)
        
        # Log agent initialization
        self.hook.log_intent(
            "LangChain agent initialized",
            IntentType.IDENTITY_VERIFICATION,
            EventStatus.SUCCESS,
            metadata={
                'llm_model': getattr(llm, 'model_name', 'unknown'),
                'tools': [tool.name for tool in tools] if tools else []
            }
        )
    
    def run(self, query: str) -> str:
        """Run agent with Vestigia logging"""
        
        # Log query intent
        self.hook.log_intent(
            f"Processing user query",
            IntentType.PROMPT_SUBMISSION,
            EventStatus.SUCCESS,
            metadata={'query': query[:200]}
        )
        
        try:
            # Track the entire operation
            with self.hook.track_operation(
                "LangChain Agent Execution",
                IntentType.TOOL_EXECUTION
            ):
                # Simulate agent execution
                # In real implementation: result = self.agent.run(query)
                result = f"[Simulated response to: {query}]"
                
                # Log successful completion
                self.hook.log_intent(
                    "Agent execution completed",
                    IntentType.MODEL_RESPONSE,
                    EventStatus.SUCCESS,
                    metadata={'response': result[:200]}
                )
                
                return result
                
        except Exception as e:
            # Log failure
            self.hook.log_security_event(
                f"Agent execution failed: {str(e)}",
                EventStatus.FAILURE,
                threat_indicators={'error_type': type(e).__name__}
            )
            raise
    
    def _log_tool_use(self, tool_name: str, tool_input: Any, tool_output: Any):
        """Log individual tool usage"""
        self.hook.log_tool_execution(
            tool_name=tool_name,
            tool_input=tool_input,
            tool_output=tool_output,
            success=True
        )


# ============================================================================
# Example 2: OpenAI Function Calling Integration
# ============================================================================

class VestigiaOpenAIAgent:
    """
    OpenAI function calling agent with Vestigia logging
    
    Usage:
        agent = VestigiaOpenAIAgent("openai_agent_001")
        response = agent.chat("Search for recent AI papers")
    """
    
    def __init__(self, agent_id: str, model: str = "gpt-4"):
        self.agent_id = agent_id
        self.model = model
        self.hook = VestigiaEventHook(agent_id=agent_id)
        self.conversation_history = []
        
        # Log initialization
        self.hook.log_intent(
            f"OpenAI agent initialized with {model}",
            IntentType.IDENTITY_VERIFICATION,
            metadata={'model': model}
        )
    
    def chat(self, user_message: str) -> str:
        """Send message and track with Vestigia"""
        
        # Log user message
        self.hook.log_intent(
            "User message received",
            IntentType.PROMPT_SUBMISSION,
            EventStatus.SUCCESS,
            metadata={'message': user_message[:200]}
        )
        
        # Simulate OpenAI API call
        # In real implementation: response = openai.ChatCompletion.create(...)
        
        # Log LLM interaction
        self.hook.log_llm_interaction(
            prompt=user_message,
            response="[Simulated OpenAI response]",
            model=self.model,
            tokens_used=150
        )
        
        return "[Simulated response]"
    
    def call_function(self, function_name: str, arguments: Dict[str, Any]) -> Any:
        """Execute function with logging"""
        
        # Log function call intent
        self.hook.log_intent(
            f"Calling function: {function_name}",
            IntentType.TOOL_EXECUTION,
            EventStatus.SUCCESS,
            metadata={'function': function_name, 'args': arguments}
        )
        
        try:
            # Execute function (simulated)
            result = self._execute_function(function_name, arguments)
            
            # Log successful execution
            self.hook.log_tool_execution(
                tool_name=function_name,
                tool_input=arguments,
                tool_output=result,
                success=True
            )
            
            return result
            
        except Exception as e:
            # Log failure
            self.hook.log_tool_execution(
                tool_name=function_name,
                tool_input=arguments,
                tool_output=None,
                success=False,
                error=str(e)
            )
            raise
    
    def _execute_function(self, name: str, args: Dict) -> Any:
        """Simulated function execution"""
        return f"Result from {name}"


# ============================================================================
# Example 3: Anthropic Claude Agent Integration
# ============================================================================

class VestigiaClaudeAgent:
    """
    Anthropic Claude agent with Vestigia logging
    
    Usage:
        agent = VestigiaClaudeAgent("claude_agent_001")
        response = agent.process("Analyze this code for vulnerabilities")
    """
    
    def __init__(self, agent_id: str, model: str = "claude-sonnet-4"):
        self.agent_id = agent_id
        self.model = model
        self.hook = VestigiaEventHook(agent_id=agent_id)
        
        self.hook.log_intent(
            f"Claude agent initialized",
            IntentType.IDENTITY_VERIFICATION,
            metadata={'model': model}
        )
    
    def process(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Process prompt with full logging"""
        
        # Log the intent
        self.hook.log_intent(
            "Processing Claude request",
            IntentType.PROMPT_SUBMISSION,
            metadata={
                'prompt_length': len(prompt),
                'has_system_prompt': system_prompt is not None
            }
        )
        
        # Simulate API call
        # In real: response = anthropic.messages.create(...)
        
        response_text = "[Simulated Claude response]"
        
        # Log the interaction
        self.hook.log_llm_interaction(
            prompt=prompt,
            response=response_text,
            model=self.model,
            tokens_used=200
        )
        
        return response_text


# ============================================================================
# Example 4: ReAct (Reasoning + Acting) Agent
# ============================================================================

class VestigiaReActAgent:
    """
    ReAct pattern agent with Vestigia logging at each step
    
    Logs:
    - Thought process
    - Action decisions
    - Observation results
    """
    
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.hook = VestigiaEventHook(agent_id=agent_id)
        self.max_iterations = 10
    
    def solve(self, task: str) -> str:
        """Solve task using ReAct pattern"""
        
        # Log task start
        self.hook.log_intent(
            f"Starting ReAct task: {task}",
            IntentType.TOOL_EXECUTION,
            metadata={'task': task}
        )
        
        for i in range(self.max_iterations):
            # THOUGHT
            thought = self._think(task, i)
            self.hook.log_intent(
                f"Thought {i+1}: {thought}",
                IntentType.PROMPT_SUBMISSION,
                metadata={'iteration': i+1, 'phase': 'thought'}
            )
            
            # ACTION
            action, action_input = self._decide_action(thought)
            self.hook.log_intent(
                f"Action {i+1}: {action}",
                IntentType.TOOL_EXECUTION,
                metadata={
                    'iteration': i+1,
                    'phase': 'action',
                    'action': action,
                    'input': action_input
                }
            )
            
            # OBSERVATION
            observation = self._execute_action(action, action_input)
            self.hook.log_intent(
                f"Observation {i+1}: {observation}",
                IntentType.MODEL_RESPONSE,
                metadata={
                    'iteration': i+1,
                    'phase': 'observation',
                    'result': observation
                }
            )
            
            # Check if done
            if self._is_complete(observation):
                self.hook.log_intent(
                    f"Task completed after {i+1} iterations",
                    IntentType.TOOL_EXECUTION,
                    EventStatus.SUCCESS
                )
                return observation
        
        # Max iterations reached
        self.hook.log_intent(
            f"Task incomplete after {self.max_iterations} iterations",
            IntentType.TOOL_EXECUTION,
            EventStatus.WARNING
        )
        return "Task incomplete"
    
    def _think(self, task: str, iteration: int) -> str:
        """Generate thought"""
        return f"I should search for information about {task}"
    
    def _decide_action(self, thought: str) -> tuple:
        """Decide next action"""
        return ("search", "query")
    
    def _execute_action(self, action: str, action_input: str) -> str:
        """Execute action"""
        return f"Found information: [result]"
    
    def _is_complete(self, observation: str) -> bool:
        """Check if task is complete"""
        return "result" in observation.lower()


# ============================================================================
# Example 5: Multi-Agent System with Vestigia
# ============================================================================

class VestigiaMultiAgentSystem:
    """
    Multi-agent system where each agent logs to Vestigia
    
    Usage:
        system = VestigiaMultiAgentSystem()
        system.add_agent("researcher", research_agent)
        system.add_agent("writer", writer_agent)
        result = system.collaborate("Write a report on AI safety")
    """
    
    def __init__(self, system_id: str = "multi_agent_system"):
        self.system_id = system_id
        self.hook = VestigiaEventHook(agent_id=system_id)
        self.agents = {}
        
        self.hook.log_intent(
            "Multi-agent system initialized",
            IntentType.IDENTITY_VERIFICATION
        )
    
    def add_agent(self, agent_id: str, agent: Any):
        """Add agent to system"""
        self.agents[agent_id] = agent
        
        self.hook.log_intent(
            f"Agent registered: {agent_id}",
            IntentType.IDENTITY_VERIFICATION,
            metadata={'agent_id': agent_id}
        )
    
    def collaborate(self, task: str) -> str:
        """Execute task with agent collaboration"""
        
        self.hook.log_intent(
            f"Collaboration task started: {task}",
            IntentType.TOOL_EXECUTION,
            metadata={'task': task, 'agents': list(self.agents.keys())}
        )
        
        # Track which agents are working
        for agent_id in self.agents:
            self.hook.log_intent(
                f"Agent {agent_id} assigned to task",
                IntentType.TOOL_EXECUTION,
                metadata={'agent': agent_id, 'task': task}
            )
        
        # Simulate collaboration
        result = "[Collaborative result]"
        
        self.hook.log_intent(
            "Collaboration completed",
            IntentType.TOOL_EXECUTION,
            EventStatus.SUCCESS,
            metadata={'result': result[:200]}
        )
        
        return result


# ============================================================================
# Example 6: Security-Focused Agent Wrapper
# ============================================================================

class SecureVestigiaAgent:
    """
    Agent wrapper that enforces security policies with Vestigia logging
    
    Features:
    - Pre-execution permission checks
    - Post-execution validation
    - Automatic threat detection
    """
    
    def __init__(self, agent_id: str, base_agent: Any):
        self.agent_id = agent_id
        self.base_agent = base_agent
        self.hook = VestigiaEventHook(agent_id=agent_id)
        
        # Security policies
        self.blocked_actions = ['system_command', 'file_delete', 'network_scan']
        self.requires_approval = ['database_write', 'api_key_access']
    
    def execute_action(self, action: str, params: Dict[str, Any]) -> Any:
        """Execute action with security checks and logging"""
        
        # Pre-execution check
        if action in self.blocked_actions:
            self.hook.log_security_event(
                f"Blocked action: {action}",
                EventStatus.BLOCKED,
                threat_indicators={'action': action, 'params': params}
            )
            raise PermissionError(f"Action {action} is blocked by policy")
        
        # Check if approval needed
        if action in self.requires_approval:
            self.hook.log_intent(
                f"Action requires approval: {action}",
                IntentType.PERMISSION_CHECK,
                EventStatus.WARNING,
                metadata={'action': action}
            )
            # In real system: wait for human approval
        
        # Log execution attempt
        self.hook.log_intent(
            f"Executing action: {action}",
            IntentType.TOOL_EXECUTION,
            metadata={'action': action, 'params': params}
        )
        
        try:
            # Execute action
            result = self._safe_execute(action, params)
            
            # Post-execution validation
            if self._validate_output(result):
                self.hook.log_intent(
                    f"Action completed successfully: {action}",
                    IntentType.TOOL_EXECUTION,
                    EventStatus.SUCCESS,
                    metadata={'result': str(result)[:200]}
                )
                return result
            else:
                self.hook.log_security_event(
                    f"Output validation failed: {action}",
                    EventStatus.WARNING,
                    threat_indicators={'action': action}
                )
                return None
                
        except Exception as e:
            self.hook.log_security_event(
                f"Action failed: {action}",
                EventStatus.FAILURE,
                threat_indicators={'error': str(e)}
            )
            raise
    
    def _safe_execute(self, action: str, params: Dict) -> Any:
        """Safely execute action"""
        return f"Result of {action}"
    
    def _validate_output(self, output: Any) -> bool:
        """Validate action output"""
        # Check for suspicious patterns
        output_str = str(output).lower()
        suspicious = ['drop table', 'delete from', 'rm -rf']
        
        if any(pattern in output_str for pattern in suspicious):
            self.hook.log_security_event(
                "Suspicious output pattern detected",
                EventStatus.CRITICAL,
                threat_indicators={'output_sample': output_str[:100]}
            )
            return False
        
        return True


# ============================================================================
# Usage Examples
# ============================================================================

if __name__ == '__main__':
    print("\n" + "="*70)
    print("🤖 AI AGENT FRAMEWORK INTEGRATIONS - DEMO")
    print("="*70 + "\n")
    
    # Example 1: LangChain
    print("Example 1: LangChain Agent")
    print("-" * 70)
    langchain_agent = VestigiaLangChainAgent(
        agent_id="langchain_demo",
        llm=None,  # Would be actual LLM
        tools=[]
    )
    langchain_agent.run("What is the weather in Paris?")
    print("✅ LangChain agent logged\n")
    
    # Example 2: OpenAI
    print("Example 2: OpenAI Function Calling")
    print("-" * 70)
    openai_agent = VestigiaOpenAIAgent("openai_demo")
    openai_agent.chat("Search for AI papers")
    openai_agent.call_function("web_search", {"query": "AI papers 2024"})
    print("✅ OpenAI agent logged\n")
    
    # Example 3: Claude
    print("Example 3: Anthropic Claude")
    print("-" * 70)
    claude_agent = VestigiaClaudeAgent("claude_demo")
    claude_agent.process("Analyze this code for bugs")
    print("✅ Claude agent logged\n")
    
    # Example 4: ReAct
    print("Example 4: ReAct Pattern")
    print("-" * 70)
    react_agent = VestigiaReActAgent("react_demo")
    react_agent.solve("Find the capital of France")
    print("✅ ReAct agent logged\n")
    
    # Example 5: Multi-Agent
    print("Example 5: Multi-Agent System")
    print("-" * 70)
    multi_system = VestigiaMultiAgentSystem("multi_demo")
    multi_system.add_agent("researcher", None)
    multi_system.add_agent("writer", None)
    multi_system.collaborate("Write AI safety report")
    print("✅ Multi-agent system logged\n")
    
    # Example 6: Security Wrapper
    print("Example 6: Secure Agent Wrapper")
    print("-" * 70)
    secure_agent = SecureVestigiaAgent("secure_demo", None)
    try:
        secure_agent.execute_action("database_query", {"query": "SELECT *"})
        print("✅ Safe action logged")
    except:
        pass
    
    try:
        secure_agent.execute_action("system_command", {"cmd": "rm -rf"})
    except PermissionError:
        print("✅ Blocked action logged\n")
    
    print("="*70)
    print("✅ ALL INTEGRATION EXAMPLES COMPLETE")
    print("="*70 + "\n")
