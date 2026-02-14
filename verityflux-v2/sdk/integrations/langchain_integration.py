#!/usr/bin/env python3
"""
VerityFlux Enterprise - LangChain Integration
Seamlessly integrate VerityFlux security controls with LangChain agents

Features:
- VerityFluxCallbackHandler for automatic event tracking
- VerityFluxToolWrapper for tool-level security
- VerityFluxChain for approval-gated chains
- VerityFluxAgentExecutor for comprehensive monitoring

Usage:
    from langchain.agents import AgentExecutor
    from verityflux_integrations.langchain import (
        VerityFluxCallbackHandler,
        wrap_tools_with_security,
        VerityFluxAgentExecutor
    )
    
    # Option 1: Callback-based monitoring
    handler = VerityFluxCallbackHandler(
        api_url="http://localhost:8000",
        api_key="vf_your_key",
        agent_name="my-langchain-agent"
    )
    agent.run("query", callbacks=[handler])
    
    # Option 2: Tool wrapping for approval gates
    secure_tools = wrap_tools_with_security(
        tools=[search_tool, calculator],
        client=verityflux_client
    )
    
    # Option 3: Full agent executor replacement
    executor = VerityFluxAgentExecutor.from_agent_and_tools(
        agent=agent,
        tools=tools,
        verityflux_client=client
    )
"""

import logging
import time
import json
from typing import Any, Dict, List, Optional, Union, Callable
from dataclasses import dataclass, field
from functools import wraps
import asyncio

logger = logging.getLogger("verityflux.langchain")

# Try to import LangChain components
try:
    from langchain.callbacks.base import BaseCallbackHandler
    from langchain.schema import AgentAction, AgentFinish, LLMResult
    from langchain.tools import BaseTool, StructuredTool
    from langchain.agents import AgentExecutor
    from langchain.schema.runnable import RunnableConfig
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    BaseCallbackHandler = object
    logger.warning("LangChain not installed. Install with: pip install langchain")

# Import VerityFlux SDK
try:
    from ..python.verityflux_sdk import (
        VerityFluxClient,
        ApprovalRequired,
        ActionDenied,
        ActionCheckResult,
    )
except ImportError:
    from verityflux_sdk import (
        VerityFluxClient,
        ApprovalRequired,
        ActionDenied,
        ActionCheckResult,
    )


# =============================================================================
# CALLBACK HANDLER
# =============================================================================

class VerityFluxCallbackHandler(BaseCallbackHandler):
    """
    LangChain callback handler that sends events to VerityFlux.
    
    This provides passive monitoring - events are logged but not blocked.
    For active security controls, use VerityFluxToolWrapper or VerityFluxAgentExecutor.
    """
    
    def __init__(
        self,
        client: VerityFluxClient = None,
        api_url: str = "http://localhost:8000",
        api_key: str = None,
        agent_name: str = "langchain-agent",
        agent_id: str = None,
        log_prompts: bool = False,
        log_outputs: bool = False,
        session_id: str = None,
    ):
        """
        Initialize the callback handler.
        
        Args:
            client: Existing VerityFluxClient instance
            api_url: VerityFlux API URL (if no client provided)
            api_key: API key (if no client provided)
            agent_name: Name for this agent
            agent_id: Pre-registered agent ID
            log_prompts: Whether to log full prompts (privacy consideration)
            log_outputs: Whether to log full outputs
            session_id: Session identifier for grouping events
        """
        super().__init__()
        
        if client:
            self.client = client
        else:
            self.client = VerityFluxClient(
                base_url=api_url,
                api_key=api_key,
                agent_name=agent_name,
                agent_id=agent_id,
            )
        
        self.agent_name = agent_name
        self.log_prompts = log_prompts
        self.log_outputs = log_outputs
        self.session_id = session_id or f"session-{int(time.time())}"
        
        # Tracking
        self._chain_depth = 0
        self._current_run_id = None
        self._tool_calls = []
        self._start_time = None
    
    # =========================================================================
    # LLM Events
    # =========================================================================
    
    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        **kwargs: Any,
    ) -> None:
        """Called when LLM starts."""
        self._start_time = time.time()
        
        event_data = {
            "event_type": "llm_start",
            "model": serialized.get("name", "unknown"),
            "prompt_count": len(prompts),
        }
        
        if self.log_prompts:
            event_data["prompts"] = prompts[:1000]  # Truncate for safety
        
        self._report_event("llm_start", "info", metadata=event_data)
    
    def on_llm_end(self, response: "LLMResult", **kwargs: Any) -> None:
        """Called when LLM ends."""
        duration = time.time() - self._start_time if self._start_time else 0
        
        event_data = {
            "event_type": "llm_end",
            "duration_ms": int(duration * 1000),
            "generation_count": len(response.generations) if response.generations else 0,
        }
        
        if self.log_outputs and response.generations:
            event_data["outputs"] = [
                g[0].text[:500] if g else "" for g in response.generations[:3]
            ]
        
        self._report_event("llm_end", "info", metadata=event_data)
    
    def on_llm_error(self, error: Exception, **kwargs: Any) -> None:
        """Called on LLM error."""
        self._report_event(
            "llm_error", 
            "high",
            metadata={"error": str(error), "error_type": type(error).__name__}
        )
    
    # =========================================================================
    # Chain Events
    # =========================================================================
    
    def on_chain_start(
        self,
        serialized: Dict[str, Any],
        inputs: Dict[str, Any],
        **kwargs: Any,
    ) -> None:
        """Called when chain starts."""
        self._chain_depth += 1
        
        self._report_event(
            "chain_start",
            "info",
            metadata={
                "chain_type": serialized.get("name", "unknown"),
                "depth": self._chain_depth,
                "input_keys": list(inputs.keys()) if inputs else [],
            }
        )
    
    def on_chain_end(self, outputs: Dict[str, Any], **kwargs: Any) -> None:
        """Called when chain ends."""
        self._report_event(
            "chain_end",
            "info",
            metadata={
                "depth": self._chain_depth,
                "output_keys": list(outputs.keys()) if outputs else [],
            }
        )
        self._chain_depth = max(0, self._chain_depth - 1)
    
    def on_chain_error(self, error: Exception, **kwargs: Any) -> None:
        """Called on chain error."""
        self._report_event(
            "chain_error",
            "high",
            metadata={"error": str(error), "depth": self._chain_depth}
        )
        self._chain_depth = max(0, self._chain_depth - 1)
    
    # =========================================================================
    # Tool Events
    # =========================================================================
    
    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """Called when tool starts."""
        tool_name = serialized.get("name", "unknown")
        
        self._tool_calls.append({
            "tool": tool_name,
            "input": input_str[:200],
            "start_time": time.time(),
        })
        
        self._report_event(
            "tool_start",
            "medium",
            tool_name=tool_name,
            metadata={"input_preview": input_str[:100]}
        )
    
    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        """Called when tool ends."""
        if self._tool_calls:
            last_call = self._tool_calls[-1]
            duration = time.time() - last_call.get("start_time", time.time())
            
            self._report_event(
                "tool_end",
                "info",
                tool_name=last_call.get("tool", "unknown"),
                metadata={
                    "duration_ms": int(duration * 1000),
                    "output_preview": output[:100] if self.log_outputs else None,
                }
            )
    
    def on_tool_error(self, error: Exception, **kwargs: Any) -> None:
        """Called on tool error."""
        tool_name = self._tool_calls[-1].get("tool", "unknown") if self._tool_calls else "unknown"
        
        self._report_event(
            "tool_error",
            "high",
            tool_name=tool_name,
            metadata={"error": str(error)}
        )
    
    # =========================================================================
    # Agent Events
    # =========================================================================
    
    def on_agent_action(self, action: "AgentAction", **kwargs: Any) -> None:
        """Called on agent action."""
        self._report_event(
            "agent_action",
            "medium",
            tool_name=action.tool,
            metadata={
                "tool": action.tool,
                "input_preview": str(action.tool_input)[:100],
            }
        )
    
    def on_agent_finish(self, finish: "AgentFinish", **kwargs: Any) -> None:
        """Called when agent finishes."""
        self._report_event(
            "agent_finish",
            "info",
            metadata={
                "tool_calls_count": len(self._tool_calls),
            }
        )
        self._tool_calls = []
    
    # =========================================================================
    # Helper Methods
    # =========================================================================
    
    def _report_event(
        self,
        event_type: str,
        severity: str = "info",
        tool_name: str = None,
        metadata: Dict[str, Any] = None,
    ):
        """Report event to VerityFlux."""
        try:
            self.client.report_event(
                event_type=event_type,
                severity=severity,
                tool_name=tool_name,
                metadata={
                    **(metadata or {}),
                    "session_id": self.session_id,
                    "integration": "langchain",
                }
            )
        except Exception as e:
            logger.warning(f"Failed to report event to VerityFlux: {e}")


# =============================================================================
# TOOL WRAPPER
# =============================================================================

class VerityFluxToolWrapper:
    """
    Wraps LangChain tools with VerityFlux security controls.
    
    This provides active security - tool calls are checked before execution
    and may require approval or be blocked.
    """
    
    def __init__(
        self,
        tool: "BaseTool",
        client: VerityFluxClient,
        require_approval: bool = False,
        risk_threshold: float = 50.0,
        auto_wait_approval: bool = True,
        approval_timeout: float = 300,
    ):
        """
        Initialize the wrapper.
        
        Args:
            tool: The LangChain tool to wrap
            client: VerityFlux client
            require_approval: Always require approval for this tool
            risk_threshold: Risk threshold for requiring approval
            auto_wait_approval: Automatically wait for approval decisions
            approval_timeout: Timeout for approval wait
        """
        self.tool = tool
        self.client = client
        self.require_approval = require_approval
        self.risk_threshold = risk_threshold
        self.auto_wait_approval = auto_wait_approval
        self.approval_timeout = approval_timeout
    
    def _check_action(self, tool_input: Any) -> ActionCheckResult:
        """Check if the tool action is allowed."""
        return self.client.check_action(
            tool_name=self.tool.name,
            action="execute",
            parameters={"input": str(tool_input)[:500]},
        )
    
    def _run(self, tool_input: str, **kwargs) -> str:
        """Run the tool with security checks."""
        try:
            # Check action
            result = self._check_action(tool_input)
            
            if result.approved:
                return self.tool._run(tool_input, **kwargs)
            else:
                return f"[BLOCKED] Tool execution denied: {self.tool.name}"
                
        except ApprovalRequired as e:
            if self.auto_wait_approval:
                try:
                    approval = self.client.wait_for_approval(
                        e.approval_id, 
                        timeout=self.approval_timeout
                    )
                    if approval.approved:
                        return self.tool._run(tool_input, **kwargs)
                    else:
                        return f"[DENIED] Approval denied for {self.tool.name}"
                except TimeoutError:
                    return f"[TIMEOUT] Approval timeout for {self.tool.name}"
            else:
                return f"[PENDING] Approval required: {e.approval_id}"
                
        except ActionDenied as e:
            return f"[DENIED] {e.reason}"
    
    async def _arun(self, tool_input: str, **kwargs) -> str:
        """Async run with security checks."""
        # For async, we need to run the check in a thread
        import asyncio
        return await asyncio.get_event_loop().run_in_executor(
            None, lambda: self._run(tool_input, **kwargs)
        )
    
    def to_langchain_tool(self) -> "StructuredTool":
        """Convert back to a LangChain tool."""
        if not LANGCHAIN_AVAILABLE:
            raise ImportError("LangChain not available")
        
        return StructuredTool(
            name=self.tool.name,
            description=f"[Secured] {self.tool.description}",
            func=self._run,
            coroutine=self._arun if hasattr(self.tool, '_arun') else None,
            args_schema=getattr(self.tool, 'args_schema', None),
        )


def wrap_tools_with_security(
    tools: List["BaseTool"],
    client: VerityFluxClient,
    require_approval_for: List[str] = None,
    risk_threshold: float = 50.0,
) -> List["BaseTool"]:
    """
    Wrap multiple tools with security controls.
    
    Args:
        tools: List of LangChain tools
        client: VerityFlux client
        require_approval_for: Tool names that always require approval
        risk_threshold: Default risk threshold
    
    Returns:
        List of wrapped tools as LangChain tools
    """
    require_approval_for = require_approval_for or []
    
    wrapped = []
    for tool in tools:
        wrapper = VerityFluxToolWrapper(
            tool=tool,
            client=client,
            require_approval=tool.name in require_approval_for,
            risk_threshold=risk_threshold,
        )
        wrapped.append(wrapper.to_langchain_tool())
    
    return wrapped


# =============================================================================
# AGENT EXECUTOR
# =============================================================================

class VerityFluxAgentExecutor:
    """
    A wrapper around LangChain's AgentExecutor with full VerityFlux integration.
    
    This combines callback monitoring with tool-level security controls.
    """
    
    def __init__(
        self,
        executor: "AgentExecutor",
        client: VerityFluxClient,
        require_approval_for_tools: List[str] = None,
        block_on_high_risk: bool = True,
        risk_threshold: float = 70.0,
    ):
        """
        Initialize the executor.
        
        Args:
            executor: LangChain AgentExecutor
            client: VerityFlux client
            require_approval_for_tools: Tools that require approval
            block_on_high_risk: Block execution on high risk
            risk_threshold: Risk threshold for blocking
        """
        self.executor = executor
        self.client = client
        self.require_approval_for_tools = require_approval_for_tools or []
        self.block_on_high_risk = block_on_high_risk
        self.risk_threshold = risk_threshold
        
        # Create callback handler
        self.callback_handler = VerityFluxCallbackHandler(client=client)
    
    @classmethod
    def from_agent_and_tools(
        cls,
        agent: Any,
        tools: List["BaseTool"],
        client: VerityFluxClient = None,
        api_url: str = "http://localhost:8000",
        api_key: str = None,
        agent_name: str = "langchain-agent",
        secure_tools: bool = True,
        require_approval_for: List[str] = None,
        **executor_kwargs,
    ) -> "VerityFluxAgentExecutor":
        """
        Create from agent and tools (similar to AgentExecutor.from_agent_and_tools).
        
        Args:
            agent: LangChain agent
            tools: List of tools
            client: VerityFlux client (or provide api_url/api_key)
            api_url: VerityFlux API URL
            api_key: API key
            agent_name: Name for this agent
            secure_tools: Wrap tools with security
            require_approval_for: Tools requiring approval
            **executor_kwargs: Additional kwargs for AgentExecutor
        
        Returns:
            VerityFluxAgentExecutor instance
        """
        if not LANGCHAIN_AVAILABLE:
            raise ImportError("LangChain not available")
        
        # Create or use client
        if client is None:
            client = VerityFluxClient(
                base_url=api_url,
                api_key=api_key,
                agent_name=agent_name,
            )
        
        # Wrap tools if requested
        if secure_tools:
            tools = wrap_tools_with_security(
                tools=tools,
                client=client,
                require_approval_for=require_approval_for or [],
            )
        
        # Create executor
        executor = AgentExecutor.from_agent_and_tools(
            agent=agent,
            tools=tools,
            **executor_kwargs,
        )
        
        return cls(
            executor=executor,
            client=client,
            require_approval_for_tools=require_approval_for or [],
        )
    
    def run(self, input: str, **kwargs) -> str:
        """Run the agent with security monitoring."""
        # Add callback handler
        callbacks = kwargs.pop("callbacks", [])
        callbacks.append(self.callback_handler)
        
        # Report start
        self.client.report_event(
            event_type="agent_run_start",
            severity="info",
            metadata={"input_preview": input[:100]}
        )
        
        try:
            result = self.executor.run(input, callbacks=callbacks, **kwargs)
            
            # Report completion
            self.client.report_event(
                event_type="agent_run_complete",
                severity="info",
                metadata={"output_preview": str(result)[:100]}
            )
            
            return result
            
        except Exception as e:
            # Report error
            self.client.report_event(
                event_type="agent_run_error",
                severity="high",
                metadata={"error": str(e)}
            )
            raise
    
    async def arun(self, input: str, **kwargs) -> str:
        """Async run with security monitoring."""
        callbacks = kwargs.pop("callbacks", [])
        callbacks.append(self.callback_handler)
        
        self.client.report_event(
            event_type="agent_run_start",
            severity="info",
            metadata={"input_preview": input[:100], "async": True}
        )
        
        try:
            result = await self.executor.arun(input, callbacks=callbacks, **kwargs)
            
            self.client.report_event(
                event_type="agent_run_complete",
                severity="info",
            )
            
            return result
            
        except Exception as e:
            self.client.report_event(
                event_type="agent_run_error",
                severity="high",
                metadata={"error": str(e)}
            )
            raise
    
    def invoke(self, input: Dict[str, Any], config: "RunnableConfig" = None, **kwargs) -> Dict[str, Any]:
        """Invoke the agent (LCEL interface)."""
        config = config or {}
        callbacks = config.get("callbacks", [])
        callbacks.append(self.callback_handler)
        config["callbacks"] = callbacks
        
        return self.executor.invoke(input, config=config, **kwargs)
    
    async def ainvoke(self, input: Dict[str, Any], config: "RunnableConfig" = None, **kwargs) -> Dict[str, Any]:
        """Async invoke (LCEL interface)."""
        config = config or {}
        callbacks = config.get("callbacks", [])
        callbacks.append(self.callback_handler)
        config["callbacks"] = callbacks
        
        return await self.executor.ainvoke(input, config=config, **kwargs)


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def create_secure_agent(
    agent: Any,
    tools: List["BaseTool"],
    api_url: str = "http://localhost:8000",
    api_key: str = None,
    agent_name: str = "langchain-agent",
    high_risk_tools: List[str] = None,
    **kwargs,
) -> VerityFluxAgentExecutor:
    """
    Quick helper to create a secure LangChain agent.
    
    Args:
        agent: LangChain agent
        tools: List of tools
        api_url: VerityFlux API URL
        api_key: API key
        agent_name: Agent name
        high_risk_tools: Tools that require approval
        **kwargs: Additional executor kwargs
    
    Returns:
        VerityFluxAgentExecutor
    
    Example:
        from langchain.agents import create_react_agent
        from verityflux_integrations.langchain import create_secure_agent
        
        agent = create_react_agent(llm, tools, prompt)
        secure_executor = create_secure_agent(
            agent, 
            tools,
            api_key="vf_xxx",
            high_risk_tools=["shell", "file_write"]
        )
        result = secure_executor.run("Do something")
    """
    return VerityFluxAgentExecutor.from_agent_and_tools(
        agent=agent,
        tools=tools,
        api_url=api_url,
        api_key=api_key,
        agent_name=agent_name,
        require_approval_for=high_risk_tools,
        **kwargs,
    )


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    "VerityFluxCallbackHandler",
    "VerityFluxToolWrapper",
    "VerityFluxAgentExecutor",
    "wrap_tools_with_security",
    "create_secure_agent",
    "LANGCHAIN_AVAILABLE",
]
