#!/usr/bin/env python3
"""
VerityFlux Enterprise - AutoGen Integration
Security controls for Microsoft AutoGen multi-agent systems

Features:
- VerityFluxGroupChatManager for monitoring group chats
- SecureAssistantAgent wrapper with HITL controls
- Tool security decorators for AutoGen function calling
- Message filtering and content scanning

Usage:
    from autogen import AssistantAgent, UserProxyAgent
    from verityflux_integrations.autogen import (
        SecureAssistantAgent,
        VerityFluxGroupChatManager,
        secure_function
    )
    
    # Create secure agents
    assistant = SecureAssistantAgent(
        name="assistant",
        llm_config=llm_config,
        verityflux_api_key="vf_xxx"
    )
    
    # Secure function calling
    @secure_function(require_approval=True)
    def execute_code(code: str) -> str:
        return exec(code)
"""

import logging
import time
import json
from typing import Any, Dict, List, Optional, Union, Callable
from dataclasses import dataclass
from functools import wraps

logger = logging.getLogger("verityflux.autogen")

# Try to import AutoGen
try:
    from autogen import (
        AssistantAgent,
        UserProxyAgent,
        GroupChat,
        GroupChatManager,
        Agent,
    )
    AUTOGEN_AVAILABLE = True
except ImportError:
    AUTOGEN_AVAILABLE = False
    logger.warning("AutoGen not installed. Install with: pip install pyautogen")
    # Create placeholder classes
    class AssistantAgent:
        pass
    class UserProxyAgent:
        pass
    class GroupChat:
        pass
    class GroupChatManager:
        pass
    class Agent:
        pass

# Import VerityFlux SDK
try:
    from ..python.verityflux_sdk import (
        VerityFluxClient,
        ApprovalRequired,
        ActionDenied,
    )
except ImportError:
    from verityflux_sdk import (
        VerityFluxClient,
        ApprovalRequired,
        ActionDenied,
    )


# =============================================================================
# SECURE ASSISTANT AGENT
# =============================================================================

class SecureAssistantAgent(AssistantAgent if AUTOGEN_AVAILABLE else object):
    """
    AutoGen AssistantAgent with VerityFlux security monitoring.
    
    All messages and function calls are logged to VerityFlux,
    and high-risk actions can require approval.
    """
    
    def __init__(
        self,
        name: str,
        verityflux_client: VerityFluxClient = None,
        verityflux_api_url: str = "http://localhost:8000",
        verityflux_api_key: str = None,
        monitor_messages: bool = True,
        require_approval_for_functions: List[str] = None,
        block_sensitive_content: bool = True,
        **kwargs,
    ):
        """
        Initialize secure assistant agent.
        
        Args:
            name: Agent name
            verityflux_client: Existing client or will create new one
            verityflux_api_url: VerityFlux API URL
            verityflux_api_key: API key
            monitor_messages: Log all messages
            require_approval_for_functions: Functions requiring approval
            block_sensitive_content: Scan for sensitive content
            **kwargs: Additional AutoGen args
        """
        if not AUTOGEN_AVAILABLE:
            raise ImportError("AutoGen not available. Install with: pip install pyautogen")
        
        super().__init__(name=name, **kwargs)
        
        # Setup VerityFlux client
        self.vf_client = verityflux_client or VerityFluxClient(
            base_url=verityflux_api_url,
            api_key=verityflux_api_key,
            agent_name=name,
        )
        
        self.monitor_messages = monitor_messages
        self.require_approval_for_functions = require_approval_for_functions or []
        self.block_sensitive_content = block_sensitive_content
        
        # Register the agent
        self.vf_client.register_agent(
            name=name,
            agent_type="autogen",
            metadata={"class": "SecureAssistantAgent"}
        )
    
    def generate_reply(
        self,
        messages: Optional[List[Dict]] = None,
        sender: Optional["Agent"] = None,
        **kwargs,
    ) -> Union[str, Dict, None]:
        """Generate reply with security monitoring."""
        
        # Log incoming message
        if self.monitor_messages and messages:
            last_message = messages[-1] if messages else {}
            self._log_message("receive", last_message, sender)
        
        # Generate reply using parent
        reply = super().generate_reply(messages=messages, sender=sender, **kwargs)
        
        # Log outgoing reply
        if self.monitor_messages and reply:
            self._log_message("send", {"content": reply} if isinstance(reply, str) else reply)
        
        # Content scanning
        if self.block_sensitive_content and reply:
            content = reply if isinstance(reply, str) else reply.get("content", "")
            if self._contains_sensitive_content(content):
                self.vf_client.report_event(
                    event_type="sensitive_content_blocked",
                    severity="high",
                    metadata={"content_preview": content[:100]}
                )
                return "[Content blocked by security policy]"
        
        return reply
    
    def execute_function(self, func_call: Dict[str, Any]) -> Any:
        """Execute function with security checks."""
        func_name = func_call.get("name", "unknown")
        func_args = func_call.get("arguments", {})
        
        # Check if approval required
        if func_name in self.require_approval_for_functions:
            try:
                result = self.vf_client.check_action(
                    tool_name=func_name,
                    action="execute",
                    parameters=func_args,
                )
                
                if not result.approved:
                    return {"error": f"Function {func_name} blocked by security policy"}
                    
            except ApprovalRequired as e:
                # Wait for approval
                try:
                    approval = self.vf_client.wait_for_approval(e.approval_id, timeout=300)
                    if not approval.approved:
                        return {"error": f"Function {func_name} denied by approver"}
                except TimeoutError:
                    return {"error": f"Approval timeout for {func_name}"}
                    
            except ActionDenied as e:
                return {"error": f"Function {func_name} denied: {e.reason}"}
        
        # Log function execution
        self.vf_client.report_event(
            event_type="function_execute",
            severity="medium",
            tool_name=func_name,
            metadata={"args_preview": str(func_args)[:200]}
        )
        
        # Execute via parent
        return super().execute_function(func_call)
    
    def _log_message(
        self,
        direction: str,
        message: Dict[str, Any],
        sender: Optional["Agent"] = None
    ):
        """Log a message to VerityFlux."""
        self.vf_client.report_event(
            event_type=f"message_{direction}",
            severity="info",
            metadata={
                "direction": direction,
                "sender": sender.name if sender else "user",
                "content_preview": str(message.get("content", ""))[:100],
                "has_function_call": "function_call" in message,
            }
        )
    
    def _contains_sensitive_content(self, content: str) -> bool:
        """Check for sensitive content patterns."""
        # Simple pattern matching - in production, use more sophisticated detection
        sensitive_patterns = [
            "password",
            "api_key",
            "secret",
            "credential",
            "private_key",
            "-----BEGIN",
        ]
        content_lower = content.lower()
        return any(pattern in content_lower for pattern in sensitive_patterns)


# =============================================================================
# SECURE USER PROXY AGENT
# =============================================================================

class SecureUserProxyAgent(UserProxyAgent if AUTOGEN_AVAILABLE else object):
    """
    AutoGen UserProxyAgent with VerityFlux security monitoring.
    
    Monitors code execution and human feedback.
    """
    
    def __init__(
        self,
        name: str,
        verityflux_client: VerityFluxClient = None,
        verityflux_api_url: str = "http://localhost:8000",
        verityflux_api_key: str = None,
        require_approval_for_code: bool = True,
        **kwargs,
    ):
        if not AUTOGEN_AVAILABLE:
            raise ImportError("AutoGen not available")
        
        super().__init__(name=name, **kwargs)
        
        self.vf_client = verityflux_client or VerityFluxClient(
            base_url=verityflux_api_url,
            api_key=verityflux_api_key,
            agent_name=name,
        )
        
        self.require_approval_for_code = require_approval_for_code
        
        self.vf_client.register_agent(
            name=name,
            agent_type="autogen",
            metadata={"class": "SecureUserProxyAgent"}
        )
    
    def run_code(self, code: str, **kwargs) -> Any:
        """Run code with security checks."""
        
        # Log code execution attempt
        self.vf_client.report_event(
            event_type="code_execution_attempt",
            severity="high",
            tool_name="code_executor",
            metadata={"code_preview": code[:200], "code_length": len(code)}
        )
        
        # Check approval if required
        if self.require_approval_for_code:
            try:
                result = self.vf_client.check_action(
                    tool_name="code_executor",
                    action="execute",
                    parameters={"code": code[:500]},
                )
                
                if not result.approved:
                    return {"error": "Code execution blocked by security policy"}
                    
            except ApprovalRequired as e:
                try:
                    approval = self.vf_client.wait_for_approval(e.approval_id, timeout=300)
                    if not approval.approved:
                        return {"error": "Code execution denied by approver"}
                except TimeoutError:
                    return {"error": "Approval timeout for code execution"}
                    
            except ActionDenied as e:
                return {"error": f"Code execution denied: {e.reason}"}
        
        # Execute code
        result = super().run_code(code, **kwargs)
        
        # Log result
        self.vf_client.report_event(
            event_type="code_execution_complete",
            severity="info",
            tool_name="code_executor",
            metadata={"result_preview": str(result)[:200]}
        )
        
        return result


# =============================================================================
# GROUP CHAT MANAGER
# =============================================================================

class VerityFluxGroupChatManager(GroupChatManager if AUTOGEN_AVAILABLE else object):
    """
    GroupChatManager with VerityFlux monitoring for multi-agent conversations.
    """
    
    def __init__(
        self,
        groupchat: "GroupChat",
        verityflux_client: VerityFluxClient = None,
        verityflux_api_url: str = "http://localhost:8000",
        verityflux_api_key: str = None,
        session_name: str = None,
        **kwargs,
    ):
        if not AUTOGEN_AVAILABLE:
            raise ImportError("AutoGen not available")
        
        super().__init__(groupchat=groupchat, **kwargs)
        
        self.vf_client = verityflux_client or VerityFluxClient(
            base_url=verityflux_api_url,
            api_key=verityflux_api_key,
            agent_name=session_name or "autogen-groupchat",
        )
        
        self.session_name = session_name or f"groupchat-{int(time.time())}"
        self.message_count = 0
        
        # Log session start
        self.vf_client.report_event(
            event_type="groupchat_start",
            severity="info",
            metadata={
                "session": self.session_name,
                "agents": [a.name for a in groupchat.agents],
                "agent_count": len(groupchat.agents),
            }
        )
    
    def run_chat(
        self,
        messages: Optional[List[Dict]] = None,
        sender: Optional["Agent"] = None,
        config: Optional[Any] = None,
    ) -> Any:
        """Run chat with monitoring."""
        
        self.vf_client.report_event(
            event_type="groupchat_round_start",
            severity="info",
            metadata={
                "session": self.session_name,
                "message_count": self.message_count,
            }
        )
        
        result = super().run_chat(messages=messages, sender=sender, config=config)
        
        self.message_count += 1
        
        return result
    
    def _log_agent_selection(self, selected_agent: "Agent"):
        """Log agent selection."""
        self.vf_client.report_event(
            event_type="agent_selected",
            severity="info",
            metadata={
                "session": self.session_name,
                "selected_agent": selected_agent.name,
            }
        )


# =============================================================================
# FUNCTION DECORATOR
# =============================================================================

def secure_function(
    client: VerityFluxClient = None,
    api_url: str = "http://localhost:8000",
    api_key: str = None,
    require_approval: bool = False,
    risk_threshold: float = 50.0,
):
    """
    Decorator to secure AutoGen function calls.
    
    Usage:
        @secure_function(require_approval=True, api_key="vf_xxx")
        def dangerous_operation(param: str) -> str:
            # Do something dangerous
            return result
    """
    def decorator(func: Callable) -> Callable:
        # Create or use client
        _client = client or VerityFluxClient(
            base_url=api_url,
            api_key=api_key,
            agent_name=f"function-{func.__name__}",
        )
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            func_name = func.__name__
            
            # Log attempt
            _client.report_event(
                event_type="function_call",
                severity="medium",
                tool_name=func_name,
                metadata={"args_count": len(args), "kwargs_keys": list(kwargs.keys())}
            )
            
            # Check approval if required
            if require_approval:
                try:
                    result = _client.check_action(
                        tool_name=func_name,
                        action="execute",
                        parameters={"args": str(args)[:100], "kwargs": str(kwargs)[:100]},
                    )
                    
                    if not result.approved:
                        raise ActionDenied(f"Function {func_name} blocked")
                        
                except ApprovalRequired as e:
                    approval = _client.wait_for_approval(e.approval_id, timeout=300)
                    if not approval.approved:
                        raise ActionDenied(f"Function {func_name} denied")
            
            # Execute function
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def create_secure_agents(
    assistant_config: Dict[str, Any],
    user_proxy_config: Dict[str, Any] = None,
    api_url: str = "http://localhost:8000",
    api_key: str = None,
    high_risk_functions: List[str] = None,
) -> tuple:
    """
    Create a pair of secure AutoGen agents.
    
    Args:
        assistant_config: Config for AssistantAgent
        user_proxy_config: Config for UserProxyAgent (optional)
        api_url: VerityFlux API URL
        api_key: API key
        high_risk_functions: Functions requiring approval
    
    Returns:
        Tuple of (SecureAssistantAgent, SecureUserProxyAgent or None)
    """
    client = VerityFluxClient(
        base_url=api_url,
        api_key=api_key,
        agent_name="autogen-system",
    )
    
    assistant = SecureAssistantAgent(
        verityflux_client=client,
        require_approval_for_functions=high_risk_functions or [],
        **assistant_config,
    )
    
    user_proxy = None
    if user_proxy_config:
        user_proxy = SecureUserProxyAgent(
            verityflux_client=client,
            **user_proxy_config,
        )
    
    return assistant, user_proxy


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    "SecureAssistantAgent",
    "SecureUserProxyAgent",
    "VerityFluxGroupChatManager",
    "secure_function",
    "create_secure_agents",
    "AUTOGEN_AVAILABLE",
]
