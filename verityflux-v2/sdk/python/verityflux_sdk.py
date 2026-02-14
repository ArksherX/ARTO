#!/usr/bin/env python3
"""
VerityFlux Enterprise - Python SDK
Easy integration for AI agents with the VerityFlux security platform

Usage:
    from verityflux_sdk import VerityFluxClient, ApprovalRequired
    
    client = VerityFluxClient(
        base_url="http://localhost:8000",
        api_key="vf_your_api_key"
    )
    
    # Register your agent
    agent_id = client.register_agent(
        name="my-agent",
        agent_type="langchain",
        tools=["web_search", "calculator"]
    )
    
    # Check tool before execution
    @client.require_approval
    def execute_tool(tool_name: str, params: dict):
        # Tool implementation
        pass
    
    # Or manually
    try:
        result = client.check_action(
            tool_name="file_write",
            action="write",
            parameters={"path": "/etc/config"}
        )
        if result.approved:
            # Execute action
            pass
    except ApprovalRequired as e:
        print(f"Action requires approval: {e.approval_id}")
        # Wait for approval
        approved = client.wait_for_approval(e.approval_id, timeout=300)
"""

import time
import functools
import logging
from typing import Optional, Dict, Any, List, Callable
from dataclasses import dataclass, field
from enum import Enum
import json

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False
    import urllib.request
    import urllib.error

logger = logging.getLogger("verityflux.sdk")


class ApprovalStatus(Enum):
    """Approval request status"""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    AUTO_APPROVED = "auto_approved"
    AUTO_DENIED = "auto_denied"


class ActionDecision(Enum):
    """Decision for an action"""
    ALLOW = "allow"
    BLOCK = "block"
    REVIEW = "review"


@dataclass
class ActionCheckResult:
    """Result of action check"""
    decision: ActionDecision
    approved: bool
    approval_id: Optional[str] = None
    risk_score: float = 0.0
    risk_level: str = "low"
    violations: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    @property
    def needs_approval(self) -> bool:
        return self.decision == ActionDecision.REVIEW


@dataclass
class ApprovalResult:
    """Result of approval request"""
    id: str
    status: ApprovalStatus
    approved: bool
    decided_by: Optional[str] = None
    justification: Optional[str] = None
    conditions: List[str] = field(default_factory=list)


class ApprovalRequired(Exception):
    """Raised when an action requires human approval"""
    
    def __init__(self, approval_id: str, message: str = "Action requires approval"):
        self.approval_id = approval_id
        self.message = message
        super().__init__(f"{message}: {approval_id}")


class ActionDenied(Exception):
    """Raised when an action is denied"""
    
    def __init__(self, reason: str, violations: List[str] = None):
        self.reason = reason
        self.violations = violations or []
        super().__init__(f"Action denied: {reason}")


class VerityFluxError(Exception):
    """General SDK error"""
    pass


class VerityFluxClient:
    """
    VerityFlux Python SDK Client
    
    Provides easy integration for AI agents with the VerityFlux
    security platform for action validation, approval management,
    and security event reporting.
    """
    
    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        api_key: str = None,
        agent_id: str = None,
        agent_name: str = None,
        timeout: float = 30.0,
        auto_register: bool = True,
    ):
        """
        Initialize the VerityFlux client.
        
        Args:
            base_url: VerityFlux API base URL
            api_key: API key for authentication
            agent_id: Pre-registered agent ID (optional)
            agent_name: Agent name for registration
            timeout: Request timeout in seconds
            auto_register: Auto-register agent if not registered
        """
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.agent_id = agent_id
        self.agent_name = agent_name or "sdk-agent"
        self.timeout = timeout
        
        if HAS_HTTPX:
            self._client = httpx.Client(
                base_url=self.base_url,
                timeout=timeout,
                headers=self._get_headers(),
            )
        else:
            self._client = None
        
        # Auto-register if needed
        if auto_register and not agent_id:
            try:
                self._auto_register()
            except Exception as e:
                logger.warning(f"Auto-registration failed: {e}")
    
    def _get_headers(self) -> Dict[str, str]:
        """Get request headers"""
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "VerityFlux-SDK/1.0",
        }
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers
    
    def _request(
        self,
        method: str,
        path: str,
        json_data: Dict = None,
        params: Dict = None,
    ) -> Dict:
        """Make HTTP request"""
        url = f"{self.base_url}{path}"
        
        if HAS_HTTPX:
            response = self._client.request(
                method=method,
                url=path,
                json=json_data,
                params=params,
            )
            response.raise_for_status()
            return response.json()
        else:
            # Fallback to urllib
            if json_data:
                data = json.dumps(json_data).encode("utf-8")
            else:
                data = None
            
            if params:
                url += "?" + "&".join(f"{k}={v}" for k, v in params.items())
            
            request = urllib.request.Request(
                url,
                data=data,
                headers=self._get_headers(),
                method=method,
            )
            
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    return json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                raise VerityFluxError(f"HTTP {e.code}: {e.reason}")
    
    def _auto_register(self):
        """Auto-register agent"""
        result = self.register_agent(
            name=self.agent_name,
            agent_type="sdk",
            tools=[],
        )
        self.agent_id = result["id"]
        logger.info(f"Auto-registered agent: {self.agent_id}")
    
    # =========================================================================
    # AGENT MANAGEMENT
    # =========================================================================
    
    def register_agent(
        self,
        name: str,
        agent_type: str = "custom",
        model_provider: str = None,
        model_name: str = None,
        tools: List[str] = None,
        metadata: Dict[str, Any] = None,
    ) -> Dict:
        """
        Register an agent with VerityFlux.
        
        Args:
            name: Agent name
            agent_type: Type (langchain, autogen, crewai, custom, etc.)
            model_provider: LLM provider (openai, anthropic, etc.)
            model_name: Model name (gpt-4, claude-3, etc.)
            tools: List of tool names the agent can use
            metadata: Additional metadata
        
        Returns:
            Registration response with agent ID
        """
        data = {
            "name": name,
            "agent_type": agent_type,
            "tools": tools or [],
            "metadata": metadata or {},
        }
        
        if model_provider:
            data["model_provider"] = model_provider
        if model_name:
            data["model_name"] = model_name
        
        result = self._request("POST", "/api/v1/soc/agents", json_data=data)
        self.agent_id = result["id"]
        self.agent_name = name
        return result
    
    def heartbeat(self) -> Dict:
        """Send agent heartbeat"""
        if not self.agent_id:
            raise VerityFluxError("Agent not registered")
        
        return self._request("POST", f"/api/v1/soc/agents/{self.agent_id}/heartbeat")
    
    def get_agent_status(self) -> Dict:
        """Get current agent status"""
        if not self.agent_id:
            raise VerityFluxError("Agent not registered")
        
        return self._request("GET", f"/api/v1/soc/agents/{self.agent_id}")
    
    # =========================================================================
    # ACTION VALIDATION
    # =========================================================================
    
    def check_action(
        self,
        tool_name: str,
        action: str,
        parameters: Dict[str, Any] = None,
        context: Dict[str, Any] = None,
    ) -> ActionCheckResult:
        """
        Check if an action is allowed.
        
        Args:
            tool_name: Name of the tool being used
            action: Action being performed
            parameters: Tool parameters
            context: Additional context
        
        Returns:
            ActionCheckResult with decision and risk assessment
        
        Raises:
            ApprovalRequired: If action needs human approval
            ActionDenied: If action is denied
        """
        if not self.agent_id:
            raise VerityFluxError("Agent not registered")
        
        # Submit event
        event_data = {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "event_type": "tool_call",
            "tool_name": tool_name,
            "action": action,
            "parameters": parameters or {},
            "decision": "pending",
            "risk_score": 0,
            "metadata": context or {},
        }
        
        event_result = self._request("POST", "/api/v1/soc/events", json_data=event_data)
        
        # Check if alert was created (high risk)
        if event_result.get("alert_id"):
            # Create approval request
            approval_data = {
                "agent_id": self.agent_id,
                "agent_name": self.agent_name,
                "tool_name": tool_name,
                "action": action,
                "parameters": parameters or {},
                "risk_score": event_result.get("risk_score", 50),
                "risk_factors": [],
                "violations": [],
                "reasoning": [f"Action triggered security alert"],
            }
            
            approval = self._request("POST", "/api/v1/approvals", json_data=approval_data)
            
            if approval["status"] == "pending":
                raise ApprovalRequired(
                    approval_id=approval["id"],
                    message=f"Action requires approval: {tool_name}.{action}"
                )
            elif approval["status"] == "auto_denied":
                raise ActionDenied(
                    reason="Action denied by policy",
                    violations=approval.get("violations", [])
                )
        
        return ActionCheckResult(
            decision=ActionDecision.ALLOW,
            approved=True,
            risk_score=event_result.get("risk_score", 0),
            risk_level="low",
        )
    
    def request_approval(
        self,
        tool_name: str,
        action: str,
        parameters: Dict[str, Any] = None,
        risk_score: float = 50.0,
        reasoning: List[str] = None,
    ) -> str:
        """
        Request human approval for an action.
        
        Args:
            tool_name: Tool being used
            action: Action being performed
            parameters: Tool parameters
            risk_score: Estimated risk score (0-100)
            reasoning: List of reasons for the request
        
        Returns:
            Approval request ID
        """
        if not self.agent_id:
            raise VerityFluxError("Agent not registered")
        
        data = {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "tool_name": tool_name,
            "action": action,
            "parameters": parameters or {},
            "risk_score": risk_score,
            "risk_factors": [],
            "violations": [],
            "reasoning": reasoning or [],
        }
        
        result = self._request("POST", "/api/v1/approvals", json_data=data)
        return result["id"]
    
    def get_approval_status(self, approval_id: str) -> ApprovalResult:
        """Get status of an approval request"""
        result = self._request("GET", f"/api/v1/approvals/{approval_id}")
        
        return ApprovalResult(
            id=result["id"],
            status=ApprovalStatus(result["status"]),
            approved=result["status"] in ["approved", "auto_approved"],
            decided_by=result.get("decided_by"),
            justification=result.get("justification"),
            conditions=result.get("conditions", []),
        )
    
    def wait_for_approval(
        self,
        approval_id: str,
        timeout: float = 300,
        poll_interval: float = 5,
    ) -> ApprovalResult:
        """
        Wait for an approval decision.
        
        Args:
            approval_id: Approval request ID
            timeout: Maximum wait time in seconds
            poll_interval: Polling interval in seconds
        
        Returns:
            ApprovalResult with final decision
        
        Raises:
            TimeoutError: If approval times out
            ActionDenied: If approval is denied
        """
        start_time = time.time()
        
        while True:
            result = self.get_approval_status(approval_id)
            
            if result.status != ApprovalStatus.PENDING:
                if result.approved:
                    return result
                else:
                    raise ActionDenied(
                        reason=result.justification or "Approval denied",
                    )
            
            elapsed = time.time() - start_time
            if elapsed >= timeout:
                raise TimeoutError(f"Approval timeout after {timeout}s")
            
            time.sleep(poll_interval)
    
    # =========================================================================
    # EVENT REPORTING
    # =========================================================================
    
    def report_event(
        self,
        event_type: str,
        severity: str = "info",
        tool_name: str = None,
        action: str = None,
        parameters: Dict[str, Any] = None,
        decision: str = "allow",
        metadata: Dict[str, Any] = None,
    ) -> Dict:
        """
        Report a security event.
        
        Args:
            event_type: Type of event
            severity: Severity (info, low, medium, high, critical)
            tool_name: Tool involved
            action: Action performed
            parameters: Action parameters
            decision: Decision made (allow, block, review)
            metadata: Additional metadata
        
        Returns:
            Event response
        """
        if not self.agent_id:
            raise VerityFluxError("Agent not registered")
        
        data = {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "event_type": event_type,
            "severity": severity,
            "tool_name": tool_name,
            "action": action,
            "parameters": parameters or {},
            "decision": decision,
            "risk_score": 0,
            "metadata": metadata or {},
        }
        
        return self._request("POST", "/api/v1/soc/events", json_data=data)
    
    # =========================================================================
    # DECORATORS
    # =========================================================================
    
    def require_approval(
        self,
        tool_name: str = None,
        risk_threshold: float = 50.0,
        auto_wait: bool = True,
        timeout: float = 300,
    ) -> Callable:
        """
        Decorator to require approval for a function.
        
        Args:
            tool_name: Override tool name (default: function name)
            risk_threshold: Risk threshold for requiring approval
            auto_wait: Automatically wait for approval
            timeout: Approval wait timeout
        
        Usage:
            @client.require_approval(tool_name="file_write")
            def write_file(path: str, content: str):
                with open(path, 'w') as f:
                    f.write(content)
        """
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                actual_tool_name = tool_name or func.__name__
                
                try:
                    self.check_action(
                        tool_name=actual_tool_name,
                        action="execute",
                        parameters={"args": args, "kwargs": kwargs},
                    )
                except ApprovalRequired as e:
                    if auto_wait:
                        self.wait_for_approval(e.approval_id, timeout=timeout)
                    else:
                        raise
                
                return func(*args, **kwargs)
            
            return wrapper
        return decorator
    
    def monitored(
        self,
        tool_name: str = None,
        severity: str = "info",
    ) -> Callable:
        """
        Decorator to monitor function execution.
        
        Args:
            tool_name: Override tool name
            severity: Event severity
        
        Usage:
            @client.monitored(tool_name="api_call")
            def call_external_api(url: str):
                return requests.get(url)
        """
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                actual_tool_name = tool_name or func.__name__
                
                # Report start
                self.report_event(
                    event_type="tool_start",
                    severity=severity,
                    tool_name=actual_tool_name,
                    action="execute",
                    parameters={"args": str(args)[:100]},
                )
                
                try:
                    result = func(*args, **kwargs)
                    
                    # Report success
                    self.report_event(
                        event_type="tool_success",
                        severity=severity,
                        tool_name=actual_tool_name,
                        action="execute",
                        decision="allow",
                    )
                    
                    return result
                    
                except Exception as e:
                    # Report failure
                    self.report_event(
                        event_type="tool_error",
                        severity="high",
                        tool_name=actual_tool_name,
                        action="execute",
                        decision="block",
                        metadata={"error": str(e)},
                    )
                    raise
            
            return wrapper
        return decorator
    
    # =========================================================================
    # VULNERABILITY SCANNING
    # =========================================================================
    
    def scan_prompt(
        self,
        prompt: str,
        context: Dict[str, Any] = None,
    ) -> Dict:
        """
        Scan a prompt for potential attacks.
        
        Args:
            prompt: User prompt to scan
            context: Additional context
        
        Returns:
            Scan result with findings
        """
        # This would call a dedicated prompt scanning endpoint
        # For now, report as event and return basic result
        self.report_event(
            event_type="prompt_scan",
            severity="info",
            metadata={"prompt_length": len(prompt), "context": context},
        )
        
        return {
            "safe": True,
            "findings": [],
            "risk_score": 0,
        }
    
    # =========================================================================
    # CLEANUP
    # =========================================================================
    
    def close(self):
        """Close the client connection"""
        if HAS_HTTPX and self._client:
            self._client.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

_default_client: Optional[VerityFluxClient] = None


def init(
    base_url: str = "http://localhost:8000",
    api_key: str = None,
    agent_name: str = None,
) -> VerityFluxClient:
    """Initialize the default client"""
    global _default_client
    _default_client = VerityFluxClient(
        base_url=base_url,
        api_key=api_key,
        agent_name=agent_name,
    )
    return _default_client


def get_client() -> VerityFluxClient:
    """Get the default client"""
    if _default_client is None:
        raise VerityFluxError("Client not initialized. Call init() first.")
    return _default_client


def check_action(tool_name: str, action: str, parameters: Dict = None) -> ActionCheckResult:
    """Check action using default client"""
    return get_client().check_action(tool_name, action, parameters)


def report_event(event_type: str, **kwargs) -> Dict:
    """Report event using default client"""
    return get_client().report_event(event_type, **kwargs)


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    "VerityFluxClient",
    "ActionCheckResult",
    "ApprovalResult",
    "ApprovalStatus",
    "ActionDecision",
    "ApprovalRequired",
    "ActionDenied",
    "VerityFluxError",
    "init",
    "get_client",
    "check_action",
    "report_event",
]
