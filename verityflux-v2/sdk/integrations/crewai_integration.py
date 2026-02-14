#!/usr/bin/env python3
"""
VerityFlux Enterprise - CrewAI Integration
Security controls for CrewAI multi-agent crews
"""

import logging
import time
from typing import Any, Dict, List, Optional, Callable
from functools import wraps

logger = logging.getLogger("verityflux.crewai")

try:
    from crewai import Agent, Task, Crew, Process
    from crewai.tools import BaseTool
    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False
    class Agent: pass
    class Task: pass
    class Crew: pass
    class Process:
        sequential = "sequential"
    class BaseTool: pass

try:
    from ..python.verityflux_sdk import VerityFluxClient, ApprovalRequired, ActionDenied
except ImportError:
    from verityflux_sdk import VerityFluxClient, ApprovalRequired, ActionDenied


class SecureAgent(Agent if CREWAI_AVAILABLE else object):
    """CrewAI Agent with VerityFlux security monitoring."""
    
    def __init__(
        self,
        role: str,
        goal: str,
        backstory: str = "",
        verityflux_client: VerityFluxClient = None,
        verityflux_api_url: str = "http://localhost:8000",
        verityflux_api_key: str = None,
        **kwargs,
    ):
        if not CREWAI_AVAILABLE:
            raise ImportError("CrewAI not available")
        
        super().__init__(role=role, goal=goal, backstory=backstory, **kwargs)
        
        self.vf_client = verityflux_client or VerityFluxClient(
            base_url=verityflux_api_url,
            api_key=verityflux_api_key,
            agent_name=role.lower().replace(" ", "-"),
        )
        
        self.vf_client.register_agent(
            name=role.lower().replace(" ", "-"),
            agent_type="crewai",
            metadata={"role": role, "goal": goal}
        )
    
    def execute_task(self, task: "Task", context: str = None) -> str:
        self.vf_client.report_event(
            event_type="task_start",
            severity="info",
            metadata={"role": self.role, "task": task.description[:200] if task.description else ""}
        )
        
        try:
            result = super().execute_task(task, context)
            self.vf_client.report_event(event_type="task_complete", severity="info", metadata={"role": self.role})
            return result
        except Exception as e:
            self.vf_client.report_event(event_type="task_error", severity="high", metadata={"error": str(e)})
            raise


def secure_tool(
    client: VerityFluxClient = None,
    api_url: str = "http://localhost:8000",
    api_key: str = None,
    require_approval: bool = False,
):
    """Decorator to secure CrewAI tool functions."""
    def decorator(func: Callable) -> Callable:
        _client = client or VerityFluxClient(base_url=api_url, api_key=api_key, agent_name=f"tool-{func.__name__}")
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            _client.report_event(event_type="tool_call", severity="medium", tool_name=func.__name__)
            
            if require_approval:
                try:
                    result = _client.check_action(tool_name=func.__name__, action="execute", parameters={})
                    if not result.approved:
                        raise ActionDenied(f"Tool {func.__name__} blocked")
                except ApprovalRequired as e:
                    approval = _client.wait_for_approval(e.approval_id, timeout=300)
                    if not approval.approved:
                        raise ActionDenied(f"Tool {func.__name__} denied")
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


class SecureCrew(Crew if CREWAI_AVAILABLE else object):
    """CrewAI Crew with VerityFlux security monitoring."""
    
    def __init__(
        self,
        agents: List["Agent"],
        tasks: List["Task"],
        verityflux_client: VerityFluxClient = None,
        verityflux_api_url: str = "http://localhost:8000",
        verityflux_api_key: str = None,
        crew_name: str = None,
        require_approval_between_tasks: bool = False,
        **kwargs,
    ):
        if not CREWAI_AVAILABLE:
            raise ImportError("CrewAI not available")
        
        super().__init__(agents=agents, tasks=tasks, **kwargs)
        
        self.vf_client = verityflux_client or VerityFluxClient(
            base_url=verityflux_api_url,
            api_key=verityflux_api_key,
            agent_name=crew_name or "crewai-crew",
        )
        
        self.crew_name = crew_name or f"crew-{int(time.time())}"
        self.require_approval_between_tasks = require_approval_between_tasks
        
        self.vf_client.register_agent(
            name=self.crew_name,
            agent_type="crewai",
            metadata={"agent_count": len(agents), "task_count": len(tasks)}
        )
    
    def kickoff(self, inputs: Dict[str, Any] = None) -> str:
        self.vf_client.report_event(
            event_type="crew_kickoff",
            severity="info",
            metadata={"crew": self.crew_name, "inputs": str(inputs)[:200] if inputs else None}
        )
        
        start_time = time.time()
        
        try:
            result = super().kickoff(inputs=inputs)
            
            duration = time.time() - start_time
            self.vf_client.report_event(
                event_type="crew_complete",
                severity="info",
                metadata={"crew": self.crew_name, "duration_seconds": round(duration, 2)}
            )
            
            return result
            
        except Exception as e:
            self.vf_client.report_event(
                event_type="crew_error",
                severity="critical",
                metadata={"crew": self.crew_name, "error": str(e)}
            )
            raise


def create_secure_crew(
    agents_config: List[Dict[str, Any]],
    tasks_config: List[Dict[str, Any]],
    api_url: str = "http://localhost:8000",
    api_key: str = None,
    crew_name: str = None,
    **crew_kwargs,
) -> SecureCrew:
    """
    Create a secure CrewAI crew from configuration.
    
    Args:
        agents_config: List of agent configs with role, goal, backstory
        tasks_config: List of task configs
        api_url: VerityFlux API URL
        api_key: API key
        crew_name: Name for the crew
    
    Returns:
        SecureCrew instance
    """
    client = VerityFluxClient(base_url=api_url, api_key=api_key, agent_name=crew_name or "crewai")
    
    agents = []
    for config in agents_config:
        agent = SecureAgent(
            verityflux_client=client,
            **config,
        )
        agents.append(agent)
    
    tasks = []
    for config in tasks_config:
        task = Task(**config)
        tasks.append(task)
    
    return SecureCrew(
        agents=agents,
        tasks=tasks,
        verityflux_client=client,
        crew_name=crew_name,
        **crew_kwargs,
    )


__all__ = [
    "SecureAgent",
    "SecureCrew",
    "secure_tool",
    "create_secure_crew",
    "CREWAI_AVAILABLE",
]
