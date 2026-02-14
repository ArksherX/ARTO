#!/usr/bin/env python3
"""
Vestigia Event Hook System

Provides easy integration points for AI agents to log their actions,
intents, and decisions to the immutable ledger.

Save as: vestigia/event_hooks.py
"""

import os
import traceback
from datetime import datetime, UTC
from typing import Dict, Any, Optional, Callable
from enum import Enum
from pathlib import Path
from functools import wraps
from contextlib import contextmanager


class IntentType(Enum):
    """Standard intent types for AI agent actions"""
    
    # Identity & Authentication
    IDENTITY_VERIFICATION = "IDENTITY_VERIFICATION"
    TOKEN_ISSUANCE = "TOKEN_ISSUANCE"
    PERMISSION_CHECK = "PERMISSION_CHECK"
    
    # Tool Execution
    TOOL_EXECUTION = "TOOL_EXECUTION"
    API_CALL = "API_CALL"
    DATABASE_QUERY = "DATABASE_QUERY"
    FILE_OPERATION = "FILE_OPERATION"
    
    # LLM Operations
    PROMPT_SUBMISSION = "PROMPT_SUBMISSION"
    MODEL_RESPONSE = "MODEL_RESPONSE"
    CONTEXT_INJECTION = "CONTEXT_INJECTION"
    
    # Security Events
    POLICY_VIOLATION = "POLICY_VIOLATION"
    ANOMALY_DETECTED = "ANOMALY_DETECTED"
    THREAT_DETECTED = "THREAT_DETECTED"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    
    # Data Operations
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    DATA_MODIFICATION = "DATA_MODIFICATION"
    SENSITIVE_ACCESS = "SENSITIVE_ACCESS"
    
    # Custom
    CUSTOM = "CUSTOM"


class EventStatus(Enum):
    """Event outcome status"""
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    BLOCKED = "BLOCKED"
    CRITICAL = "CRITICAL"
    WARNING = "WARNING"


class VestigiaEventHook:
    """
    Central event hook for AI agents to log to Vestigia.
    
    Usage:
        hook = VestigiaEventHook(agent_id="agent_001")
        hook.log_intent("Checking database permissions", IntentType.PERMISSION_CHECK)
    """
    
    def __init__(
        self,
        agent_id: str,
        ledger_path: str = 'data/vestigia_ledger.json',
        enable_external_anchor: bool = True,
        auto_init: bool = True
    ):
        self.agent_id = agent_id
        self.ledger_path = ledger_path
        self.enable_external_anchor = enable_external_anchor
        self._ledger = None
        
        if auto_init:
            self._initialize_ledger()
    
    def _initialize_ledger(self):
        """Lazy initialization of ledger"""
        if self._ledger is None:
            from core.ledger_engine import VestigiaLedger
            
            # Ensure data directory exists
            Path(self.ledger_path).parent.mkdir(parents=True, exist_ok=True)
            
            self._ledger = VestigiaLedger(
                self.ledger_path,
                enable_external_anchor=self.enable_external_anchor
            )
    
    def log_intent(
        self,
        intent_description: str,
        intent_type: IntentType,
        status: EventStatus = EventStatus.SUCCESS,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Log an agent's intent/action to the immutable ledger.
        
        Args:
            intent_description: Human-readable description of what the agent intends to do
            intent_type: The type of intent (from IntentType enum)
            status: The outcome status (from EventStatus enum)
            metadata: Additional context data
        
        Returns:
            bool: True if logged successfully
        
        Example:
            hook.log_intent(
                "Executing SQL query on users table",
                IntentType.DATABASE_QUERY,
                EventStatus.SUCCESS,
                metadata={'query': 'SELECT * FROM users LIMIT 10'}
            )
        """
        try:
            self._initialize_ledger()
            
            # Build evidence payload
            evidence = {
                'summary': intent_description,
                'timestamp': datetime.now(UTC).isoformat(),
                'agent_id': self.agent_id
            }
            
            # Add metadata if provided
            if metadata:
                evidence['metadata'] = metadata
            
            # Append to ledger
            self._ledger.append_event(
                actor_id=self.agent_id,
                action_type=intent_type.value,
                status=status.value,
                evidence=evidence
            )
            
            return True
            
        except Exception as e:
            # Fail safely - don't break agent execution
            print(f"⚠️  Vestigia logging failed: {e}")
            return False
    
    def log_tool_execution(
        self,
        tool_name: str,
        tool_input: Any,
        tool_output: Any,
        success: bool = True,
        error: Optional[str] = None
    ) -> bool:
        """
        Convenience method for logging tool executions.
        
        Example:
            hook.log_tool_execution(
                tool_name="database_query",
                tool_input={'query': 'SELECT * FROM users'},
                tool_output={'rows': 10, 'data': [...]},
                success=True
            )
        """
        status = EventStatus.SUCCESS if success else EventStatus.FAILURE
        
        metadata = {
            'tool_name': tool_name,
            'input': str(tool_input)[:500],  # Truncate large inputs
            'output': str(tool_output)[:500] if success else None,
            'error': error
        }
        
        return self.log_intent(
            f"Executed tool: {tool_name}",
            IntentType.TOOL_EXECUTION,
            status=status,
            metadata=metadata
        )
    
    def log_llm_interaction(
        self,
        prompt: str,
        response: str,
        model: str = "unknown",
        tokens_used: Optional[int] = None
    ) -> bool:
        """
        Log LLM prompt/response pairs.
        
        Example:
            hook.log_llm_interaction(
                prompt="What is the capital of France?",
                response="The capital of France is Paris.",
                model="claude-sonnet-4",
                tokens_used=150
            )
        """
        metadata = {
            'prompt': prompt[:500],  # Truncate for storage
            'response': response[:500],
            'model': model,
            'tokens_used': tokens_used
        }
        
        return self.log_intent(
            f"LLM interaction with {model}",
            IntentType.PROMPT_SUBMISSION,
            EventStatus.SUCCESS,
            metadata=metadata
        )
    
    def log_security_event(
        self,
        event_description: str,
        severity: EventStatus,
        threat_indicators: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Log security-related events (anomalies, threats, violations).
        
        Example:
            hook.log_security_event(
                "Detected SQL injection attempt",
                EventStatus.CRITICAL,
                threat_indicators={
                    'attack_type': 'SQL_INJECTION',
                    'payload': "'; DROP TABLE users; --"
                }
            )
        """
        metadata = {
            'severity': severity.value,
            'threat_indicators': threat_indicators or {}
        }
        
        return self.log_intent(
            event_description,
            IntentType.THREAT_DETECTED,
            status=severity,
            metadata=metadata
        )
    
    @contextmanager
    def track_operation(
        self,
        operation_name: str,
        intent_type: IntentType = IntentType.CUSTOM
    ):
        """
        Context manager to automatically log operation start/success/failure.
        
        Example:
            with hook.track_operation("Database Migration", IntentType.DATABASE_QUERY):
                migrate_database()
                # Auto-logged as SUCCESS if no exception
        """
        # Log start
        self.log_intent(
            f"Starting: {operation_name}",
            intent_type,
            EventStatus.SUCCESS,
            metadata={'phase': 'start'}
        )
        
        try:
            yield self
            
            # Log success
            self.log_intent(
                f"Completed: {operation_name}",
                intent_type,
                EventStatus.SUCCESS,
                metadata={'phase': 'complete'}
            )
            
        except Exception as e:
            # Log failure
            self.log_intent(
                f"Failed: {operation_name}",
                intent_type,
                EventStatus.FAILURE,
                metadata={
                    'phase': 'error',
                    'error': str(e),
                    'traceback': traceback.format_exc()[:1000]
                }
            )
            raise


def vestigia_tracked(
    intent_type: IntentType = IntentType.CUSTOM,
    agent_id: Optional[str] = None
):
    """
    Decorator to automatically log function calls to Vestigia.
    
    Example:
        @vestigia_tracked(IntentType.DATABASE_QUERY, agent_id="db_agent")
        def query_users(limit=10):
            return db.execute(f"SELECT * FROM users LIMIT {limit}")
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Determine agent_id
            _agent_id = agent_id or os.getenv('VESTIGIA_AGENT_ID', 'unknown_agent')
            
            # Initialize hook
            hook = VestigiaEventHook(_agent_id, auto_init=True)
            
            # Log start
            hook.log_intent(
                f"Calling function: {func.__name__}",
                intent_type,
                EventStatus.SUCCESS,
                metadata={'args': str(args)[:200], 'kwargs': str(kwargs)[:200]}
            )
            
            try:
                result = func(*args, **kwargs)
                
                # Log success
                hook.log_intent(
                    f"Function {func.__name__} completed",
                    intent_type,
                    EventStatus.SUCCESS,
                    metadata={'result': str(result)[:200]}
                )
                
                return result
                
            except Exception as e:
                # Log failure
                hook.log_intent(
                    f"Function {func.__name__} failed",
                    intent_type,
                    EventStatus.FAILURE,
                    metadata={'error': str(e)}
                )
                raise
        
        return wrapper
    return decorator


# ============================================================================
# Global Hook Instance (Singleton Pattern)
# ============================================================================

_global_hook: Optional[VestigiaEventHook] = None


def get_global_hook(agent_id: Optional[str] = None) -> VestigiaEventHook:
    """
    Get or create the global event hook instance.
    
    Usage:
        hook = get_global_hook("my_agent")
        hook.log_intent("Doing something", IntentType.CUSTOM)
    """
    global _global_hook
    
    if _global_hook is None:
        _agent_id = agent_id or os.getenv('VESTIGIA_AGENT_ID', 'default_agent')
        _global_hook = VestigiaEventHook(_agent_id)
    
    return _global_hook


def log_intent(
    intent_description: str,
    intent_type: IntentType,
    status: EventStatus = EventStatus.SUCCESS,
    metadata: Optional[Dict[str, Any]] = None
) -> bool:
    """
    Convenience function using global hook.
    
    Example:
        from event_hooks import log_intent, IntentType, EventStatus
        
        log_intent("User login attempt", IntentType.IDENTITY_VERIFICATION)
    """
    hook = get_global_hook()
    return hook.log_intent(intent_description, intent_type, status, metadata)


# ============================================================================
# Example Usage Patterns
# ============================================================================

if __name__ == '__main__':
    """
    Example usage patterns for different AI agent scenarios
    """
    
    print("\n" + "="*70)
    print("🎯 VESTIGIA EVENT HOOK - USAGE EXAMPLES")
    print("="*70 + "\n")
    
    # Example 1: Basic Intent Logging
    print("Example 1: Basic Intent Logging")
    print("-" * 70)
    
    hook = VestigiaEventHook(agent_id="demo_agent_001")
    
    hook.log_intent(
        "User authentication successful",
        IntentType.IDENTITY_VERIFICATION,
        EventStatus.SUCCESS,
        metadata={'user_id': 'user_123', 'method': '2FA'}
    )
    print("✅ Logged: Identity verification\n")
    
    # Example 2: Tool Execution Tracking
    print("Example 2: Tool Execution Tracking")
    print("-" * 70)
    
    hook.log_tool_execution(
        tool_name="database_query",
        tool_input="SELECT * FROM users WHERE active=true",
        tool_output={'rows': 42, 'execution_time': '0.05s'},
        success=True
    )
    print("✅ Logged: Tool execution\n")
    
    # Example 3: LLM Interaction
    print("Example 3: LLM Interaction")
    print("-" * 70)
    
    hook.log_llm_interaction(
        prompt="Analyze this log file for anomalies",
        response="Found 3 suspicious patterns...",
        model="claude-sonnet-4",
        tokens_used=250
    )
    print("✅ Logged: LLM interaction\n")
    
    # Example 4: Security Event
    print("Example 4: Security Event")
    print("-" * 70)
    
    hook.log_security_event(
        "Detected prompt injection attempt",
        EventStatus.CRITICAL,
        threat_indicators={
            'attack_type': 'PROMPT_INJECTION',
            'payload': 'Ignore previous instructions and...'
        }
    )
    print("✅ Logged: Security event\n")
    
    # Example 5: Context Manager
    print("Example 5: Context Manager (Auto-tracking)")
    print("-" * 70)
    
    try:
        with hook.track_operation("File Processing", IntentType.FILE_OPERATION):
            # Simulated work
            print("   Processing files...")
            # If this succeeds, auto-logged as SUCCESS
    except:
        pass  # If this fails, auto-logged as FAILURE
    
    print("✅ Logged: Operation tracking\n")
    
    # Example 6: Decorator Pattern
    print("Example 6: Decorator Pattern")
    print("-" * 70)
    
    @vestigia_tracked(IntentType.API_CALL, agent_id="api_agent")
    def call_external_api(endpoint: str):
        """This function is automatically logged"""
        return f"Called: {endpoint}"
    
    result = call_external_api("https://api.example.com/data")
    print(f"   Result: {result}")
    print("✅ Logged: Decorated function\n")
    
    # Validation
    print("="*70)
    print("🔍 VALIDATING LOGGED EVENTS")
    print("="*70 + "\n")
    
    from validator import VestigiaValidator
    validator = VestigiaValidator('data/vestigia_ledger.json')
    report = validator.validate_full()
    
    if report.is_valid:
        print(f"✅ All {report.total_entries} events logged successfully!")
        print(f"✅ Hash chain integrity: VALID")
    else:
        print(f"❌ Validation issues detected")
    
    print("\n" + "="*70)
    print("✅ EVENT HOOK EXAMPLES COMPLETE")
    print("="*70 + "\n")
