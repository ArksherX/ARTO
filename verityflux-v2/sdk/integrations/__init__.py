"""
VerityFlux Enterprise - Framework Integrations

Integrations for popular AI agent frameworks:
- LangChain
- AutoGen  
- CrewAI
"""

# Check for LangChain
try:
    from .langchain_integration import (
        VerityFluxCallbackHandler,
        VerityFluxToolWrapper,
        VerityFluxAgentExecutor,
        wrap_tools_with_security,
        create_secure_agent,
    )
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False

# Check for AutoGen
try:
    from .autogen_integration import (
        SecureAssistantAgent,
        SecureUserProxyAgent,
        VerityFluxGroupChatManager,
        secure_function,
        create_secure_agents,
    )
    AUTOGEN_AVAILABLE = True
except ImportError:
    AUTOGEN_AVAILABLE = False

# Check for CrewAI
try:
    from .crewai_integration import (
        SecureAgent,
        SecureCrew,
        secure_tool,
        create_secure_crew,
    )
    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False

__all__ = [
    "LANGCHAIN_AVAILABLE",
    "AUTOGEN_AVAILABLE", 
    "CREWAI_AVAILABLE",
]

if LANGCHAIN_AVAILABLE:
    __all__.extend([
        "VerityFluxCallbackHandler",
        "VerityFluxToolWrapper",
        "VerityFluxAgentExecutor",
        "wrap_tools_with_security",
        "create_secure_agent",
    ])

if AUTOGEN_AVAILABLE:
    __all__.extend([
        "SecureAssistantAgent",
        "SecureUserProxyAgent",
        "VerityFluxGroupChatManager",
        "secure_function",
        "create_secure_agents",
    ])

if CREWAI_AVAILABLE:
    __all__.extend([
        "SecureAgent",
        "SecureCrew",
        "secure_tool",
        "create_secure_crew",
    ])
