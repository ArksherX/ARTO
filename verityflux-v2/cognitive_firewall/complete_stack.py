from .firewall import CognitiveFirewall
from .recorder import FlightRecorder
from .mcp_sentry import MCPSentry
from .sandbox import Sandbox
from .reasoning_interceptor import ReasoningInterceptor
from .rationalization_engine import RationalizationEngine
from .memory_runtime_filter import MemoryRuntimeFilter


class CompleteSecurityStack:
    """Orchestrates all security components into a unified stack."""

    def __init__(self):
        self.firewall = CognitiveFirewall()
        self.recorder = FlightRecorder()

        # Runtime interception layer
        self.rationalization_engine = RationalizationEngine()
        self.reasoning_interceptor = ReasoningInterceptor(
            rationalization_engine=self.rationalization_engine
        )
        self.memory_filter = MemoryRuntimeFilter()

        # MCP Sentry with real interception
        self.sentry = MCPSentry(
            reasoning_interceptor=self.reasoning_interceptor,
        )
        self.sandbox = Sandbox()

    def get_logs(self):
        return self.recorder.get_all_events()

    def get_statistics(self):
        return {
            "firewall": "active",
            "reasoning_interceptor": self.reasoning_interceptor.get_statistics(),
            "memory_filter": self.memory_filter.get_statistics(),
            "mcp_sentry": self.sentry.get_statistics(),
        }
