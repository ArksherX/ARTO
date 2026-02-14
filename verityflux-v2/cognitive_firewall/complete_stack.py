from .firewall import CognitiveFirewall
from .recorder import FlightRecorder
from .mcp_sentry import MCPSentry
from .sandbox import Sandbox

class CompleteSecurityStack:
    def __init__(self):
        self.firewall = CognitiveFirewall()
        self.recorder = FlightRecorder()
        self.sentry = MCPSentry()
        self.sandbox = Sandbox()
        
    def get_logs(self):
        return self.recorder.get_all_events()
