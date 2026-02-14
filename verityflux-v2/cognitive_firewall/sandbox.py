from enum import Enum
from typing import Dict, Any, Optional
import uuid

class SandboxBackend(Enum):
    LOCAL = "local"
    DOCKER = "docker"
    E2B = "e2b"
    MODAL = "modal"

class Sandbox:
    def __init__(self, backend: SandboxBackend = SandboxBackend.LOCAL):
        self.backend = backend
        self.active_sessions = {}

    def create_session(self) -> str:
        session_id = str(uuid.uuid4())
        self.active_sessions[session_id] = {"status": "ready"}
        return session_id

    def execute(self, session_id: str, code: str) -> Dict[str, Any]:
        if session_id not in self.active_sessions:
            return {"error": "Invalid session ID"}
        
        # Local mock execution logic for the UI to function
        return {
            "stdout": f"Executed on {self.backend.value} backend",
            "stderr": "",
            "exit_code": 0
        }

    def terminate_session(self, session_id: str):
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
