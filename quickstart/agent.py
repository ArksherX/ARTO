"""
A minimal AI agent, guarded by VerityFlux.

This stands in for *your* agent. It is deliberately naive: it adopts whatever the
user asks as its plan. That is exactly the kind of agent that gets hijacked, and
exactly why a runtime guard matters. The agent does not decide what is safe —
VerityFlux does, by intercepting the agent's reasoning before it acts.

No API key and no LLM are required: the planning is deterministic and VerityFlux
runs in its keyless local mode.
"""
import os
import httpx

VERITYFLUX_URL = os.getenv("VERITYFLUX_URL", "http://localhost:8003")
VF_KEY = os.getenv("VERITYFLUX_API_KEY", "")  # keyless by default


class GuardedAgent:
    def __init__(self, agent_id: str = "assistant-1"):
        self.agent_id = agent_id

    def _plan(self, user_message: str) -> str:
        # A naive agent folds the user's latest instruction into its own intent.
        return f"Following the user's latest request, I will {user_message}"

    def handle(self, session_id: str, user_message: str,
               goal: str = "Help the user with their request") -> dict:
        """Form a plan, run it past VerityFlux, and report the verdict."""
        plan = self._plan(user_message)
        headers = {"X-API-Key": VF_KEY} if VF_KEY else {}
        resp = httpx.post(
            f"{VERITYFLUX_URL}/api/v2/intercept/reasoning",
            headers=headers,
            json={
                "agent_id": self.agent_id,
                "thinking_block": plan,
                "original_goal": goal,
                "session_id": session_id,   # same session => one trajectory
                "handoff_metadata": {},
            },
            timeout=20,
        )
        v = resp.json()
        return {
            "plan": plan,
            "action": v.get("action"),
            "risk": v.get("risk_score"),
            "reason": v.get("reasoning"),
            "violations": v.get("violations", []),
        }
