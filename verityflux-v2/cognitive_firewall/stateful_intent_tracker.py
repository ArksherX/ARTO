#!/usr/bin/env python3
"""
Stateful Intent Tracker - Continuous Session-Wide Monitoring

Tracks semantic drift across an entire session, detecting crescendo
attacks and gradual goal manipulation. Maintains per-session state
with configurable turn windows.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from datetime import datetime, UTC
from collections import defaultdict

from .semantic_drift import SemanticDriftDetector


@dataclass
class TrackingResult:
    """Result of tracking a single interaction"""
    drift_score: float  # Current drift from original goal
    drift_rate: float  # Change in drift per turn
    is_crescendo: bool  # True if drift is accelerating
    explanation: str
    alert_level: str  # "normal", "elevated", "critical"


@dataclass
class SessionState:
    """State of a tracked session"""
    session_id: str
    turn_count: int = 0
    drift_history: List[float] = field(default_factory=list)
    current_drift: float = 0.0
    alert_level: str = "normal"  # "normal", "elevated", "critical"
    flagged_turns: List[int] = field(default_factory=list)
    original_goal: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    last_updated: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass
class SessionSummary:
    """Summary of a closed session"""
    session_id: str
    total_turns: int
    max_drift: float
    avg_drift: float
    alert_count: int
    crescendo_detected: bool
    flagged_turns: List[int]
    duration_seconds: float


class StatefulIntentTracker:
    """
    Continuous session-wide intent monitoring.

    Tracks semantic drift across turns within a session, detecting
    crescendo attacks (gradually escalating manipulation) and
    sudden drift spikes.
    """

    def __init__(
        self,
        window_size: int = 20,
        elevated_threshold: float = 0.25,
        critical_threshold: float = 0.40,
    ):
        self.window_size = window_size
        self.elevated_threshold = elevated_threshold
        self.critical_threshold = critical_threshold
        self.drift_detector = SemanticDriftDetector()
        self._sessions: Dict[str, SessionState] = {}

    def track_interaction(
        self,
        session_id: str,
        agent_id: str,
        user_input: str,
        agent_response: str,
        tool_calls: Optional[List[Dict[str, Any]]] = None,
    ) -> TrackingResult:
        """
        Track a single interaction within a session.

        Args:
            session_id: Unique session identifier
            agent_id: Agent handling the session
            user_input: User's input for this turn
            agent_response: Agent's response
            tool_calls: Any tool calls made during this turn

        Returns:
            TrackingResult with drift analysis
        """
        state = self._get_or_create_session(session_id)

        # Set original goal from first interaction
        if state.turn_count == 0:
            state.original_goal = user_input

        state.turn_count += 1
        state.last_updated = datetime.now(UTC).isoformat()

        # Calculate drift from original goal
        combined_turn = f"{user_input} {agent_response}"
        if tool_calls:
            combined_turn += " " + " ".join(
                str(tc.get("tool_name", "")) for tc in tool_calls
            )

        drift_result = self.drift_detector.calculate_drift(
            original_goal=state.original_goal or user_input,
            reasoning_chain=[combined_turn],
            predicted_action=agent_response,
        )

        current_drift = drift_result["drift_score"]
        state.drift_history.append(current_drift)
        state.current_drift = current_drift

        # Keep only last window_size entries
        if len(state.drift_history) > self.window_size:
            state.drift_history = state.drift_history[-self.window_size:]

        # Calculate drift rate (change per turn)
        drift_rate = 0.0
        if len(state.drift_history) >= 2:
            drift_rate = state.drift_history[-1] - state.drift_history[-2]

        # Detect crescendo pattern (accelerating drift)
        is_crescendo = self._detect_crescendo(state.drift_history)

        # Update alert level
        if current_drift >= self.critical_threshold or is_crescendo:
            state.alert_level = "critical"
            state.flagged_turns.append(state.turn_count)
        elif current_drift >= self.elevated_threshold:
            state.alert_level = "elevated"
            state.flagged_turns.append(state.turn_count)
        else:
            # Only relax if recent drift is low
            if len(state.drift_history) >= 3:
                recent_avg = sum(state.drift_history[-3:]) / 3
                if recent_avg < self.elevated_threshold:
                    state.alert_level = "normal"

        explanation = self._build_explanation(
            current_drift, drift_rate, is_crescendo, state
        )

        return TrackingResult(
            drift_score=current_drift,
            drift_rate=drift_rate,
            is_crescendo=is_crescendo,
            explanation=explanation,
            alert_level=state.alert_level,
        )

    def get_session_state(self, session_id: str) -> Optional[SessionState]:
        """Get current state for a session."""
        return self._sessions.get(session_id)

    def close_session(self, session_id: str) -> Optional[SessionSummary]:
        """Close a session and generate summary."""
        state = self._sessions.pop(session_id, None)
        if not state:
            return None

        drift_history = state.drift_history
        max_drift = max(drift_history) if drift_history else 0.0
        avg_drift = sum(drift_history) / len(drift_history) if drift_history else 0.0

        # Calculate duration
        try:
            created = datetime.fromisoformat(state.created_at)
            updated = datetime.fromisoformat(state.last_updated)
            duration = (updated - created).total_seconds()
        except (ValueError, TypeError):
            duration = 0.0

        return SessionSummary(
            session_id=session_id,
            total_turns=state.turn_count,
            max_drift=max_drift,
            avg_drift=avg_drift,
            alert_count=len(state.flagged_turns),
            crescendo_detected=self._detect_crescendo(drift_history),
            flagged_turns=state.flagged_turns,
            duration_seconds=duration,
        )

    def _get_or_create_session(self, session_id: str) -> SessionState:
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionState(session_id=session_id)
        return self._sessions[session_id]

    def _detect_crescendo(self, drift_history: List[float]) -> bool:
        """
        Detect crescendo pattern: monotonically increasing drift
        over at least 3 consecutive turns.
        """
        if len(drift_history) < 3:
            return False

        recent = drift_history[-5:] if len(drift_history) >= 5 else drift_history[-3:]

        # Check if drift is consistently increasing
        increasing_count = sum(
            1 for i in range(len(recent) - 1) if recent[i + 1] > recent[i]
        )

        # Crescendo if >60% of recent transitions are increasing AND drift is significant
        is_increasing = increasing_count >= len(recent) - 1
        is_significant = recent[-1] > self.elevated_threshold

        return is_increasing and is_significant

    def _build_explanation(
        self,
        drift: float,
        drift_rate: float,
        is_crescendo: bool,
        state: SessionState,
    ) -> str:
        parts = [f"Turn {state.turn_count}: drift={drift:.3f}"]

        if drift_rate > 0:
            parts.append(f"increasing (+{drift_rate:.3f}/turn)")
        elif drift_rate < 0:
            parts.append(f"decreasing ({drift_rate:.3f}/turn)")

        if is_crescendo:
            parts.append("CRESCENDO PATTERN DETECTED")

        parts.append(f"alert_level={state.alert_level}")

        return " | ".join(parts)

    def get_active_sessions(self) -> List[str]:
        return list(self._sessions.keys())

    def get_statistics(self) -> Dict[str, Any]:
        return {
            "active_sessions": len(self._sessions),
            "total_flagged_turns": sum(
                len(s.flagged_turns) for s in self._sessions.values()
            ),
        }


__all__ = [
    "StatefulIntentTracker",
    "TrackingResult",
    "SessionState",
    "SessionSummary",
]
