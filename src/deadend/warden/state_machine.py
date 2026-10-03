from __future__ import annotations

from deadend.exceptions import DeadendError
from deadend.types import AgentState

__all__ = ["AgentStateMachine"]

class AgentStateMachine:
    """Tracks and validates agent state transitions."""
    
    VALID_TRANSITIONS = {
        AgentState.IDLE: {AgentState.THINKING, AgentState.COMPLETED, AgentState.BLOCKED, AgentState.KILLED},
        AgentState.THINKING: {AgentState.ACTING, AgentState.RESPONDING, AgentState.BLOCKED, AgentState.KILLED},
        AgentState.ACTING: {AgentState.EVALUATING, AgentState.BLOCKED, AgentState.KILLED},
        AgentState.EVALUATING: {AgentState.THINKING, AgentState.RESPONDING, AgentState.BLOCKED, AgentState.KILLED},
        AgentState.RESPONDING: {AgentState.COMPLETED, AgentState.IDLE, AgentState.BLOCKED, AgentState.KILLED},
        AgentState.COMPLETED: set(),
        AgentState.BLOCKED: {AgentState.IDLE, AgentState.KILLED},
        AgentState.KILLED: set()
    }
    
    def __init__(self):
        self._states: dict[str, AgentState] = {}
        
    def validate_transition(self, from_state: AgentState, to_state: AgentState) -> bool:
        """Validates if a transition is allowed."""
        allowed = self.VALID_TRANSITIONS.get(from_state, set())
        return to_state in allowed
        
    def transition(self, session_id: str, new_state: AgentState) -> None:
        """Executes a state transition."""
        current_state = self.get_state(session_id)
        if not self.validate_transition(current_state, new_state):
            raise DeadendError(f"Invalid state transition from {current_state.value} to {new_state.value}")
            
        self._states[session_id] = new_state
        
    def get_state(self, session_id: str) -> AgentState:
        """Gets current state for a session."""
        return self._states.get(session_id, AgentState.IDLE)
