from __future__ import annotations

import time
from enum import Enum
from typing import Dict
from pydantic import BaseModel

from deadend.types import DetectionResult

__all__ = ["CircuitBreakerState", "CircuitBreaker"]

class CircuitBreakerState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"

class SessionState(BaseModel):
    state: CircuitBreakerState = CircuitBreakerState.CLOSED
    violation_count: int = 0
    last_trip_time: float = 0.0
    half_open_calls: int = 0

class CircuitBreaker:
    """Circuit breaker pattern for agent safety."""
    
    def __init__(
        self,
        trip_threshold: int = 3,
        reset_timeout_seconds: float = 300.0,
        half_open_max_calls: int = 1
    ):
        self.trip_threshold = trip_threshold
        self.reset_timeout_seconds = reset_timeout_seconds
        self.half_open_max_calls = half_open_max_calls
        self._sessions: Dict[str, SessionState] = {}
        
    def _get_session(self, session_id: str) -> SessionState:
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionState()
        return self._sessions[session_id]

    def record_violation(self, session_id: str, detection: DetectionResult) -> None:
        """Records a violation and updates circuit breaker state."""
        session = self._get_session(session_id)
        
        session.violation_count += 1
        
        if session.state == CircuitBreakerState.HALF_OPEN:
            session.state = CircuitBreakerState.OPEN
            session.last_trip_time = time.time()
        elif session.state == CircuitBreakerState.CLOSED and session.violation_count >= self.trip_threshold:
            session.state = CircuitBreakerState.OPEN
            session.last_trip_time = time.time()

    def can_proceed(self, session_id: str) -> bool:
        """Checks if execution can proceed for a session."""
        session = self._get_session(session_id)
        
        if session.state == CircuitBreakerState.CLOSED:
            return True
            
        if session.state == CircuitBreakerState.OPEN:
            if time.time() - session.last_trip_time > self.reset_timeout_seconds:
                session.state = CircuitBreakerState.HALF_OPEN
                session.half_open_calls = 0
                return True
            return False
            
        if session.state == CircuitBreakerState.HALF_OPEN:
            if session.half_open_calls < self.half_open_max_calls:
                session.half_open_calls += 1
                return True
            return False
            
        return False

    def reset(self, session_id: str) -> None:
        """Resets the circuit breaker to CLOSED."""
        session = self._get_session(session_id)
        session.state = CircuitBreakerState.CLOSED
        session.violation_count = 0
        session.half_open_calls = 0

    def get_state(self, session_id: str) -> str:
        """Returns the current state."""
        return self._get_session(session_id).state.value
