from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from deadend.types import ActionType, ModuleType, ThreatSeverity

__all__ = ["AuditEvent"]

class AuditEvent(BaseModel):
    """Represents a structured audit event."""
    
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    session_id: str
    agent_id: str = 'default'
    event_type: str
    module: ModuleType
    severity: ThreatSeverity | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    scan_result: Any | None = None
    action_taken: ActionType | None = None
    latency_ms: float | None = None
    policy_name: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)
    previous_hash: str | None = None
    hash: str | None = None

    model_config = {
        "arbitrary_types_allowed": True
    }
