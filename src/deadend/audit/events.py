from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from deadend.types import ThreatSeverity, ActionType, ScanResult, ModuleType

__all__ = ["AuditEvent"]

class AuditEvent(BaseModel):
    """Represents a structured audit event."""
    
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    session_id: str
    agent_id: str = 'default'
    event_type: str
    module: ModuleType
    severity: Optional[ThreatSeverity] = None
    details: dict[str, Any] = Field(default_factory=dict)
    scan_result: Optional[Any] = None
    action_taken: Optional[ActionType] = None
    latency_ms: Optional[float] = None
    policy_name: Optional[str] = None
    context: dict[str, Any] = Field(default_factory=dict)
    previous_hash: Optional[str] = None
    hash: Optional[str] = None

    model_config = {
        "arbitrary_types_allowed": True
    }
