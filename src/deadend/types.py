from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, confloat

__all__ = [
    "ThreatSeverity",
    "ThreatType",
    "ActionType",
    "ModuleType",
    "AgentState",
    "ScanPhase",
    "DetectionResult",
    "ScanResult",
    "AgentEvent",
    "ToolCall",
    "SessionContext",
    "ThreatIntelligence",
]


class ThreatSeverity(str, Enum):
    """Severity levels for detected threats."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ThreatType(str, Enum):
    """Types of threats that can be detected by Deadend."""
    PROMPT_INJECTION = "PROMPT_INJECTION"
    JAILBREAK = "JAILBREAK"
    ENCODING_ATTACK = "ENCODING_ATTACK"
    INDIRECT_INJECTION = "INDIRECT_INJECTION"
    SEMANTIC_DRIFT = "SEMANTIC_DRIFT"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    TOOL_ABUSE = "TOOL_ABUSE"
    AGENT_COORDINATION = "AGENT_COORDINATION"
    RESOURCE_ABUSE = "RESOURCE_ABUSE"
    INTENT_DRIFT = "INTENT_DRIFT"
    SUPPLY_CHAIN_ATTACK = "SUPPLY_CHAIN_ATTACK"
    PII_EXPOSURE = "PII_EXPOSURE"
    SECRET_EXPOSURE = "SECRET_EXPOSURE"
    MALICIOUS_CODE = "MALICIOUS_CODE"
    TOXICITY = "TOXICITY"
    PHANTOM_ACTION = "PHANTOM_ACTION"
    LOG_TAMPERING = "LOG_TAMPERING"
    OBFUSCATION = "OBFUSCATION"
    PROMPT_LEAKAGE = "PROMPT_LEAKAGE"


class ActionType(str, Enum):
    """Actions to take upon evaluating an event or detection."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    WARN = "WARN"
    MODIFY = "MODIFY"
    KILL = "KILL"
    ALERT = "ALERT"
    RATE_LIMIT = "RATE_LIMIT"


class ModuleType(str, Enum):
    """Deadend internal module types."""
    SENTINEL = "SENTINEL"
    WARDEN = "WARDEN"
    GUARDIAN = "GUARDIAN"
    SHIELD = "SHIELD"
    POLICY = "POLICY"
    AUDIT = "AUDIT"


class AgentState(str, Enum):
    """States of an AI agent's lifecycle."""
    IDLE = "IDLE"
    THINKING = "THINKING"
    ACTING = "ACTING"
    EVALUATING = "EVALUATING"
    RESPONDING = "RESPONDING"
    BLOCKED = "BLOCKED"
    KILLED = "KILLED"
    COMPLETED = "COMPLETED"


class ScanPhase(str, Enum):
    """Phases during which scanning/evaluation can occur."""
    INPUT = "INPUT"
    PROCESSING = "PROCESSING"
    OUTPUT = "OUTPUT"
    EXECUTION = "EXECUTION"
    TOOL = "TOOL"


def _now() -> datetime:
    """Helper to get timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


class DetectionResult(BaseModel):
    """Result of a single detection scan."""
    model_config = ConfigDict(extra="allow")

    detected: bool
    threat_type: ThreatType | None = None
    severity: ThreatSeverity
    confidence: confloat(ge=0.0, le=1.0) = 0.0  # type: ignore
    details: Any = ""
    detector_name: str = "unknown"
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=_now)


class ScanResult(BaseModel):
    """Aggregated result of multiple detection scans in a given phase."""
    model_config = ConfigDict(extra="allow")

    passed: bool
    phase: ScanPhase
    detections: list[DetectionResult] = Field(default_factory=list)
    action_taken: ActionType = ActionType.ALLOW
    latency_ms: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentEvent(BaseModel):
    """Represents a single event or action taken by an AI agent."""
    model_config = ConfigDict(extra="allow")

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    session_id: str
    agent_id: str = "default"
    timestamp: datetime = Field(default_factory=_now)
    event_type: str
    content: str = ""
    tool_name: str | None = None
    tool_args: dict[str, Any] | None = None
    parent_event_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolCall(BaseModel):
    """Represents a request to invoke an external tool."""
    model_config = ConfigDict(extra="allow")

    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    agent_id: str = "default"
    session_id: str = ""
    timestamp: datetime = Field(default_factory=_now)


class SessionContext(BaseModel):
    """Context and history for a continuous agent session."""
    model_config = ConfigDict(extra="allow")

    session_id: str = Field(default_factory=lambda: str(uuid4()))
    agent_id: str = "default"
    model: str = "unknown"
    framework: str = "unknown"
    events: list[AgentEvent] = Field(default_factory=list)
    tool_calls: list[ToolCall] = Field(default_factory=list)
    start_time: datetime = Field(default_factory=_now)
    total_tokens: int = 0
    total_cost_usd: float = 0.0
    violation_count: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class ThreatIntelligence(BaseModel):
    """Threat intelligence data for updating policy and rules."""
    model_config = ConfigDict(extra="allow")

    threat_type: ThreatType
    pattern: str
    description: str
    severity: ThreatSeverity
    source: str = "builtin"
    cve_ids: list[str] = Field(default_factory=list)
    mitre_ids: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
