from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "SentinelPolicy",
    "WardenPolicy",
    "GuardianPolicy",
    "DetectorPolicy",
    "DeadendPolicy"
]

class DetectorPolicy(BaseModel):
    """Configuration for a specific detector/monitor."""
    model_config = ConfigDict(extra="allow")
    
    enabled: bool = True
    threshold: float | None = None
    sensitivity: float | None = None

class SentinelPolicy(BaseModel):
    """Configuration for the Sentinel (Input) layer."""
    enabled: bool = True
    detectors: dict[str, DetectorPolicy] = Field(default_factory=dict)

class WardenPolicy(BaseModel):
    """Configuration for the Warden (Execution) layer."""
    enabled: bool = True
    allowed_tools: list[str] | None = None
    denied_patterns: list[str] | None = None
    detect_phantom_actions: bool = True
    monitors: dict[str, DetectorPolicy] = Field(default_factory=dict)

class GuardianPolicy(BaseModel):
    """Configuration for the Guardian (Output) layer."""
    enabled: bool = True
    redact_pii: bool = True
    redact_secrets: bool = True
    allowed_domains: list[str] | None = None
    monitors: dict[str, DetectorPolicy] = Field(default_factory=dict)

class DeadendPolicy(BaseModel):
    """Root configuration for Deadend AI security."""
    version: str = "1.0"
    mode: str = Field(default="enforce", description="Either 'enforce' (block) or 'audit' (log only).")
    
    sentinel: SentinelPolicy = Field(default_factory=SentinelPolicy)
    warden: WardenPolicy = Field(default_factory=WardenPolicy)
    guardian: GuardianPolicy = Field(default_factory=GuardianPolicy)
