from __future__ import annotations

from typing import List, Literal, Optional
from pydantic import BaseModel, Field

from phalanx_ai.types import ActionType

class PolicyMetadata(BaseModel):
    name: str
    version: str = '1.0'
    description: str = ''
    author: str = ''

class ToolPolicy(BaseModel):
    name: str
    max_calls_per_session: int = -1
    allowed_domains: List[str] = Field(default_factory=list)
    denied_patterns: List[str] = Field(default_factory=list)
    sandbox: bool = False
    timeout_seconds: int = 30

class NetworkPolicy(BaseModel):
    allowed_outbound: List[str] = Field(default_factory=list)
    denied_outbound: List[str] = Field(default_factory=lambda: ['*'])
    max_payload_size_kb: int = 50

class ResourcePolicy(BaseModel):
    max_tokens_per_session: int = 100000
    max_cost_per_session_usd: float = 10.0
    max_api_calls_per_minute: int = 30
    max_agent_depth: int = 3
    max_concurrent_agents: int = 5
    max_consecutive_tool_calls: int = 10

class SentinelPolicy(BaseModel):
    injection_detection: Literal['strict','moderate','relaxed'] = 'strict'
    jailbreak_detection: Literal['strict','moderate','relaxed'] = 'strict'
    encoding_detection: bool = True
    canary_tokens: bool = True
    max_prompt_length: int = 8192
    blocked_topics: List[str] = Field(default_factory=list)

class WardenPolicy(BaseModel):
    allowed_tools: List[ToolPolicy] = Field(default_factory=list)
    network: NetworkPolicy = Field(default_factory=NetworkPolicy)
    resources: ResourcePolicy = Field(default_factory=ResourcePolicy)
    block_privilege_escalation: bool = True
    block_lateral_movement: bool = True
    block_data_exfiltration: bool = True
    block_self_modification: bool = True

class GuardianPolicy(BaseModel):
    pii_detection: bool = True
    secret_detection: bool = True
    code_validation: bool = True
    toxicity_check: bool = True
    max_output_length: int = 16384
    redaction_strategy: Literal['mask','remove','hash'] = 'mask'
    mask_char: str = '█'

class ActionPolicy(BaseModel):
    on_critical: List[ActionType] = Field(default_factory=lambda: [ActionType.BLOCK, ActionType.KILL, ActionType.ALERT])
    on_high: List[ActionType] = Field(default_factory=lambda: [ActionType.BLOCK, ActionType.ALERT])
    on_medium: List[ActionType] = Field(default_factory=lambda: [ActionType.WARN, ActionType.ALERT])
    on_low: List[ActionType] = Field(default_factory=lambda: [ActionType.WARN])
    on_info: List[ActionType] = Field(default_factory=lambda: [ActionType.ALLOW])

class SecurityPolicy(BaseModel):
    api_version: str = 'phalanx/v1'
    metadata: PolicyMetadata
    mode: Literal['enforce','monitor','disabled'] = 'enforce'
    sentinel: SentinelPolicy = Field(default_factory=SentinelPolicy)
    warden: WardenPolicy = Field(default_factory=WardenPolicy)
    guardian: GuardianPolicy = Field(default_factory=GuardianPolicy)
    actions: ActionPolicy = Field(default_factory=ActionPolicy)

__all__ = [
    "PolicyMetadata", "ToolPolicy", "NetworkPolicy", "ResourcePolicy",
    "SentinelPolicy", "WardenPolicy", "GuardianPolicy", "ActionPolicy", "SecurityPolicy"
]
