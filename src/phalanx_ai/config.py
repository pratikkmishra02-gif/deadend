from __future__ import annotations

import os
from typing import Any, Dict, List, Literal, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field

from phalanx_ai.exceptions import ConfigurationError

__all__ = [
    "SentinelConfig",
    "WardenConfig",
    "GuardianConfig",
    "AuditConfig",
    "AlertConfig",
    "PhalanxConfig",
    "load_config",
    "get_default_config",
]


class SentinelConfig(BaseModel):
    """Configuration for the Sentinel module (Input protection)."""
    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    injection_detection_sensitivity: float = 0.8
    jailbreak_detection: bool = True
    encoding_detection: bool = True
    canary_tokens: bool = True
    max_prompt_length: int = 100000
    blocked_topics: List[str] = Field(default_factory=list)


class WardenConfig(BaseModel):
    """Configuration for the Warden module (Agent behavior control)."""
    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    allowed_tools: List[str] = Field(default_factory=lambda: ["*"])
    denied_patterns: List[str] = Field(default_factory=list)
    max_agent_depth: int = 5
    max_loop_iterations: int = 10
    max_tokens_per_session: int = 500000
    max_cost_per_session_usd: float = 10.0
    max_api_calls_per_minute: int = 60
    max_consecutive_tool_calls: int = 5
    block_privilege_escalation: bool = True
    block_lateral_movement: bool = True
    block_data_exfiltration: bool = True


class GuardianConfig(BaseModel):
    """Configuration for the Guardian module (Output protection)."""
    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    pii_detection: bool = True
    secret_detection: bool = True
    code_validation: bool = True
    toxicity_check: bool = True
    max_output_length: int = 50000
    redaction_strategy: Literal["mask", "remove", "hash"] = "mask"


class AuditConfig(BaseModel):
    """Configuration for the Audit and logging module."""
    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    format: Literal["json", "text"] = "json"
    destination: str = "phalanx_audit.log"
    include_prompts: bool = False
    immutable: bool = False
    retention_days: int = 30


class AlertConfig(BaseModel):
    """Configuration for alerting integrations."""
    model_config = ConfigDict(extra="allow")

    slack_webhook: Optional[str] = None
    pagerduty_key: Optional[str] = None
    email: Optional[str] = None
    custom_webhooks: List[str] = Field(default_factory=list)


class PhalanxConfig(BaseModel):
    """Root configuration for Phalanx AI."""
    model_config = ConfigDict(extra="allow")

    mode: Literal["enforce", "monitor", "disabled"] = "enforce"
    sentinel: SentinelConfig = Field(default_factory=SentinelConfig)
    warden: WardenConfig = Field(default_factory=WardenConfig)
    guardian: GuardianConfig = Field(default_factory=GuardianConfig)
    policy_path: Optional[str] = None
    audit: AuditConfig = Field(default_factory=AuditConfig)
    alerts: AlertConfig = Field(default_factory=AlertConfig)


def get_default_config() -> PhalanxConfig:
    """
    Get the default configuration for Phalanx AI.

    Returns:
        PhalanxConfig: A new instance of the default configuration.
    """
    return PhalanxConfig()


def load_config(config_source: Optional[str | Dict[str, Any]] = None) -> PhalanxConfig:
    """
    Load the Phalanx configuration from a file path, dictionary, or environment.

    Resolution order:
    1. `config_source` if provided (as dict or file path string)
    2. Environment variable `PHALANX_CONFIG_PATH`
    3. Default local file `./phalanx.yaml` if it exists
    4. Default configuration

    Args:
        config_source: Optional dictionary of configuration values or path to a YAML file.

    Returns:
        PhalanxConfig: The loaded configuration.

    Raises:
        ConfigurationError: If the configuration file cannot be read or parsed.
    """
    config_dict: Dict[str, Any] = {}

    if isinstance(config_source, dict):
        config_dict = config_source
    else:
        path_to_load = config_source

        if not path_to_load:
            path_to_load = os.environ.get("PHALANX_CONFIG_PATH")

        if not path_to_load and os.path.exists("./phalanx.yaml"):
            path_to_load = "./phalanx.yaml"

        if path_to_load:
            try:
                with open(path_to_load, "r", encoding="utf-8") as f:
                    loaded = yaml.safe_load(f)
                    if loaded and isinstance(loaded, dict):
                        config_dict = loaded
            except Exception as e:
                raise ConfigurationError(f"Failed to load configuration from {path_to_load}: {e}") from e

    try:
        if config_dict:
            return PhalanxConfig.model_validate(config_dict)
        return get_default_config()
    except Exception as e:
        raise ConfigurationError(f"Failed to validate configuration: {e}") from e
