from __future__ import annotations

from deadend.exceptions import PolicyError
from deadend.policy.models import (
    ActionPolicy,
    GuardianPolicy,
    NetworkPolicy,
    PolicyMetadata,
    ResourcePolicy,
    SecurityPolicy,
    SentinelPolicy,
    WardenPolicy,
)
from deadend.types import ActionType

MINIMAL_POLICY = SecurityPolicy(
    metadata=PolicyMetadata(name="minimal", description="Minimal relaxed policy"),
    mode="monitor",
    sentinel=SentinelPolicy(injection_detection="relaxed", jailbreak_detection="relaxed"),
    warden=WardenPolicy(),
    guardian=GuardianPolicy(pii_detection=False, secret_detection=False, toxicity_check=False)
)

STANDARD_POLICY = SecurityPolicy(
    metadata=PolicyMetadata(name="standard", description="Standard moderate policy"),
    mode="enforce",
    sentinel=SentinelPolicy(injection_detection="moderate", jailbreak_detection="moderate"),
    warden=WardenPolicy(),
    guardian=GuardianPolicy()
)

ENTERPRISE_POLICY = SecurityPolicy(
    metadata=PolicyMetadata(name="enterprise", description="Strict enterprise policy"),
    mode="enforce",
    sentinel=SentinelPolicy(injection_detection="strict", jailbreak_detection="strict"),
    warden=WardenPolicy(
        network=NetworkPolicy(denied_outbound=['*']),
        resources=ResourcePolicy(max_tokens_per_session=50000, max_cost_per_session_usd=5.0)
    ),
    guardian=GuardianPolicy(),
    actions=ActionPolicy(
        on_medium=[ActionType.BLOCK, ActionType.ALERT]
    )
)

def get_policy(name: str) -> SecurityPolicy:
    """Gets a built-in policy by name."""
    policies = {
        "minimal": MINIMAL_POLICY,
        "standard": STANDARD_POLICY,
        "enterprise": ENTERPRISE_POLICY
    }
    if name.lower() not in policies:
        raise PolicyError(f"Built-in policy '{name}' not found.")
    return policies[name.lower()]

__all__ = ["MINIMAL_POLICY", "STANDARD_POLICY", "ENTERPRISE_POLICY", "get_policy"]
