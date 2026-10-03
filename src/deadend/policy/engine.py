from __future__ import annotations

from typing import List, Optional
import structlog

from deadend.policy.models import SecurityPolicy
from deadend.types import DetectionResult, ActionType, ThreatSeverity, SessionContext

logger = structlog.get_logger(__name__)

class PolicyEngine:
    """Engine for evaluating security policies against detections and actions."""

    def __init__(self, policy: SecurityPolicy) -> None:
        self.policy = policy

    def evaluate(self, detection: DetectionResult) -> List[ActionType]:
        """Maps threat severity to configured actions based on the policy."""
        if self.policy.mode == 'disabled':
            return [ActionType.ALLOW]
        
        actions = self.get_actions_for_severity(detection.severity)
        if self.policy.mode == 'monitor' and ActionType.BLOCK in actions:
            actions = [a for a in actions if a != ActionType.BLOCK]
            if ActionType.WARN not in actions:
                actions.append(ActionType.WARN)
        
        return actions

    def get_actions_for_severity(self, severity: ThreatSeverity) -> List[ActionType]:
        """Returns the configured actions for a given severity."""
        actions = self.policy.actions
        if severity == ThreatSeverity.CRITICAL:
            return actions.on_critical
        elif severity == ThreatSeverity.HIGH:
            return actions.on_high
        elif severity == ThreatSeverity.MEDIUM:
            return actions.on_medium
        elif severity == ThreatSeverity.LOW:
            return actions.on_low
        else:
            return actions.on_info

    def check_tool_allowed(self, tool_name: str, session: SessionContext) -> bool:
        """Checks if a tool is allowed by the policy."""
        if self.policy.mode == 'disabled':
            return True
            
        allowed_tools = [t.name for t in self.policy.warden.allowed_tools]
        if not allowed_tools:
            return True

        return tool_name in allowed_tools

    def check_resource_limits(self, session: SessionContext) -> Optional[DetectionResult]:
        """Checks if a session exceeds configured resource limits."""
        if self.policy.mode == 'disabled':
            return None
        return None

    def check_network_allowed(self, domain: str) -> bool:
        """Checks if outbound network access to a domain is allowed."""
        if self.policy.mode == 'disabled':
            return True
            
        allowed = self.policy.warden.network.allowed_outbound
        denied = self.policy.warden.network.denied_outbound
        
        if '*' in denied and domain not in allowed:
            return False
            
        if domain in denied:
            return False
            
        return True

__all__ = ["PolicyEngine"]
