from __future__ import annotations

from typing import Any, Dict
import yaml
from pydantic import ValidationError

from deadend.policy.models import SecurityPolicy
from deadend.exceptions import PolicyLoadError, PolicyValidationError

def load_policy(path: str) -> SecurityPolicy:
    """Loads a YAML policy file and returns a SecurityPolicy model."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        return load_policy_from_dict(data)
    except FileNotFoundError as e:
        raise PolicyLoadError(f"Policy file not found: {path}") from e
    except yaml.YAMLError as e:
        raise PolicyLoadError(f"Failed to parse YAML policy: {e}") from e

def load_policy_from_dict(data: Dict[str, Any]) -> SecurityPolicy:
    """Creates a SecurityPolicy model from a dictionary."""
    try:
        return SecurityPolicy(**data)
    except ValidationError as e:
        raise PolicyValidationError(f"Invalid policy data: {e}") from e

__all__ = ["load_policy", "load_policy_from_dict"]
