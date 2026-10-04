import os

import structlog
import yaml

from deadend.policy.models import SecurityPolicy

logger = structlog.get_logger(__name__)

__all__ = ["PolicyLoader"]


class PolicyLoader:
    """Loads and validates a Deadend YAML policy file."""
    
    DEFAULT_POLICY_LOCations = [
        "deadend-policy.yaml",
        "deadend-policy.yml",
        ".deadend/policy.yaml",
        ".deadend/policy.yml"
    ]
    
    @classmethod
    def load(cls, filepath: str | None = None) -> SecurityPolicy:
        """
        Load policy from the specified filepath, or search default locations.
        If no file is found, returns the default permissive policy.
        """
        target_path = None
        
        if filepath:
            target_path = filepath
        else:
            for path in cls.DEFAULT_POLICY_LOCations:
                if os.path.exists(path):
                    target_path = path
                    break
                    
        if not target_path or not os.path.exists(target_path):
            logger.debug("No deadend policy file found, using defaults.")
            # Note: SecurityPolicy requires metadata. We mock it for the default case.
            return SecurityPolicy(metadata={"name": "default", "version": "1.0"})
            
        try:
            with open(target_path, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                
            policy = SecurityPolicy(**data)
            logger.info("Loaded deadend security policy", path=target_path, mode=policy.mode)
            return policy
            
        except Exception as e:
            logger.error("Failed to load policy file", error=str(e), path=target_path)
            # Fall back to safe default for runtime stability, but log loudly.
            return SecurityPolicy(metadata={"name": "default", "version": "1.0"})
