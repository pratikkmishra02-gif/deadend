from __future__ import annotations

import hashlib
import json

from .logger import AuditLogger
from .events import AuditEvent

__all__ = ["CryptoAuditLogger"]


class CryptoAuditLogger(AuditLogger):
    """Tamper-proof audit logger."""

    def __init__(self, destination: str = 'stdout', format: str = 'json', include_prompts: bool = False) -> None:
        super().__init__(destination, format, include_prompts)
        self._last_hash = None

    async def log(self, event: AuditEvent) -> None:
        """Write structured audit event with hash chain."""
        event.previous_hash = self._last_hash
        event.hash = self._compute_hash(event)
        self._last_hash = event.hash
        
        await super().log(event)

    def _compute_hash(self, event: AuditEvent) -> str:
        """Compute SHA256 hash of event data + previous hash."""
        event_dict = event.model_dump(exclude={'hash'})
        if 'timestamp' in event_dict:
            event_dict['timestamp'] = event_dict['timestamp'].isoformat()
            
        # Serialize stably
        event_json = json.dumps(event_dict, sort_keys=True, default=str)
        return hashlib.sha256(event_json.encode('utf-8')).hexdigest()

    def verify_chain(self, events: list[AuditEvent]) -> bool:
        """Verifies integrity of entire chain."""
        if not events:
            return True
            
        expected_prev_hash = None
        
        for event in events:
            if event.previous_hash != expected_prev_hash:
                return False
                
            computed_hash = self._compute_hash(event)
            if event.hash != computed_hash:
                return False
                
            expected_prev_hash = event.hash
            
        return True
