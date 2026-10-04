"""
Deadend AI — MCP (Model Context Protocol) Tool Poisoning Detector
==================================================================
Detects malicious prompt injection hidden inside MCP tool metadata
(names, descriptions, and schemas). This is the #1 new attack vector
in 2026: an attacker controls an MCP server and embeds hidden
directives in tool descriptions that hijack the agent's behavior.

Attack Vectors Covered
----------------------
1. **Tool Description Injection** — Hidden instructions inside tool
   ``description`` fields that instruct the model to exfiltrate data,
   ignore safety constraints, or execute unauthorized actions.
2. **Rug Pull Detection** — A previously-safe tool definition that
   changes between connections (description or schema mutation).
3. **Schema Manipulation** — Tool parameter schemas with suspiciously
   long descriptions or default values that contain executable payloads.
4. **Name Spoofing** — Tools whose names mimic trusted system tools
   (e.g., ``read_file`` vs ``read_flle``) to trick the agent.
"""
from __future__ import annotations

import re
from hashlib import sha256

import structlog

from deadend.sentinel.detectors.base import BaseDetector
from deadend.types import DetectionResult, SessionContext, ThreatSeverity, ThreatType

logger = structlog.get_logger(__name__)

__all__ = ["MCPPoisoningDetector"]

# ── Injection signatures commonly hidden in MCP tool descriptions ──
_INJECTION_PATTERNS = [
    # Direct instruction injection
    re.compile(r"(?i)\b(?:ignore|disregard|forget)\b.{0,30}\b(?:previous|prior|above|all)\b.{0,30}\b(?:instructions?|rules?|constraints?)\b"),
    # Role override / persona hijacking
    re.compile(r"(?i)\byou\s+(?:are|must|should|will)\s+(?:now|actually|really)\b"),
    re.compile(r"(?i)\b(?:act\s+as|pretend\s+to\s+be|assume\s+the\s+role)\b"),
    # Data exfiltration directives
    re.compile(r"(?i)\b(?:send|post|upload|transmit|exfiltrate|leak)\b.{0,40}\b(?:to|towards?|at)\s+(?:https?://|[a-z0-9.-]+\.[a-z]{2,})"),
    re.compile(r"(?i)\b(?:include|embed|attach|append)\b.{0,30}\b(?:api.?key|token|secret|password|credential|ssn|credit.?card)\b"),
    # System prompt extraction
    re.compile(r"(?i)\b(?:reveal|show|output|print|display|return)\b.{0,30}\b(?:system\s+prompt|instructions?|configuration|internal)\b"),
    # Invisible / hidden text markers
    re.compile(r"(?i)\[SYSTEM\]|\[INST\]|\[/INST\]|<\|im_start\|>|<\|im_end\|>|<<SYS>>|<</SYS>>"),
    # Encoded payload smuggling in descriptions
    re.compile(r"(?i)(?:eval|exec|import\s+os|subprocess|__import__|compile)\s*\("),
    # Unicode homoglyph obfuscation (Cyrillic/Greek lookalikes)
    re.compile(r"[\u0400-\u04FF\u0370-\u03FF]"),  # Cyrillic/Greek chars in tool metadata
]

# ── Suspicious structural signals ──
_MAX_DESCRIPTION_LENGTH = 1500  # Legitimate tool descriptions are rarely this long
_MAX_PARAM_DESCRIPTION_LENGTH = 500
_SUSPICIOUS_DESCRIPTION_RATIO = 0.4  # If >40% of chars are non-alphanumeric

# ── Common system tool names that attackers try to spoof ──
_TRUSTED_TOOL_NAMES = {
    "read_file", "write_file", "list_directory", "search_files",
    "run_command", "execute_code", "python_repl", "bash",
    "web_search", "browser", "read_url", "fetch_url",
    "send_email", "create_issue", "git_commit",
}

# ── Homoglyph confusables for tool name spoofing detection ──
_CONFUSABLE_MAP = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y",
    "і": "i", "ј": "j", "ѕ": "s", "ɡ": "g", "ɩ": "l", "ɪ": "i",
    "ʀ": "r", "ᴏ": "o", "ᴜ": "u",
}


class MCPPoisoningDetector(BaseDetector):
    """Detects malicious prompt injection hidden in MCP tool metadata.

    This detector scans the ``name``, ``description``, and ``parameters``
    of MCP tool definitions for hidden directives, structural anomalies,
    and rug-pull mutations.

    Args:
        max_description_length: Flag descriptions longer than this.
        track_mutations: If True, maintain a hash registry to detect
            tool definitions that change between connections.
    """

    def __init__(
        self,
        max_description_length: int = _MAX_DESCRIPTION_LENGTH,
        track_mutations: bool = True,
    ) -> None:
        self.max_description_length = max_description_length
        self.track_mutations = track_mutations
        # Registry: tool_name -> sha256(description + schema)
        self._tool_registry: dict[str, str] = {}

    @property
    def name(self) -> str:
        return "mcp_poisoning_detector"

    def _hash_tool(self, tool_def: dict) -> str:
        """Compute a stable hash of a tool definition for mutation tracking."""
        canonical = f"{tool_def.get('name', '')}|{tool_def.get('description', '')}|{tool_def.get('inputSchema', '')}"
        return sha256(canonical.encode()).hexdigest()[:16]

    def _check_injection_patterns(self, text: str) -> list[str]:
        """Scan text against known injection patterns."""
        findings = []
        for pattern in _INJECTION_PATTERNS:
            if pattern.search(text):
                findings.append(f"Injection pattern detected: /{pattern.pattern[:60].strip()}.../")
        return findings

    def _check_structural_anomalies(self, tool_def: dict) -> list[str]:
        """Check for structural red flags in the tool definition."""
        findings = []
        description = tool_def.get("description", "")

        # Excessively long description (common injection vector)
        if len(description) > self.max_description_length:
            findings.append(
                f"Suspiciously long description ({len(description)} chars, "
                f"max {self.max_description_length})"
            )

        # High ratio of non-alphanumeric characters (encoded payloads)
        if description:
            non_alnum = sum(1 for c in description if not c.isalnum() and not c.isspace())
            ratio = non_alnum / len(description)
            if ratio > _SUSPICIOUS_DESCRIPTION_RATIO:
                findings.append(
                    f"High non-alphanumeric ratio in description ({ratio:.0%})"
                )

        # Check parameter descriptions too
        schema = tool_def.get("inputSchema", {})
        if isinstance(schema, dict):
            for prop_name, prop_def in schema.get("properties", {}).items():
                param_desc = prop_def.get("description", "")
                if len(param_desc) > _MAX_PARAM_DESCRIPTION_LENGTH:
                    findings.append(
                        f"Parameter '{prop_name}' has suspiciously long "
                        f"description ({len(param_desc)} chars)"
                    )
                # Check for injection in parameter descriptions
                param_findings = self._check_injection_patterns(param_desc)
                if param_findings:
                    findings.extend(
                        f"In parameter '{prop_name}': {f}" for f in param_findings
                    )
                # Check default values for executable content
                default_val = str(prop_def.get("default", ""))
                if re.search(r"(?i)(?:eval|exec|import|subprocess|__import__|curl|wget)\s*\(", default_val):
                    findings.append(
                        f"Parameter '{prop_name}' has suspicious default value"
                    )

        return findings

    def _check_name_spoofing(self, tool_name: str) -> list[str]:
        """Detect tool names that mimic trusted system tools via homoglyphs."""
        findings = []

        # Normalize the tool name by replacing confusable characters
        normalized = tool_name
        for fake_char, real_char in _CONFUSABLE_MAP.items():
            normalized = normalized.replace(fake_char, real_char)

        # If normalization changed the name AND the normalized version
        # matches a trusted tool, this is a spoofing attempt
        if normalized != tool_name and normalized in _TRUSTED_TOOL_NAMES:
            findings.append(
                f"Tool name '{tool_name}' appears to spoof trusted tool "
                f"'{normalized}' using homoglyph characters"
            )

        # Check for subtle typosquatting (edit distance = 1)
        for trusted in _TRUSTED_TOOL_NAMES:
            if tool_name != trusted and len(tool_name) == len(trusted):
                diffs = sum(1 for a, b in zip(tool_name, trusted, strict=True) if a != b)
                if diffs == 1:
                    findings.append(
                        f"Tool name '{tool_name}' is suspiciously similar to "
                        f"trusted tool '{trusted}' (1 character difference)"
                    )

        return findings

    def _check_rug_pull(self, tool_def: dict) -> list[str]:
        """Detect tool definitions that changed since last seen (rug pull)."""
        if not self.track_mutations:
            return []

        findings = []
        tool_name = tool_def.get("name", "unknown")
        current_hash = self._hash_tool(tool_def)

        if tool_name in self._tool_registry:
            previous_hash = self._tool_registry[tool_name]
            if current_hash != previous_hash:
                findings.append(
                    f"RUG PULL: Tool '{tool_name}' definition changed since "
                    f"last connection (prev={previous_hash}, now={current_hash})"
                )
                logger.critical(
                    "MCP rug pull detected",
                    tool=tool_name,
                    prev_hash=previous_hash,
                    new_hash=current_hash,
                )

        # Update registry
        self._tool_registry[tool_name] = current_hash
        return findings

    async def scan_tool(self, tool_def: dict) -> DetectionResult:
        """Scan a single MCP tool definition for poisoning.

        Args:
            tool_def: A dictionary representing the MCP tool, typically
                containing ``name``, ``description``, and ``inputSchema``.

        Returns:
            DetectionResult indicating whether the tool is poisoned.
        """
        all_findings: list[str] = []
        tool_name = tool_def.get("name", "unknown")
        description = tool_def.get("description", "")

        # 1. Check for injection patterns in description
        all_findings.extend(self._check_injection_patterns(description))

        # 2. Check structural anomalies
        all_findings.extend(self._check_structural_anomalies(tool_def))

        # 3. Check name spoofing
        all_findings.extend(self._check_name_spoofing(tool_name))

        # 4. Check rug pull
        all_findings.extend(self._check_rug_pull(tool_def))

        is_poisoned = len(all_findings) > 0

        if is_poisoned:
            # Determine severity based on findings
            has_rug_pull = any("RUG PULL" in f for f in all_findings)
            has_injection = any("Injection pattern" in f for f in all_findings)
            has_spoofing = any("spoof" in f.lower() for f in all_findings)

            if has_rug_pull or has_injection:
                severity = ThreatSeverity.CRITICAL
            elif has_spoofing:
                severity = ThreatSeverity.HIGH
            else:
                severity = ThreatSeverity.MEDIUM

            logger.warning(
                "MCP tool poisoning detected",
                tool=tool_name,
                severity=severity.value,
                findings=all_findings,
            )
        else:
            severity = ThreatSeverity.INFO

        return DetectionResult(
            detected=is_poisoned,
            threat_type=ThreatType.PROMPT_INJECTION if is_poisoned else None,
            severity=severity,
            confidence=0.95 if is_poisoned else 0.0,
            details={
                "tool_name": tool_name,
                "findings": all_findings,
                "tool_hash": self._hash_tool(tool_def),
            } if is_poisoned else {},
            detector_name=self.name,
        )

    async def scan_server(self, tools: list[dict]) -> list[DetectionResult]:
        """Scan all tools from an MCP server connection.

        Args:
            tools: List of MCP tool definitions from the server.

        Returns:
            List of DetectionResults, one per tool.
        """
        results = []
        for tool_def in tools:
            result = await self.scan_tool(tool_def)
            results.append(result)
        return results

    async def detect(
        self, text: str, context: SessionContext | None = None
    ) -> DetectionResult:
        """Standard detector interface — scans raw text for MCP-style injection.

        This allows the MCP detector to be used in the standard Sentinel
        pipeline (e.g., scanning raw tool descriptions passed as text).
        """
        findings = self._check_injection_patterns(text)

        is_threat = len(findings) > 0
        return DetectionResult(
            detected=is_threat,
            threat_type=ThreatType.PROMPT_INJECTION if is_threat else None,
            severity=ThreatSeverity.HIGH if is_threat else ThreatSeverity.INFO,
            confidence=0.9 if is_threat else 0.0,
            details={"findings": findings} if is_threat else {},
            detector_name=self.name,
        )
