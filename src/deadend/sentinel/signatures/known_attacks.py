from __future__ import annotations

from typing import Any

INJECTION_PATTERNS: list[dict[str, Any]] = [
    {"pattern": r"(?i)\bignore\s+(all\s+)?(previous|prior|above)\s+(instructions|directions|prompts|rules)\b", "description": "Ignore previous instructions", "severity": "CRITICAL", "source": "common"},
    {"pattern": r"(?i)\bdisregard\s+(the\s+)?above\b", "description": "Disregard above", "severity": "HIGH", "source": "common"},
    {"pattern": r"(?i)\byou\s+are\s+now\b", "description": "Identity override", "severity": "HIGH", "source": "common"},
    {"pattern": r"(?i)\b(act|roleplay|pretend)\s+as\b", "description": "Roleplay request", "severity": "MEDIUM", "source": "common"},
    {"pattern": r"(?i)^(system\s+prompt|new\s+instructions|override|admin\s+mode)\s*:", "description": "System instruction impersonation", "severity": "CRITICAL", "source": "common"},
    {"pattern": r"(?i)\bdo\s+not\s+follow\b", "description": "Instruction defiance", "severity": "HIGH", "source": "common"},
    {"pattern": r"(?i)\bforget\s+(everything|all)\b", "description": "Memory reset override", "severity": "HIGH", "source": "common"},
    {"pattern": r"(?i)\breset\s+your\b", "description": "Reset system override", "severity": "HIGH", "source": "common"},
    {"pattern": r"(?i)\byou\s+(must\s+obey|will\s+comply)\b", "description": "Forced compliance", "severity": "HIGH", "source": "common"},
    {"pattern": r"(?i)\bfrom\s+now\s+on\s+you\b", "description": "Future behavior override", "severity": "HIGH", "source": "common"},
    {"pattern": r"(?i)\b(translate|repeat|print|output)\s+(the\s+)?above\b", "description": "System prompt leakage attempt", "severity": "HIGH", "source": "common"},
    {"pattern": r"(?i)(^|\n)human\s*:", "description": "Conversation injection (Human)", "severity": "HIGH", "source": "common"},
    {"pattern": r"(?i)(^|\n)assistant\s*:", "description": "Conversation injection (Assistant)", "severity": "HIGH", "source": "common"},
    {"pattern": r"(?i)\b(IMPORTANT|CRITICAL|URGENT)\s*:\s*(ignore|new\s+instructions|override)", "description": "Urgent instruction override", "severity": "CRITICAL", "source": "common"},
    {"pattern": r"```(system|instructions)", "description": "Markdown injection", "severity": "HIGH", "source": "common"},
    {"pattern": r"</?(system|instructions|prompt)>", "description": "XML tag injection", "severity": "HIGH", "source": "common"},
    {"pattern": r"\[INST\]", "description": "Llama style instruction injection", "severity": "HIGH", "source": "common"},
]

JAILBREAK_PATTERNS: list[dict[str, Any]] = [
    {"pattern": r"(?i)\bDAN\b.*\b(do\s+anything\s+now)\b", "description": "DAN (Do Anything Now) jailbreak", "severity": "CRITICAL", "source": "known_jailbreaks"},
    {"pattern": r"(?i)\bjailbroken\b", "description": "Jailbreak keyword", "severity": "HIGH", "source": "known_jailbreaks"},
    {"pattern": r"(?i)\bAIM\b.*\b(always\s+intelligent\s+and\s+machiavellian)\b", "description": "AIM jailbreak", "severity": "CRITICAL", "source": "known_jailbreaks"},
    {"pattern": r"(?i)\b(unfiltered|uncensored|no\s+restrictions|without\s+limits)\b", "description": "Uncensored persona request", "severity": "HIGH", "source": "known_jailbreaks"},
    {"pattern": r"(?i)\b(hypothetically|in\s+a\s+fictional\s+scenario|for\s+educational\s+purposes)\b", "description": "Hypothetical/Educational framing bypass", "severity": "MEDIUM", "source": "known_jailbreaks"},
    {"pattern": r"(?i)\bopposite\s+day\b", "description": "Opposite day logic subversion", "severity": "MEDIUM", "source": "known_jailbreaks"},
    {"pattern": r"(?i)\brespond\s+with\s+the\s+opposite\b", "description": "Opposite response logic subversion", "severity": "HIGH", "source": "known_jailbreaks"},
    {"pattern": r"(?i)\b(developer|god|sudo|debug)\s+mode\b", "description": "Privileged mode request", "severity": "CRITICAL", "source": "known_jailbreaks"},
    {"pattern": r"(?i)^(sure,\s+here\s+is|absolutely,\s+I\s+can)", "description": "Prefix injection / Assent forcing", "severity": "HIGH", "source": "known_jailbreaks"},
]

ENCODING_BYPASS_PATTERNS: list[dict[str, Any]] = [
    {"pattern": r"(?i)base64", "description": "Base64 encoding mentioned", "severity": "LOW", "source": "encoding"},
    {"pattern": r"(?i)rot13", "description": "ROT13 encoding mentioned", "severity": "LOW", "source": "encoding"},
    {"pattern": r"\\x[0-9a-fA-F]{2}", "description": "Hex encoding pattern", "severity": "LOW", "source": "encoding"},
    {"pattern": r"0x[0-9a-fA-F]{2}", "description": "Hex encoding pattern (0x)", "severity": "LOW", "source": "encoding"},
    {"pattern": r"(?i)(u202E|u202B)", "description": "Right-To-Left override character", "severity": "HIGH", "source": "encoding"},
]

INDIRECT_PATTERNS: list[dict[str, Any]] = [
    {"pattern": r"(?i)IMPORTANT\s+INSTRUCTIONS\s+FOR\s+AI", "description": "Indirect instruction marker", "severity": "CRITICAL", "source": "indirect"},
    {"pattern": r"(?i)BEGIN\s+HIDDEN\s+PROMPT", "description": "Hidden prompt marker", "severity": "CRITICAL", "source": "indirect"},
    {"pattern": r"<!--.*?-->", "description": "HTML comment potentially hiding instructions", "severity": "LOW", "source": "indirect"},
]
