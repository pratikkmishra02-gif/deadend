from __future__ import annotations

import base64
import codecs
import re
import urllib.parse
import html
from typing import Optional

from phalanx_ai.types import DetectionResult, SessionContext, ThreatType, ThreatSeverity
from phalanx_ai.sentinel.detectors.base import BaseDetector
from phalanx_ai.sentinel.signatures.known_attacks import ENCODING_BYPASS_PATTERNS
from phalanx_ai.sentinel.detectors.injection import InjectionDetector

class EncodingDetector(BaseDetector):
    """Detects encoded or obfuscated attacks."""

    def __init__(self, decode_depth: int = 3):
        self.decode_depth = decode_depth
        self._compiled_patterns = [
            (re.compile(p["pattern"], re.IGNORECASE), p)
            for p in ENCODING_BYPASS_PATTERNS
        ]
        # Re-use injection detector logic on decoded strings
        self._injection_detector = InjectionDetector(sensitivity=0.6)

    @property
    def name(self) -> str:
        return 'encoding_detector'

    def _decode_layer(self, text: str) -> tuple[str, list[str]]:
        """Attempt various decodings on the text. Returns (decoded_text, list_of_methods_applied)."""
        methods_applied = []
        decoded = text
        
        # URL Decoding
        if '%' in decoded:
            url_decoded = urllib.parse.unquote(decoded)
            if url_decoded != decoded:
                decoded = url_decoded
                methods_applied.append("url_decode")

        # HTML Entity Decoding
        if '&' in decoded and ';' in decoded:
            html_decoded = html.unescape(decoded)
            if html_decoded != decoded:
                decoded = html_decoded
                methods_applied.append("html_decode")

        # Base64 Detection & Decoding
        b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
        b64_matches = b64_pattern.findall(decoded)
        for match in b64_matches:
            if len(match) > 16:  # Only bother with sufficiently long base64 strings
                try:
                    b64_decoded = base64.b64decode(match).decode('utf-8')
                    decoded = decoded.replace(match, b64_decoded)
                    methods_applied.append("base64_decode")
                except Exception:
                    pass

        # Hex Decoding (\x41 or 0x41)
        if r'\x' in decoded or '0x' in decoded:
            try:
                # Naive cleanup for common hex representation
                cleaned = re.sub(r'\\x([0-9A-Fa-f]{2})', lambda m: chr(int(m.group(1), 16)), decoded)
                cleaned = re.sub(r'0x([0-9A-Fa-f]{2})', lambda m: chr(int(m.group(1), 16)), cleaned)
                if cleaned != decoded:
                    decoded = cleaned
                    methods_applied.append("hex_decode")
            except Exception:
                pass
                
        # ROT13
        # It's hard to definitively know if it's ROT13 unless we re-evaluate it with heuristics, 
        # but we can tentatively decode it and see if words emerge, or rely on recursive checking.
        rot13_decoded = codecs.encode(decoded, 'rot_13')
        # We will keep both variations for the deep scan if needed, but for simplicity here we 
        # won't inline replace it unless requested, as it destroys plaintext.
        # However, if 'rot13' signature was found, it might be worth checking.

        return decoded, methods_applied

    async def detect(self, text: str, context: Optional[SessionContext] = None) -> DetectionResult:
        flags = []
        
        # 1. Signature matching for known encoding tricks
        for regex, meta in self._compiled_patterns:
            if regex.search(text):
                flags.append(meta["description"])

        # 2. Recursive Decoding
        current_text = text
        all_methods = []
        for _ in range(self.decode_depth):
            current_text, methods = self._decode_layer(current_text)
            if not methods:
                break
            all_methods.extend(methods)
            
        is_threat = False
        severity = ThreatSeverity.LOW
        confidence = 0.0
        details = {"encoding_flags": flags, "methods_applied": list(set(all_methods))}
        
        # 3. Check decoded text for payloads if decoding occurred
        if all_methods:
            # Check with injection detector
            inj_result = await self._injection_detector.detect(current_text, context)
            if inj_result.detected:
                is_threat = True
                severity = ThreatSeverity.HIGH
                confidence = max(0.8, inj_result.confidence)
                details["decoded_payload_threat"] = inj_result.threat_type.name
                details["decoded_payload_details"] = inj_result.details

        # Fallback to pure signature if no payload found but bad chars present
        if not is_threat and len(flags) > 0:
            is_threat = True
            severity = ThreatSeverity.MEDIUM
            confidence = 0.6
            
        if is_threat:
            return DetectionResult(
                detected=True,
                threat_type=ThreatType.OBFUSCATION,
                severity=severity,
                confidence=confidence,
                detector_name=self.name,
                details=details
            )

        return DetectionResult(
            detected=False,
            threat_type=ThreatType.OBFUSCATION,
            severity=ThreatSeverity.INFO,
            confidence=0.0,
            detector_name=self.name,
            details={}
        )

__all__ = ["EncodingDetector"]
