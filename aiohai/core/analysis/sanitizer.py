#!/usr/bin/env python3
"""
AIOHAI Core Analysis — Content Sanitizer
==========================================
Content sanitization with:
- Injection pattern detection (40+ patterns)
- Invisible Unicode character stripping
- Homoglyph and fullwidth character normalization
- Obfuscation detection (base64, hex escapes, decode functions)
- Trust level assignment for external content

Previously defined inline in proxy/aiohai_proxy.py.
Extracted as Phase 2a of the monolith → layered architecture migration.

Import from: aiohai.core.analysis.sanitizer
"""

import re
from typing import Tuple, List, Dict

from aiohai.core.types import AlertSeverity, TrustLevel
from aiohai.core.patterns import (
    INJECTION_PATTERNS,
    INVISIBLE_CHARS,
    HOMOGLYPHS,
    FULLWIDTH_MAP,
)


class ContentSanitizer:
    """Sanitizes input for injection attacks with enhanced detection."""

    def __init__(self, logger, alerts):
        self.logger = logger
        self.alerts = alerts
        self.injection_patterns = [re.compile(p, re.I | re.M) for p in INJECTION_PATTERNS]

    def sanitize(self, content: str, source: str = "unknown") -> Tuple[str, List[Dict], TrustLevel]:
        warnings = []
        trust_level = TrustLevel.UNTRUSTED

        # 1. Remove invisible characters
        for char in INVISIBLE_CHARS:
            if char in content:
                warnings.append({'type': 'INVISIBLE_CHAR', 'char': f'U+{ord(char):04X}'})
                content = content.replace(char, '')

        # 2. Normalize homoglyphs
        for cyrillic, latin in HOMOGLYPHS.items():
            if cyrillic in content:
                warnings.append({'type': 'HOMOGLYPH', 'char': f'U+{ord(cyrillic):04X}'})
                content = content.replace(cyrillic, latin)

        # 3. Normalize fullwidth
        for fw, ascii_char in FULLWIDTH_MAP.items():
            if fw in content:
                warnings.append({'type': 'FULLWIDTH', 'char': fw})
                content = content.replace(fw, ascii_char)

        # 4. Detect injection patterns
        for pattern in self.injection_patterns:
            if pattern.search(content):
                warnings.append({'type': 'INJECTION', 'pattern': pattern.pattern[:40]})
                trust_level = TrustLevel.HOSTILE

        # 5. Detect obfuscation in content
        obfuscation_patterns = [
            (r'[A-Za-z0-9+/]{50,}={0,2}', 'Long base64'),
            (r'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}', 'Hex escapes'),
            (r'\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){5,}', 'Unicode escapes'),
            (r'(?i)frombase64|b64decode|bytes\.fromhex', 'Decode function'),
        ]
        for pattern, desc in obfuscation_patterns:
            if re.search(pattern, content):
                warnings.append({'type': 'OBFUSCATION', 'desc': desc})
                trust_level = TrustLevel.HOSTILE

        if trust_level == TrustLevel.HOSTILE:
            self.alerts.alert(AlertSeverity.HIGH, "INJECTION_DETECTED",
                            f"Hostile content from {source}",
                            {'warnings': len(warnings)})

        if warnings:
            self.logger.log_event("CONTENT_SANITIZED", AlertSeverity.WARNING,
                                 {'source': source, 'warnings': len(warnings)})

        return content, warnings, trust_level


__all__ = [
    'ContentSanitizer',
    'INJECTION_PATTERNS',
    'TrustLevel',
]
