#!/usr/bin/env python3
"""
AIOHAI Core Analysis — Credential Redactor
============================================
Redacts sensitive credentials from text for safe display:
- Passwords, API keys, tokens, bearer tokens
- AWS credentials, private keys
- Connection strings (MongoDB, PostgreSQL, etc.)
- RTSP/streaming URLs with embedded credentials
- Credit card numbers, SSNs

Previously defined inline in security/security_components.py.
Extracted as Phase 2b of the monolith → layered architecture migration.

Import from: aiohai.core.analysis.credentials
"""

import re


class CredentialRedactor:
    """Redacts sensitive credentials from text for safe display."""

    REDACTION_PATTERNS = [
        (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\'<>]{3,})["\']?', r'\1: [REDACTED]'),
        (r'(?i)(pass)\s*[:=]\s*["\']?([^\s"\'<>]{3,})["\']?', r'\1: [REDACTED]'),
        (r'(rtsp|rtmp|http|https)://([^:]+):([^@]+)@', r'\1://\2:[REDACTED]@'),
        (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9_-]{16,})["\']?', r'\1: [REDACTED]'),
        (r'(?i)(secret[_-]?key|secretkey)\s*[:=]\s*["\']?([A-Za-z0-9_-]{16,})["\']?', r'\1: [REDACTED]'),
        (r'(?i)(access[_-]?token|accesstoken)\s*[:=]\s*["\']?([A-Za-z0-9_-]{16,})["\']?', r'\1: [REDACTED]'),
        (r'(?i)(auth[_-]?token|authtoken)\s*[:=]\s*["\']?([A-Za-z0-9_-]{16,})["\']?', r'\1: [REDACTED]'),
        (r'(?i)(bearer)\s+([A-Za-z0-9_-]{20,})', r'\1 [REDACTED]'),
        (r'(?i)(aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*["\']?(AKIA[A-Z0-9]{16})["\']?', r'\1: [REDACTED]'),
        (r'(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', r'\1: [REDACTED]'),
        (r'-----BEGIN[^-]+PRIVATE KEY-----[\s\S]*?-----END[^-]+PRIVATE KEY-----', '[REDACTED PRIVATE KEY]'),
        (r'(?i)(mongodb|postgresql|mysql|redis|amqp)://([^:]+):([^@]+)@', r'\1://\2:[REDACTED]@'),
        (r'(?i)(secret|token|credential|auth)\s*:\s*["\']?([^\s"\']{8,})["\']?', r'\1: [REDACTED]'),
        (r'\b(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})\b', '[REDACTED CC]'),
        (r'\b(\d{3}-\d{2}-\d{4})\b', '[REDACTED SSN]'),
    ]

    def __init__(self):
        self.compiled = [(re.compile(p, re.I | re.M), r) for p, r in self.REDACTION_PATTERNS]

    def redact(self, text: str) -> str:
        """Redact all sensitive credentials from text."""
        for pattern, replacement in self.compiled:
            text = pattern.sub(replacement, text)
        return text

    def redact_for_preview(self, text: str, max_length: int = 100) -> str:
        """Redact and truncate for safe preview display."""
        redacted = self.redact(text)
        redacted = ' '.join(redacted.split())
        if len(redacted) > max_length:
            return redacted[:max_length] + '...'
        return redacted


__all__ = ['CredentialRedactor']
