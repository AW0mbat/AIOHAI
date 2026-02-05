#!/usr/bin/env python3
"""
AIOHAI Core Analysis — PII Protector
======================================
PII detection and redaction:
- Email addresses, phone numbers, SSNs, credit card numbers
- IP addresses, AWS keys, API keys, private keys, passwords
- Dynamic detection of username, computer name, user profile path
- Confidence-scored findings

Previously defined inline in security/security_components.py.
Extracted as Phase 2b of the monolith → layered architecture migration.

Import from: aiohai.core.analysis.pii_protector
"""

import os
import re
from typing import List, Dict, Tuple, Set

from aiohai.core.types import PIIType, PIIFinding


class PIIProtector:
    """Comprehensive PII detection and redaction."""

    PATTERNS = {
        PIIType.EMAIL: (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 0.95),
        PIIType.PHONE: (r'\b(?:\+1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b', 0.8),
        PIIType.SSN: (r'\b\d{3}-\d{2}-\d{4}\b', 0.95),
        PIIType.CREDIT_CARD: (r'\b(?:\d{4}[-\s]?){3}\d{4}\b', 0.9),
        PIIType.IP_ADDRESS: (r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', 0.85),
        PIIType.AWS_KEY: (r'\b(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b', 0.99),
        PIIType.API_KEY: (r'(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,})["\']?', 0.9),
        PIIType.PRIVATE_KEY: (r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', 0.99),
        PIIType.PASSWORD: (r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{4,})["\']?', 0.85),
    }

    def __init__(self):
        self.username = os.environ.get('USERNAME', '')
        self.userprofile = os.environ.get('USERPROFILE', '')
        self.computername = os.environ.get('COMPUTERNAME', '')
        self.compiled = {t: (re.compile(p, re.I), c) for t, (p, c) in self.PATTERNS.items()}

    def detect_pii(self, text: str) -> List[PIIFinding]:
        findings = []

        for pii_type, (pattern, confidence) in self.compiled.items():
            for match in pattern.finditer(text):
                findings.append(PIIFinding(
                    pii_type=pii_type, value=match.group()[:50],
                    start=match.start(), end=match.end(), confidence=confidence
                ))

        # Dynamic detection
        if self.username:
            for match in re.finditer(re.escape(self.username), text, re.I):
                findings.append(PIIFinding(
                    pii_type=PIIType.USERNAME, value=self.username,
                    start=match.start(), end=match.end(), confidence=0.99
                ))

        return findings

    def redact_pii(self, text: str, types: Set[PIIType] = None) -> Tuple[str, List[PIIFinding]]:
        if types is None:
            types = set(PIIType)

        findings = self.detect_pii(text)
        findings.sort(key=lambda f: f.start, reverse=True)

        for f in findings:
            if f.pii_type in types:
                placeholder = f"[REDACTED_{f.pii_type.value.upper()}]"
                text = text[:f.start] + placeholder + text[f.end:]

        return text, findings

    def redact_for_logging(self, text: str) -> str:
        text, _ = self.redact_pii(text)
        if self.username:
            text = re.sub(re.escape(self.username), '[USER]', text, flags=re.I)
        if self.userprofile:
            text = re.sub(re.escape(self.userprofile), '[USERPROFILE]', text, flags=re.I)
            text = re.sub(re.escape(self.userprofile.replace('\\', '/')), '[USERPROFILE]', text, flags=re.I)
        if self.computername:
            text = re.sub(re.escape(self.computername), '[COMPUTER]', text, flags=re.I)
        return text

    def check_response_for_pii(self, response: str) -> Dict:
        findings = self.detect_pii(response)
        critical = {PIIType.SSN, PIIType.CREDIT_CARD, PIIType.PRIVATE_KEY, PIIType.AWS_KEY, PIIType.PASSWORD}
        critical_findings = [f for f in findings if f.pii_type in critical]

        return {
            'contains_pii': len(findings) > 0,
            'total_findings': len(findings),
            'critical_count': len(critical_findings),
            'pii_types': list(set(f.pii_type.value for f in findings)),
            'should_block': len(critical_findings) > 0,
        }


__all__ = [
    'PIIProtector',
    'PIIType',
    'PIIFinding',
]
