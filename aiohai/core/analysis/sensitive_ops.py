#!/usr/bin/env python3
"""
AIOHAI Core Analysis — Sensitive Operation Detector
=====================================================
Categorizes operations by sensitivity level:
- Financial, credentials, personal, family, security, work
- Keyword-based detection with compiled regex patterns
- Severity-ranked warning formatting

Previously defined inline in security/security_components.py.
Extracted as Phase 2b of the monolith → layered architecture migration.

Import from: aiohai.core.analysis.sensitive_ops
"""

import re
from typing import List, Dict


class SensitiveOperationDetector:
    """Detects and categorizes sensitive operations for user awareness."""

    CATEGORIES = {
        'financial': {
            'keywords': ['quicken', 'bank', 'tax', 'payment', 'credit', 'debit',
                        'account', 'money', 'financial', 'invoice', 'payroll',
                        'salary', 'wage', 'budget', 'investment', 'stock', 'crypto',
                        'wallet', 'trading', 'brokerage', 'retirement', '401k', 'ira'],
            'icon': '\U0001f4b0',
            'severity': 'HIGH',
        },
        'credentials': {
            'keywords': ['password', 'credential', 'secret', 'key', 'token',
                        '.ssh', 'id_rsa', 'id_ed25519', '.gnupg', 'pgp',
                        'keychain', 'vault', 'lastpass', '1password', 'bitwarden',
                        'keepass', '.kdbx', 'auth', 'login', 'api_key', 'apikey'],
            'icon': '\U0001f510',
            'severity': 'CRITICAL',
        },
        'personal': {
            'keywords': ['medical', 'health', 'doctor', 'hospital', 'prescription',
                        'diagnosis', 'insurance', 'legal', 'attorney', 'lawyer',
                        'divorce', 'custody', 'court', 'social security', 'ssn',
                        'passport', 'license', 'birth certificate', 'will', 'estate'],
            'icon': '\U0001f464',
            'severity': 'HIGH',
        },
        'family': {
            'keywords': ['kids', 'children', 'school', 'grades', 'report card',
                        'family', 'photos', 'pictures', 'videos', 'memories',
                        'diary', 'journal', 'private', 'personal'],
            'icon': '\U0001f468\u200d\U0001f469\u200d\U0001f467\u200d\U0001f466',
            'severity': 'MEDIUM',
        },
        'security': {
            'keywords': ['camera', 'surveillance', 'alarm', 'security code',
                        'pin', 'combination', 'safe', 'lock', 'access code',
                        'gate code', 'garage code', 'entry'],
            'icon': '\U0001f512',
            'severity': 'HIGH',
        },
        'work': {
            'keywords': ['confidential', 'proprietary', 'nda', 'trade secret',
                        'business', 'client', 'contract', 'agreement', 'employee'],
            'icon': '\U0001f4bc',
            'severity': 'MEDIUM',
        },
    }

    def __init__(self):
        self.patterns = {}
        for category, data in self.CATEGORIES.items():
            pattern = '|'.join(re.escape(kw) for kw in data['keywords'])
            self.patterns[category] = re.compile(pattern, re.I)

    def detect(self, target: str, content: str = "") -> List[Dict]:
        """Detect sensitive operations and return matching categories."""
        combined = f"{target} {content}".lower()
        matches = []

        for category, pattern in self.patterns.items():
            if pattern.search(combined):
                cat_data = self.CATEGORIES[category]
                matches.append({
                    'category': category,
                    'icon': cat_data['icon'],
                    'severity': cat_data['severity'],
                })

        return matches

    def format_warning(self, matches: List[Dict]) -> str:
        """Format sensitivity warning for display."""
        if not matches:
            return ""

        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        matches.sort(key=lambda m: severity_order.get(m['severity'], 99))

        icons = ' '.join(m['icon'] for m in matches)
        categories = ', '.join(m['category'].upper() for m in matches)
        highest_severity = matches[0]['severity']

        if highest_severity == 'CRITICAL':
            return f"\U0001f6a8 **CRITICAL SENSITIVE DATA:** {icons} {categories}"
        elif highest_severity == 'HIGH':
            return f"\u26a0\ufe0f **SENSITIVE:** {icons} {categories}"
        else:
            return f"\u2139\ufe0f **Note:** Involves {categories} data"


__all__ = ['SensitiveOperationDetector']
