#!/usr/bin/env python3
"""
AIOHAI Integrations — Office Document Content Scanner
======================================================
Scans document content BEFORE writing to detect PII, credentials,
dangerous formulas, external references, and blocked embedded objects.

Uses existing PIIProtector and CredentialRedactor for detection,
adds Office-specific scanning on top.

Previously defined in proxy/aiohai_proxy.py.
Extracted as Phase 4b of the monolith → layered architecture migration.

Import from: aiohai.integrations.office.document_scanner
"""

import re
from typing import Dict, List

from aiohai.core.types import AlertSeverity
from aiohai.core.audit.logger import SecurityLogger
from aiohai.core.patterns import BLOCKED_EXCEL_FORMULAS


class DocumentContentScanner:
    """
    Scans document content BEFORE writing to detect PII, credentials,
    dangerous formulas, external references, and blocked embedded objects.

    Uses existing PIIProtector and CredentialRedactor for detection,
    adds Office-specific scanning on top.
    """

    def __init__(self, logger: SecurityLogger,
                 pii_protector=None, credential_redactor=None):
        self.logger = logger
        self.pii_protector = pii_protector
        self.credential_redactor = credential_redactor
        self._formula_patterns = [re.compile(p) for p in BLOCKED_EXCEL_FORMULAS]

    def scan(self, content: str, file_type: str = '',
             filename: str = '') -> Dict:
        """
        Scan document content for security issues.

        Returns:
            Dict with keys: safe (bool), findings (list), should_block (bool),
                           pii_findings (list), formula_issues (list),
                           credential_issues (list)
        """
        result = {
            'safe': True,
            'should_block': False,
            'findings': [],
            'pii_findings': [],
            'formula_issues': [],
            'credential_issues': [],
            'external_refs': [],
        }

        # 1. PII detection
        if self.pii_protector:
            pii_findings = self.pii_protector.detect_pii(content)
            result['pii_findings'] = pii_findings

            # Check for critical PII
            critical_types = {'ssn', 'credit_card', 'private_key', 'aws_key'}
            has_critical = any(f.get('pii_type', '').lower() in critical_types
                              or getattr(f, 'pii_type', '').lower() in critical_types
                              for f in pii_findings)
            if has_critical:
                result['should_block'] = True
                result['findings'].append({
                    'severity': 'CRITICAL',
                    'type': 'critical_pii',
                    'message': 'Critical PII detected (SSN, credit card, or key material)',
                })
            elif pii_findings:
                result['findings'].append({
                    'severity': 'WARNING',
                    'type': 'pii_detected',
                    'message': f'{len(pii_findings)} PII item(s) detected',
                })

        # 2. Credential detection
        if self.credential_redactor:
            original = content
            redacted = self.credential_redactor.redact(content)
            if redacted != original:
                result['credential_issues'].append({
                    'severity': 'WARNING',
                    'message': 'Credential-like patterns found in content',
                })
                result['findings'].append({
                    'severity': 'WARNING',
                    'type': 'credentials_detected',
                    'message': 'Content contains patterns matching credentials',
                })

        # 3. Excel formula safety (for spreadsheet content)
        if file_type in ('.xlsx', '.xls', '.csv', '.tsv'):
            formula_issues = self._scan_formulas(content)
            result['formula_issues'] = formula_issues
            if formula_issues:
                result['should_block'] = True
                result['findings'].append({
                    'severity': 'CRITICAL',
                    'type': 'dangerous_formula',
                    'message': f'{len(formula_issues)} blocked formula(s) detected',
                })

        # 4. CSV injection check
        if file_type in ('.csv', '.tsv'):
            csv_issues = self._scan_csv_injection(content)
            if csv_issues:
                result['findings'].append({
                    'severity': 'WARNING',
                    'type': 'csv_injection_risk',
                    'message': f'{len(csv_issues)} cell(s) with formula injection risk',
                })

        # 5. External reference detection
        ext_refs = self._scan_external_references(content)
        result['external_refs'] = ext_refs
        if ext_refs:
            result['findings'].append({
                'severity': 'WARNING',
                'type': 'external_references',
                'message': f'{len(ext_refs)} external reference(s) detected',
            })

        result['safe'] = len(result['findings']) == 0

        if result['findings']:
            self.logger.log_event("DOCUMENT_CONTENT_SCAN", AlertSeverity.WARNING,
                                  {'file_type': file_type, 'filename': filename,
                                   'findings': len(result['findings']),
                                   'should_block': result['should_block']})

        return result

    def _scan_formulas(self, content: str) -> List[Dict]:
        """Check for blocked Excel formulas."""
        issues = []
        for i, line in enumerate(content.split('\n'), 1):
            for pattern in self._formula_patterns:
                if pattern.search(line):
                    issues.append({
                        'line': i,
                        'pattern': pattern.pattern[:40],
                        'content': line[:80],
                    })
        return issues

    def _scan_csv_injection(self, content: str) -> List[Dict]:
        """Detect CSV injection patterns."""
        issues = []
        dangerous_prefixes = ('=', '+', '-', '@', '\t', '\r')
        for i, line in enumerate(content.split('\n'), 1):
            for cell in line.split(','):
                cell = cell.strip().strip('"').strip("'")
                if cell and cell[0] in dangerous_prefixes:
                    # Exception: negative numbers are fine
                    if cell[0] == '-':
                        try:
                            float(cell)
                            continue
                        except ValueError:
                            pass
                    issues.append({'line': i, 'cell': cell[:40]})
        return issues

    def _scan_external_references(self, content: str) -> List[Dict]:
        """Detect external URLs, UNC paths, and data connections."""
        refs = []
        # UNC paths
        unc_pattern = re.compile(r'\\\\[^\s\\]+\\[^\s]+')
        for match in unc_pattern.finditer(content):
            refs.append({'type': 'unc_path', 'value': match.group()[:60]})

        # External URLs in formulas or content
        url_pattern = re.compile(r'https?://[^\s"\'<>]+', re.I)
        for match in url_pattern.finditer(content):
            url = match.group()
            # Allow localhost
            if '127.0.0.1' in url or 'localhost' in url:
                continue
            refs.append({'type': 'external_url', 'value': url[:80]})

        return refs

    def get_scan_summary(self, scan_result: Dict) -> str:
        """Format scan results for user display."""
        if scan_result['safe']:
            return "✅ Document content scan: clean"

        lines = ["⚠️ Document Content Scan Results:"]
        for finding in scan_result['findings']:
            icon = '🔴' if finding['severity'] == 'CRITICAL' else '🟡'
            lines.append(f"  {icon} [{finding['severity']}] {finding['message']}")

        if scan_result['should_block']:
            lines.append("\n❌ Operation blocked — critical issues found.")
            lines.append("   Resolve critical items or confirm to proceed.")

        return '\n'.join(lines)


__all__ = ['DocumentContentScanner']
