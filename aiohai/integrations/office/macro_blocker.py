#!/usr/bin/env python3
"""
AIOHAI Integrations — Office Macro Blocker
============================================
Hard block on macro-enabled document creation and VBA execution.

This is a security-critical class — macros in Office documents are
a primary malware delivery vector.

Previously defined in proxy/aiohai_proxy.py.
Extracted as Phase 4b of the monolith → layered architecture migration.

Import from: aiohai.integrations.office.macro_blocker
"""

import re
from pathlib import Path
from typing import Tuple

from aiohai.core.types import AlertSeverity
from aiohai.core.audit.logger import SecurityLogger
from aiohai.core.patterns import MACRO_ENABLED_EXTENSIONS


class MacroBlocker:
    """
    Hard block on macro-enabled document creation and VBA execution.

    This is a security-critical class — macros in Office documents are
    a primary malware delivery vector.
    """

    def __init__(self, logger: SecurityLogger):
        self.logger = logger

    def check_extension(self, file_path: str) -> Tuple[bool, str]:
        """
        Check if a file extension is allowed for creation.

        Returns:
            (allowed, reason) — False + reason if blocked
        """
        ext = Path(file_path).suffix.lower()

        if ext in MACRO_ENABLED_EXTENSIONS:
            self.logger.log_event("MACRO_DOCUMENT_BLOCKED", AlertSeverity.HIGH,
                                  {'path': str(file_path)[:200], 'extension': ext})
            return False, (f"Macro-enabled format '{ext}' is blocked. "
                          f"Use the macro-free equivalent instead: "
                          f"{self._suggest_safe_alternative(ext)}")

        return True, ''

    def scan_content_for_vba(self, content: str) -> Tuple[bool, str]:
        """
        Scan content for VBA/macro indicators.

        Returns:
            (safe, reason) — False + reason if VBA content detected
        """
        vba_indicators = [
            (r'(?i)\bSub\s+\w+\s*\(', 'VBA Sub procedure'),
            (r'(?i)\bFunction\s+\w+\s*\(', 'VBA Function'),
            (r'(?i)\bDim\s+\w+\s+As\s+', 'VBA variable declaration'),
            (r'(?i)\bSet\s+\w+\s*=\s*CreateObject', 'COM object creation'),
            (r'(?i)\bShell\s*\(', 'Shell command execution'),
            (r'(?i)\bApplication\.Run\b', 'Application.Run call'),
            (r'(?i)\bApplication\.VBE\b', 'VBA Editor access'),
            (r'(?i)\bWScript\.Shell\b', 'WScript Shell access'),
            (r'(?i)\bActiveX', 'ActiveX control'),
            (r'(?i)\bCreateObject\s*\(\s*["\']', 'COM object instantiation'),
            (r'(?i)\bAutoOpen\b', 'Auto-execute macro'),
            (r'(?i)\bAuto_Open\b', 'Auto-execute macro'),
            (r'(?i)\bWorkbook_Open\b', 'Workbook open event'),
            (r'(?i)\bDocument_Open\b', 'Document open event'),
        ]

        found = []
        for pattern, description in vba_indicators:
            if re.search(pattern, content):
                found.append(description)

        if found:
            self.logger.log_event("VBA_CONTENT_BLOCKED", AlertSeverity.HIGH,
                                  {'indicators': found[:5]})
            return False, f"VBA/macro content detected: {', '.join(found[:3])}"

        return True, ''

    def check_command_for_macro_execution(self, command: str) -> Tuple[bool, str]:
        """
        Check if a command attempts to execute Office macros.

        Returns:
            (safe, reason)
        """
        macro_patterns = [
            (r'(?i)wscript\s+', 'WScript execution'),
            (r'(?i)cscript\s+', 'CScript execution'),
            (r'(?i)\.vbs\b', 'VBScript file'),
            (r'(?i)\.vbe\b', 'Encoded VBScript'),
            (r'(?i)winword.*/m', 'Word with macro switch'),
            (r'(?i)excel.*/e', 'Excel with macro switch'),
            (r'(?i)Application\.Run', 'Office macro execution'),
            (r'(?i)mshta\b', 'HTML Application host'),
        ]

        for pattern, description in macro_patterns:
            if re.search(pattern, command):
                self.logger.log_event("MACRO_EXECUTION_BLOCKED", AlertSeverity.HIGH,
                                      {'command': command[:100], 'reason': description})
                return False, f"Macro execution blocked: {description}"

        return True, ''

    def _suggest_safe_alternative(self, blocked_ext: str) -> str:
        """Suggest macro-free alternative for a blocked extension."""
        alternatives = {
            '.xlsm': '.xlsx', '.xltm': '.xltx', '.xlam': '.xlsx',
            '.xlsb': '.xlsx',
            '.docm': '.docx', '.dotm': '.dotx',
            '.pptm': '.pptx', '.potm': '.potx', '.ppam': '.pptx',
        }
        return alternatives.get(blocked_ext, '.docx/.xlsx/.pptx')


__all__ = ['MacroBlocker']
