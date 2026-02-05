#!/usr/bin/env python3
"""
AIOHAI Core Audit — Startup Security Verifier
===============================================
Pre-flight security checks run before the proxy accepts any requests:
- Blocks execution as Administrator/root
- DLL directory hardening
- Debugger detection
- Suspicious environment variable detection

Previously defined inline in proxy/aiohai_proxy.py.
Extracted as Phase 2a of the monolith → layered architecture migration.

Import from: aiohai.core.audit.startup
"""

import os
from typing import Tuple, List

from aiohai.core.types import AlertSeverity
from aiohai.core.constants import IS_WINDOWS

if IS_WINDOWS:
    try:
        import ctypes
        _CTYPES_AVAILABLE = True
    except ImportError:
        _CTYPES_AVAILABLE = False
else:
    _CTYPES_AVAILABLE = False


class StartupSecurityVerifier:
    def __init__(self, config, logger, alerts):
        self.config = config
        self.logger = logger
        self.alerts = alerts

    def verify_all(self) -> Tuple[bool, List[str]]:
        issues = []

        if self.config.refuse_admin and not self._verify_not_admin():
            issues.append("CRITICAL: Running as Administrator")
            return False, issues

        if self.config.verify_dll_integrity:
            issues.extend(self._check_dll())

        if self._is_debugger():
            issues.append("WARNING: Debugger attached")
            self.alerts.alert(AlertSeverity.HIGH, "DEBUGGER_DETECTED", "Debugger attached")

        issues.extend(self._check_env())

        critical = [i for i in issues if i.startswith("CRITICAL")]
        return len(critical) == 0, issues

    def _verify_not_admin(self) -> bool:
        if not IS_WINDOWS or not _CTYPES_AVAILABLE:
            return True
        try:
            if ctypes.windll.shell32.IsUserAnAdmin():
                self.alerts.alert(AlertSeverity.CRITICAL, "RUNNING_AS_ADMIN",
                                "Must NOT run as Administrator!")
                return False
            return True
        except Exception:
            return True  # Assume non-admin if check unavailable

    def _check_dll(self) -> List[str]:
        issues = []
        if IS_WINDOWS and _CTYPES_AVAILABLE:
            try:
                ctypes.windll.kernel32.SetDllDirectoryW("")
            except Exception:
                pass  # DLL directory hardening is best-effort
        return issues

    def _is_debugger(self) -> bool:
        if IS_WINDOWS and _CTYPES_AVAILABLE:
            try:
                return bool(ctypes.windll.kernel32.IsDebuggerPresent())
            except Exception:
                pass  # Debugger check unavailable on this platform
        return False

    def _check_env(self) -> List[str]:
        issues = []
        bad_vars = ['OLLAMA_OVERRIDE', 'LLM_BYPASS', 'DEBUG_MODE', 'SKIP_SECURITY']
        for var in bad_vars:
            if os.environ.get(var):
                issues.append(f"WARNING: Suspicious env: {var}")
        return issues


__all__ = ['StartupSecurityVerifier']
