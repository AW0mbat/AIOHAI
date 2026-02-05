#!/usr/bin/env python3
"""
AIOHAI Core Audit — Alert Manager
===================================
Desktop notifications and alert routing with background processing.

Previously defined inline in proxy/aiohai_proxy.py.
Extracted as Phase 1 of the monolith → layered architecture migration.

Import from: aiohai.core.audit.alerts
"""

import queue
import threading
from typing import Dict

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


class AlertManager:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.alert_queue = queue.Queue()
        self.running = True
        self.thread = threading.Thread(target=self._process, daemon=True)
        self.thread.start()

    def alert(self, severity: AlertSeverity, title: str, message: str, details: Dict = None) -> None:
        self.alert_queue.put({'severity': severity, 'title': title, 'message': message})
        self.logger.log_event(title, severity, {'message': message, **(details or {})})

    def _process(self):
        while self.running:
            try:
                alert = self.alert_queue.get(timeout=1)
                self._deliver(alert)
            except queue.Empty:
                continue

    def _deliver(self, alert: Dict):
        severity = alert['severity']
        colors = {AlertSeverity.INFO: '\033[94m', AlertSeverity.WARNING: '\033[93m',
                  AlertSeverity.HIGH: '\033[91m', AlertSeverity.CRITICAL: '\033[95m'}
        reset = '\033[0m'
        print(f"{colors.get(severity, '')}{severity.value.upper()}: {alert['title']}{reset}")

        if self.config.enable_desktop_alerts and IS_WINDOWS and _CTYPES_AVAILABLE and severity == AlertSeverity.CRITICAL:
            try:
                ctypes.windll.user32.MessageBoxW(0, alert['message'][:500],
                                                 f"AIOHAI: {alert['title']}", 0x10)
            except Exception:
                pass  # Desktop alert is best-effort


__all__ = ['AlertManager']
