"""
Audit Layer — Logging, integrity, transparency, alerts.

Classes:
- SecurityLogger: Tamper-evident logging with chain hashing and HSM signing
- IntegrityVerifier: SHA-256 monitoring of policy + framework files
- SessionTransparencyTracker: Records all actions for the REPORT command
- AlertManager: Desktop notifications and alert routing
"""

from aiohai.core.audit.logger import SecurityLogger, AlertSeverity
from aiohai.core.audit.integrity import IntegrityVerifier, ALLOWED_FRAMEWORK_NAMES
from aiohai.core.audit.transparency import SessionTransparencyTracker
from aiohai.core.audit.alerts import AlertManager

__all__ = [
    'SecurityLogger',
    'AlertSeverity',
    'IntegrityVerifier',
    'ALLOWED_FRAMEWORK_NAMES',
    'SessionTransparencyTracker',
    'AlertManager',
]
