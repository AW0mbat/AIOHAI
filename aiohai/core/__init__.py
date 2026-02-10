"""
AIOHAI Core — Accessor-Agnostic Trust Infrastructure

Submodules:
- version   : Version constants (single source of truth)
- types     : Shared enums, dataclasses, exceptions
- config    : Configuration management
- access/   : Path validation, command validation, session management
- crypto/   : HSM integration, FIDO2/WebAuthn, credential storage
- audit/    : Logging, integrity verification, transparency tracking, alerts
- analysis/ : Content sanitization, PII protection, static analysis
- network/  : Socket-level network interception
- resources/: Resource limiting (DoS protection)

Import directly from submodules for best experience:
    from aiohai.core.types import SecurityLevel, ApprovalTier
    from aiohai.core.config import UnifiedConfig
    from aiohai.core.version import __version__, POLICY_FILENAME

O6: Trimmed re-exports to genuinely public API items.
Patterns, constants, and templates should be imported from their own modules.
"""

from aiohai.core.version import __version__
from aiohai.core.types import (
    SecurityError, SecurityLevel, ActionType, AlertSeverity,
    ApprovalTier, ApprovalStatus, UserRole,
    # Approval Gate Taxonomy v3 (v5.2.0+)
    SecurityGate, ActionCategory, TargetDomain, ApprovalLevel,
)
from aiohai.core.config import UnifiedConfig

__all__ = [
    '__version__',
    'SecurityError', 'SecurityLevel', 'ActionType', 'AlertSeverity',
    'ApprovalTier', 'ApprovalStatus', 'UserRole',
    'SecurityGate', 'ActionCategory', 'TargetDomain', 'ApprovalLevel',
    'UnifiedConfig',
]
