"""
AIOHAI Core — Accessor-Agnostic Trust Infrastructure

This layer provides security primitives that treat all accessors uniformly:
the AI agent, the user at the keyboard, scripts, and future companion apps
all go through the same security gates.

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

Quick imports:
    from aiohai.core import PathValidator, CommandValidator
    from aiohai.core import FIDO2ApprovalClient, get_hsm_manager
    from aiohai.core import SecurityLevel, ApprovalTier
    from aiohai.core.version import __version__, POLICY_FILENAME
"""

# Re-export version constants
from aiohai.core.version import (
    __version__,
    POLICY_FILENAME,
    CONFIG_SCHEMA_VERSION,
    ALLOWED_FRAMEWORK_NAMES,
)

# Re-export commonly used items at package level
from aiohai.core.types import (
    # Exceptions
    SecurityError,
    NetworkSecurityError,
    ResourceLimitExceeded,
    # Enums
    SecurityLevel,
    ActionType,
    AlertSeverity,
    TrustLevel,
    Severity,
    PIIType,
    Verdict,
    ApprovalTier,
    ApprovalStatus,
    UserRole,
    HSMStatus,
    # Dataclasses
    SecurityFinding,
    PIIFinding,
    VerificationResult,
    ResourceLimits,
    RegisteredCredential,
    RegisteredUser,
    HardwareApprovalRequest,
    HSMKeyInfo,
    SignedLogEntry,
    PolicyVerificationResult,
)

__all__ = [
    # Version constants
    '__version__', 'POLICY_FILENAME', 'CONFIG_SCHEMA_VERSION', 'ALLOWED_FRAMEWORK_NAMES',
    # All types
    'SecurityError', 'NetworkSecurityError', 'ResourceLimitExceeded',
    'SecurityLevel', 'ActionType', 'AlertSeverity', 'TrustLevel',
    'Severity', 'PIIType', 'Verdict',
    'ApprovalTier', 'ApprovalStatus', 'UserRole', 'HSMStatus',
    'SecurityFinding', 'PIIFinding', 'VerificationResult', 'ResourceLimits',
    'RegisteredCredential', 'RegisteredUser', 'HardwareApprovalRequest',
    'HSMKeyInfo', 'SignedLogEntry', 'PolicyVerificationResult',
]
