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

# Re-export patterns (centralized, deduplicated)
from aiohai.core.patterns import (
    BLOCKED_PATH_PATTERNS, TIER3_PATH_PATTERNS, FINANCIAL_PATH_PATTERNS,
    BLOCKED_COMMAND_PATTERNS, UAC_BYPASS_PATTERNS, CLIPBOARD_BLOCK_PATTERNS,
    INJECTION_PATTERNS, INVISIBLE_CHARS, HOMOGLYPHS, FULLWIDTH_MAP,
    DOH_SERVERS,
    MACRO_ENABLED_EXTENSIONS, SAFE_OFFICE_EXTENSIONS, OFFICE_SCANNABLE_EXTENSIONS,
    BLOCKED_EXCEL_FORMULAS, BLOCKED_EMBED_EXTENSIONS,
    BLOCKED_GRAPH_ENDPOINTS, BLOCKED_GRAPH_SCOPES,
    TRUSTED_DOCKER_REGISTRIES,
)

# Re-export constants
from aiohai.core.constants import (
    IS_WINDOWS,
    SESSION_ID_BYTES, APPROVAL_ID_BYTES, API_SECRET_BYTES,
    CHALLENGE_TOKEN_BYTES, REQUEST_ID_URL_BYTES,
    HASH_CHUNK_SIZE,
    HSM_HEALTH_CHECK_INTERVAL, APPROVAL_CLEANUP_AGE_MINUTES,
    FIDO2_CLIENT_MAX_RETRIES, FIDO2_CLIENT_RETRY_BACKOFF,
    SAFE_ENV_VARS, WHITELISTED_EXECUTABLES, DOCKER_COMMAND_TIERS,
)

# Re-export templates
from aiohai.core.templates import AGENTIC_INSTRUCTIONS, HELP_TEXT

# Re-export Phase 1 extracted classes
from aiohai.core.config import UnifiedConfig
from aiohai.core.audit.logger import SecurityLogger
from aiohai.core.audit.alerts import AlertManager

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
    # Patterns
    'BLOCKED_PATH_PATTERNS', 'TIER3_PATH_PATTERNS', 'FINANCIAL_PATH_PATTERNS',
    'BLOCKED_COMMAND_PATTERNS', 'UAC_BYPASS_PATTERNS', 'CLIPBOARD_BLOCK_PATTERNS',
    'INJECTION_PATTERNS', 'INVISIBLE_CHARS', 'HOMOGLYPHS', 'FULLWIDTH_MAP',
    'DOH_SERVERS',
    'MACRO_ENABLED_EXTENSIONS', 'SAFE_OFFICE_EXTENSIONS', 'OFFICE_SCANNABLE_EXTENSIONS',
    'BLOCKED_EXCEL_FORMULAS', 'BLOCKED_EMBED_EXTENSIONS',
    'BLOCKED_GRAPH_ENDPOINTS', 'BLOCKED_GRAPH_SCOPES',
    'TRUSTED_DOCKER_REGISTRIES',
    # Constants
    'IS_WINDOWS',
    'SESSION_ID_BYTES', 'APPROVAL_ID_BYTES', 'API_SECRET_BYTES',
    'CHALLENGE_TOKEN_BYTES', 'REQUEST_ID_URL_BYTES',
    'HASH_CHUNK_SIZE',
    'HSM_HEALTH_CHECK_INTERVAL', 'APPROVAL_CLEANUP_AGE_MINUTES',
    'FIDO2_CLIENT_MAX_RETRIES', 'FIDO2_CLIENT_RETRY_BACKOFF',
    'SAFE_ENV_VARS', 'WHITELISTED_EXECUTABLES', 'DOCKER_COMMAND_TIERS',
    # Templates
    'AGENTIC_INSTRUCTIONS', 'HELP_TEXT',
    # Phase 1 classes
    'UnifiedConfig', 'SecurityLogger', 'AlertManager',
]
