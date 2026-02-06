"""
AIOHAI Core Types — Shared enums, dataclasses, and exceptions.

This module centralizes all type definitions used across the AIOHAI codebase.
All layers (Core, Integrations, Proxy, Agent) import types from here.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Dict, List, Optional


# =============================================================================
# EXCEPTIONS
# =============================================================================

class SecurityError(Exception):
    """Base exception for all AIOHAI security errors."""
    pass


class NetworkSecurityError(SecurityError):
    """Raised when a network operation violates security policy."""
    pass


class ResourceLimitExceeded(Exception):
    """Raised when a resource limit (CPU, memory, file ops, etc.) is exceeded."""
    pass


# =============================================================================
# ENUMS — From proxy/aiohai_proxy.py
# =============================================================================

class SecurityLevel(Enum):
    """Classification of security level for an operation or path."""
    BLOCKED = auto()   # Never allowed, hard block
    CRITICAL = auto()  # Requires Tier 3 FIDO2 approval
    ELEVATED = auto()  # Requires Tier 2 software approval
    STANDARD = auto()  # Allowed with logging
    ALLOWED = auto()   # Allowed without restriction


class ActionType(Enum):
    """Types of actions the AI can request."""
    FILE_READ = auto()
    FILE_WRITE = auto()
    FILE_DELETE = auto()
    COMMAND_EXEC = auto()
    DIRECTORY_LIST = auto()
    NETWORK_REQUEST = auto()
    LOCAL_API_QUERY = auto()
    DOCUMENT_OP = auto()


class AlertSeverity(Enum):
    """Severity levels for security alerts."""
    INFO = "info"
    WARNING = "warning"
    HIGH = "high"
    CRITICAL = "critical"


class TrustLevel(Enum):
    """Trust classification for content sources."""
    TRUSTED = auto()    # Known safe source
    UNTRUSTED = auto()  # Unknown source, treat with caution
    HOSTILE = auto()    # Detected malicious patterns


# =============================================================================
# ENUMS — From security/security_components.py
# =============================================================================

class Severity(Enum):
    """Severity levels for static analysis findings."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class PIIType(Enum):
    """Types of personally identifiable information detected."""
    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    IP_ADDRESS = "ip_address"
    USERNAME = "username"
    FILEPATH_WITH_USER = "filepath_with_user"
    AWS_KEY = "aws_key"
    API_KEY = "api_key"
    PRIVATE_KEY = "private_key"
    PASSWORD = "password"


class Verdict(Enum):
    """Safety verdict from security analysis."""
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"
    BLOCKED = "blocked"


# =============================================================================
# ENUMS — From security/fido2_approval.py
# =============================================================================

class ApprovalTier(Enum):
    """Hardware approval tier classification."""
    TIER_1 = 1  # No approval (list, read metadata)
    TIER_2 = 2  # Software approval (read/write non-sensitive)
    TIER_3 = 3  # Hardware approval (DELETE, sensitive, bulk)
    TIER_4 = 4  # Physical server presence (policy, HSM, users)


class ApprovalStatus(Enum):
    """Status of an approval request."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class UserRole(Enum):
    """User role for access control."""
    ADMIN = "admin"
    TRUSTED_ADULT = "trusted"
    RESTRICTED = "restricted"
    GUEST = "guest"


# =============================================================================
# ENUMS — From security/hsm_integration.py
# =============================================================================

class HSMStatus(Enum):
    """HSM connection status."""
    NOT_INITIALIZED = "not_initialized"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"
    PIN_REQUIRED = "pin_required"
    PIN_LOCKED = "pin_locked"


# =============================================================================
# DATACLASSES — From security/security_components.py
# =============================================================================

@dataclass
class SecurityFinding:
    """Result from static security analysis."""
    severity: Severity
    category: str
    message: str
    line: Optional[int]
    code_snippet: str
    cwe_id: Optional[str] = None
    remediation: Optional[str] = None


@dataclass
class PIIFinding:
    """Detected PII in content."""
    pii_type: PIIType
    value: str
    start: int
    end: int
    confidence: float


@dataclass
class VerificationResult:
    """Result from dual-LLM verification."""
    verdict: Verdict
    risk_score: int
    concerns: List[str]
    recommendation: str
    reasoning: str


@dataclass
class ResourceLimits:
    """Configuration for resource limiting (DoS protection)."""
    max_execution_time_seconds: int = 30
    max_session_time_minutes: int = 60
    max_memory_mb: int = 512
    max_memory_percent: float = 25.0
    max_cpu_percent: float = 50.0
    max_disk_write_mb: int = 100
    max_file_size_mb: int = 50
    max_files_created: int = 100
    max_requests_per_minute: int = 60
    max_actions_per_minute: int = 30
    max_concurrent_actions: int = 5
    max_output_size_bytes: int = 1_000_000


# =============================================================================
# DATACLASSES — From security/fido2_approval.py
# =============================================================================

@dataclass
class RegisteredCredential:
    """A WebAuthn credential registered to a user."""
    credential_id: bytes
    public_key: bytes
    sign_count: int
    authenticator_type: str  # 'security_key' or 'platform'
    device_name: str
    registered_at: str
    last_used: str = ""

    def to_dict(self) -> dict:
        """Serialize to JSON-safe dictionary."""
        return {
            'credential_id': base64.urlsafe_b64encode(self.credential_id).decode(),
            'public_key': base64.urlsafe_b64encode(self.public_key).decode(),
            'sign_count': self.sign_count,
            'authenticator_type': self.authenticator_type,
            'device_name': self.device_name,
            'registered_at': self.registered_at,
            'last_used': self.last_used,
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'RegisteredCredential':
        """Deserialize from dictionary."""
        return cls(
            credential_id=base64.urlsafe_b64decode(d['credential_id']),
            public_key=base64.urlsafe_b64decode(d['public_key']),
            sign_count=d['sign_count'],
            authenticator_type=d['authenticator_type'],
            device_name=d['device_name'],
            registered_at=d['registered_at'],
            last_used=d.get('last_used', ''),
        )


@dataclass
class RegisteredUser:
    """A user with registered WebAuthn credentials."""
    user_id: bytes
    username: str
    role: UserRole
    credentials: List[RegisteredCredential] = field(default_factory=list)
    created_at: str = ""
    allowed_paths: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialize to JSON-safe dictionary."""
        return {
            'user_id': base64.urlsafe_b64encode(self.user_id).decode(),
            'username': self.username,
            'role': self.role.value,
            'credentials': [c.to_dict() for c in self.credentials],
            'created_at': self.created_at,
            'allowed_paths': self.allowed_paths,
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'RegisteredUser':
        """Deserialize from dictionary."""
        return cls(
            user_id=base64.urlsafe_b64decode(d['user_id']),
            username=d['username'],
            role=UserRole(d['role']),
            credentials=[RegisteredCredential.from_dict(c) for c in d.get('credentials', [])],
            created_at=d.get('created_at', ''),
            allowed_paths=d.get('allowed_paths', []),
        )


@dataclass
class HardwareApprovalRequest:
    """A request requiring hardware (FIDO2) approval."""
    request_id: str
    operation_type: str
    target: str
    description: str
    tier: ApprovalTier
    status: ApprovalStatus = ApprovalStatus.PENDING
    required_role: UserRole = UserRole.ADMIN
    approved_by: str = ""
    authenticator_used: str = ""
    created_at: str = ""
    expires_at: str = ""
    approved_at: str = ""
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize to JSON-safe dictionary."""
        return {
            'request_id': self.request_id,
            'operation_type': self.operation_type,
            'target': self.target,
            'description': self.description,
            'tier': self.tier.value,
            'status': self.status.value,
            'required_role': self.required_role.value,
            'approved_by': self.approved_by,
            'authenticator_used': self.authenticator_used,
            'created_at': self.created_at,
            'expires_at': self.expires_at,
            'approved_at': self.approved_at,
            'metadata': self.metadata,
        }

    def is_expired(self) -> bool:
        """Check if this approval request has expired."""
        if not self.expires_at:
            return False
        return datetime.fromisoformat(self.expires_at) < datetime.now()


# =============================================================================
# DATACLASSES — From security/hsm_integration.py
# =============================================================================

@dataclass
class HSMKeyInfo:
    """Information about a key stored in HSM."""
    label: str
    key_type: str  # 'RSA', 'EC', 'AES'
    key_id: bytes
    can_sign: bool = False
    can_verify: bool = False
    can_encrypt: bool = False
    can_decrypt: bool = False
    is_private: bool = False


@dataclass
class SignedLogEntry:
    """A log entry with HSM signature for tamper evidence."""
    timestamp: str
    event_type: str
    data: Dict[str, Any]
    entry_hash: str
    signature: str  # Base64 encoded
    previous_hash: str  # Chain link


@dataclass
class PolicyVerificationResult:
    """Result of policy signature verification."""
    is_valid: bool
    policy_hash: str
    signature_date: Optional[str] = None
    signer_key_id: Optional[str] = None
    error_message: Optional[str] = None


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Exceptions
    'SecurityError',
    'NetworkSecurityError',
    'ResourceLimitExceeded',
    
    # Enums from proxy
    'SecurityLevel',
    'ActionType',
    'AlertSeverity',
    'TrustLevel',
    
    # Enums from security_components
    'Severity',
    'PIIType',
    'Verdict',
    
    # Enums from fido2_approval
    'ApprovalTier',
    'ApprovalStatus',
    'UserRole',
    
    # Enums from hsm_integration
    'HSMStatus',
    
    # Dataclasses from security_components
    'SecurityFinding',
    'PIIFinding',
    'VerificationResult',
    'ResourceLimits',
    
    # Dataclasses from fido2_approval
    'RegisteredCredential',
    'RegisteredUser',
    'HardwareApprovalRequest',
    
    # Dataclasses from hsm_integration
    'HSMKeyInfo',
    'SignedLogEntry',
    'PolicyVerificationResult',
]
