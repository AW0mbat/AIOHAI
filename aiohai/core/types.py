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
# ENUMS — Approval Gate Taxonomy v3 (v5.2.0+)
# =============================================================================

class SecurityGate(Enum):
    """Security gates determine HOW the system verifies human authorization.

    Ordered by proof strength: DENY > PHYSICAL > BIOMETRIC > SOFTWARE > PASSIVE.

    Gate boundaries are immutable in code:
    - DENY gate items can NEVER be changed at runtime.
    - PHYSICAL → BIOMETRIC demotion requires code change + restart.
    - BIOMETRIC → SOFTWARE demotion requires code change + restart.
    - Within-gate review depth is freely adjustable at runtime.
    - Session elevation provides temporary gate step-down (not permanent demotion).
    """
    DENY = 0        # Action blocked — no verification possible
    PHYSICAL = 1    # NFC tap at server hardware — proves physical presence
    BIOMETRIC = 2   # WebAuthn challenge on any registered device — proves authenticator possession
    SOFTWARE = 3    # UI click/tap — proves someone at the UI session chose to approve
    PASSIVE = 4     # No active confirmation — action proceeds, user informed/logged

    def __lt__(self, other):
        if not isinstance(other, SecurityGate):
            return NotImplemented
        # Lower numeric value = MORE restrictive (DENY=0 is most restrictive)
        return self.value < other.value

    def __le__(self, other):
        if not isinstance(other, SecurityGate):
            return NotImplemented
        return self.value <= other.value

    def __gt__(self, other):
        if not isinstance(other, SecurityGate):
            return NotImplemented
        return self.value > other.value

    def __ge__(self, other):
        if not isinstance(other, SecurityGate):
            return NotImplemented
        return self.value >= other.value

    @property
    def is_hardware(self) -> bool:
        """True if this gate requires hardware authentication."""
        return self in (SecurityGate.PHYSICAL, SecurityGate.BIOMETRIC)

    @classmethod
    def from_level(cls, level: int) -> 'SecurityGate':
        """Derive gate from a TrustLevel numeric value (0-14)."""
        if level <= 1:
            return cls.DENY
        elif level <= 4:
            return cls.PHYSICAL
        elif level <= 7:
            return cls.BIOMETRIC
        elif level <= 10:
            return cls.SOFTWARE
        else:
            return cls.PASSIVE


class ActionCategory(Enum):
    """What an operation does — the verb dimension of action classification.

    10 categories replacing the previous 8-value ActionType enum.
    Ordered roughly by risk (OBSERVE lowest, ADMIN highest).
    """
    OBSERVE = "OBSERVE"         # Read/query without state change
    LIST = "LIST"               # Enumerate contents of a container
    CREATE = "CREATE"           # Make something new
    MODIFY = "MODIFY"           # Change something existing
    EXECUTE = "EXECUTE"         # Run a command or trigger a service action
    TRANSFER = "TRANSFER"       # Move, copy, or send data between locations
    DELETE = "DELETE"            # Remove something permanently
    CONFIGURE = "CONFIGURE"     # Change system/service configuration
    INSTALL = "INSTALL"         # Add or remove software/integrations
    ADMIN = "ADMIN"             # User, permission, or security management

    @classmethod
    def from_legacy_action_type(cls, action_type: str) -> 'ActionCategory':
        """Map legacy ActionType string values to ActionCategory.

        Used during migration from the old 6-action-type system.
        """
        mapping = {
            'READ': cls.OBSERVE,
            'FILE_READ': cls.OBSERVE,
            'WRITE': cls.MODIFY,
            'FILE_WRITE': cls.MODIFY,
            'DELETE': cls.DELETE,
            'FILE_DELETE': cls.DELETE,
            'LIST': cls.LIST,
            'DIRECTORY_LIST': cls.LIST,
            'COMMAND': cls.EXECUTE,
            'COMMAND_EXEC': cls.EXECUTE,
            'API_QUERY': cls.EXECUTE,
            'LOCAL_API_QUERY': cls.EXECUTE,
            'DOCUMENT_OP': cls.MODIFY,
            'NETWORK_REQUEST': cls.EXECUTE,
        }
        return mapping.get(action_type, cls.EXECUTE)


class TargetDomain(Enum):
    """What an action touches — the noun dimension of action classification.

    43 domains across filesystem, command, Home Assistant, and Office families.
    Domain names use the short notation from the taxonomy spec (e.g. fs.temp → FS_TEMP).
    """
    # --- Filesystem domains ---
    FS_TEMP = "FS_TEMP"             # Temp directories (low risk)
    FS_DL = "FS_DL"                 # Downloads folder
    FS_DOC = "FS_DOC"               # Documents (general)
    FS_DOC_SENS = "FS_DOC_SENS"     # Sensitive documents (financial, medical, legal)
    FS_DESK = "FS_DESK"             # Desktop
    FS_MEDIA = "FS_MEDIA"           # Pictures, Music, Videos
    FS_APPCONF = "FS_APPCONF"       # Application config files (AppData etc.)
    FS_AIOHAI = "FS_AIOHAI"         # AIOHAI's own files
    FS_SYSTEM = "FS_SYSTEM"         # OS system directories
    FS_CRED = "FS_CRED"             # Credential stores (.ssh, .gnupg, keychains)
    FS_NET = "FS_NET"               # Network-related files (hosts, adapters)

    # --- Command domains ---
    CMD_INFO = "CMD_INFO"           # Informational commands (systeminfo, whoami)
    CMD_FOPS = "CMD_FOPS"           # File operation commands (copy, move, rename)
    CMD_SVC = "CMD_SVC"             # Service management (sc, net start/stop)
    CMD_INST = "CMD_INST"           # Software installation (winget, pip, npm)
    CMD_SCRIPT = "CMD_SCRIPT"       # Script execution (python, node, powershell scripts)
    CMD_NET = "CMD_NET"             # Network commands (netsh, ipconfig, ping)
    CMD_ADMIN = "CMD_ADMIN"         # Admin commands (reg, bcdedit, sfc)
    CMD_DISK = "CMD_DISK"           # Disk commands (diskpart, format, chkdsk)

    # --- Home Assistant domains ---
    HA_SENS = "HA_SENS"             # Sensors (temperature, humidity, motion)
    HA_PRES = "HA_PRES"             # Presence/person entities
    HA_LIGHT = "HA_LIGHT"           # Lights
    HA_MEDIA = "HA_MEDIA"           # Media players
    HA_CLIM = "HA_CLIM"             # Climate/HVAC
    HA_COVER = "HA_COVER"           # Covers (blinds, shades)
    HA_GARAGE = "HA_GARAGE"         # Garage doors
    HA_LOCK = "HA_LOCK"             # Door locks
    HA_ALARM = "HA_ALARM"           # Alarm systems
    HA_CAM = "HA_CAM"               # Cameras
    HA_NOTIFY = "HA_NOTIFY"         # Notification services
    HA_SCENE = "HA_SCENE"           # Scenes
    HA_AUTO = "HA_AUTO"             # Automations
    HA_SCRIPT = "HA_SCRIPT"         # Scripts
    HA_HELPER = "HA_HELPER"         # Input helpers (input_boolean, counter, etc.)
    HA_CONF = "HA_CONF"             # HA configuration (YAML, integrations)

    # --- Office domains ---
    OFF_DOC = "OFF_DOC"             # Office documents (Word, Excel, PowerPoint)
    OFF_MACRO = "OFF_MACRO"         # Macros and VBA
    OFF_EREAD = "OFF_EREAD"         # Email reading
    OFF_ESEND = "OFF_ESEND"         # Email sending
    OFF_CAL = "OFF_CAL"             # Calendar
    OFF_CONT = "OFF_CONT"           # Contacts

    # --- Fallback ---
    UNKNOWN = "UNKNOWN"             # Unclassified target — defaults to CONFIRM_STANDARD (level 9)


class ApprovalLevel(Enum):
    """The 15-level approval taxonomy.

    Each level maps to exactly one SecurityGate and a review depth within that gate.
    Levels 0-1: DENY gate    (action does not execute)
    Levels 2-4: PHYSICAL gate (NFC tap at server)
    Levels 5-7: BIOMETRIC gate (authenticator challenge)
    Levels 8-10: SOFTWARE gate (UI confirmation)
    Levels 11-14: PASSIVE gate (automatic execution)
    """
    # DENY gate
    HARDBLOCK = 0               # Silently blocked, no path forward
    SOFTBLOCK = 1               # Blocked with explanation + change request log

    # PHYSICAL gate
    PHYSICAL_DETAILED = 2       # Full details + NFC tap (no timeout)
    PHYSICAL_STANDARD = 3       # Summary + NFC tap (no timeout)
    PHYSICAL_QUICK = 4          # One-line + NFC tap (no timeout)

    # BIOMETRIC gate
    BIOMETRIC_DETAILED = 5      # Full details + WebAuthn challenge (120s timeout)
    BIOMETRIC_STANDARD = 6      # Summary + WebAuthn challenge (60s timeout)
    BIOMETRIC_QUICK = 7         # One-line + WebAuthn challenge (30s timeout)

    # SOFTWARE gate
    CONFIRM_DETAILED = 8        # Full detail panel + CONFIRM/REJECT (60s auto-reject)
    CONFIRM_STANDARD = 9        # Summary card + CONFIRM/REJECT (30s auto-reject)
    CONFIRM_QUICK = 10          # Banner + ALLOW (10s auto-approve)

    # PASSIVE gate
    NOTIFY_AND_PROCEED = 11     # Toast + 15s UNDO button
    LOG_ONLY = 12               # Session transparency log only
    TRANSPARENT = 13            # Persistent audit trail only
    SILENT = 14                 # Minimal log (type + timestamp)

    @property
    def gate(self) -> SecurityGate:
        """Get the SecurityGate this level belongs to."""
        return SecurityGate.from_level(self.value)

    @property
    def is_blocked(self) -> bool:
        """True if this level blocks the action entirely."""
        return self.value <= 1

    @property
    def requires_confirmation(self) -> bool:
        """True if this level requires active user interaction."""
        return 2 <= self.value <= 10

    @property
    def is_passive(self) -> bool:
        """True if this level auto-executes without confirmation."""
        return self.value >= 11

    @property
    def timeout_seconds(self) -> Optional[int]:
        """Timeout for this level, or None if no timeout."""
        timeouts = {
            5: 120, 6: 60, 7: 30,   # BIOMETRIC
            8: 60, 9: 30, 10: 10,   # SOFTWARE
        }
        return timeouts.get(self.value)

    @property
    def auto_action_on_timeout(self) -> Optional[str]:
        """What happens on timeout: 'reject', 'approve', or None."""
        if self.value in (8, 9):
            return 'reject'
        if self.value == 10:
            return 'approve'
        return None


# =============================================================================
# ENUMS — From security/fido2_approval.py (legacy, being replaced by taxonomy)
# =============================================================================

class ApprovalTier(Enum):
    """Hardware approval tier classification.

    Tier 3: Any FIDO2 authenticator (platform biometric or roaming key)
    Tier 4: Roaming hardware key ONLY (YubiKey/Nitrokey physical tap required)
    """
    TIER_1 = 1  # No approval (list, read metadata)
    TIER_2 = 2  # Software approval (read/write non-sensitive)
    TIER_3 = 3  # FIDO2 approval — platform (biometric) or roaming key
    TIER_4 = 4  # FIDO2 approval — roaming hardware key ONLY (no biometric)


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
    required_authenticator: str = "any"  # 'any', 'security_key', 'platform'
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
            'required_authenticator': self.required_authenticator,
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

    # Approval Gate Taxonomy v3 (v5.2.0+)
    'SecurityGate',
    'ActionCategory',
    'TargetDomain',
    'ApprovalLevel',

    # Enums from proxy (legacy — being replaced by taxonomy)
    'SecurityLevel',
    'ActionType',
    'AlertSeverity',
    'TrustLevel',
    
    # Enums from security_components
    'Severity',
    'PIIType',
    'Verdict',
    
    # Enums from fido2_approval (legacy — being replaced by taxonomy)
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
