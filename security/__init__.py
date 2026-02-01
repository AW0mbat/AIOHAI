# Security components package

# Core security components
from .security_components import (
    StaticSecurityAnalyzer, PIIProtector, ResourceLimiter,
    DualLLMVerifier, MultiStageDetector, ResourceLimitExceeded,
    Severity, Verdict, SmartHomeConfigAnalyzer, SecureDockerComposeGenerator,
    CredentialRedactor, SensitiveOperationDetector, SessionTransparencyTracker,
    FamilyAccessControl, FamilyMember
)

# HSM integration (optional - requires PyKCS11)
try:
    from .hsm_integration import (
        get_hsm_manager, NitrokeyHSMManager, MockHSMManager,
        HSMStatus, PolicyVerificationResult, SignedLogEntry,
        HSMKeyInfo
    )
    HSM_AVAILABLE = True
except ImportError:
    HSM_AVAILABLE = False

# FIDO2/WebAuthn integration (optional - requires fido2, flask)
try:
    from .fido2_approval import (
        FIDO2ApprovalServer, FIDO2ApprovalClient,
        OperationClassifier, ApprovalTier, ApprovalStatus,
        UserRole, CredentialStore, HardwareApprovalRequest,
    )
    FIDO2_AVAILABLE = True
except ImportError:
    FIDO2_AVAILABLE = False


