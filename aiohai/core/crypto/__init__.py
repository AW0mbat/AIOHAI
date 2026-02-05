"""
Cryptographic Layer — HSM, FIDO2/WebAuthn, credential management.

Submodules:
- hsm_bridge: Nitrokey HSM integration for signing and verification
- fido_gate: FIDO2/WebAuthn hardware approval system
- credentials: Credential storage and redaction

Classes:
- NitrokeyHSMManager: PKCS#11 interface to Nitrokey HSM for signing/verification
- MockHSMManager: Software mock for testing
- FIDO2ApprovalServer: Flask HTTPS server for hardware key approval
- FIDO2ApprovalClient: Client with retry logic and SSL pinning
- OperationClassifier: Classifies operations into Tier 1-4
- CredentialStore: On-disk JSON storage of WebAuthn credentials
- CredentialRedactor: Strip API keys, passwords from content
"""

# HSM Bridge
from aiohai.core.crypto.hsm_bridge import (
    NitrokeyHSMManager,
    MockHSMManager,
    get_hsm_manager,
    PKCS11_AVAILABLE,
    HSM_KEY_LABELS,
)

# Operation Classifier
from aiohai.core.crypto.classifier import OperationClassifier

# FIDO2 Gate
from aiohai.core.crypto.fido_gate import (
    CredentialStore,
    FIDO2ApprovalServer,
    FIDO2ApprovalClient,
    FIDO2_AVAILABLE,
    FLASK_AVAILABLE,
    CRYPTO_AVAILABLE,
)

# Credentials
from aiohai.core.crypto.credentials import (
    CredentialRedactor,
)

# Types (re-exported for convenience)
from aiohai.core.types import (
    HSMStatus,
    HSMKeyInfo,
    SignedLogEntry,
    PolicyVerificationResult,
    ApprovalTier,
    ApprovalStatus,
    UserRole,
    RegisteredCredential,
    RegisteredUser,
    HardwareApprovalRequest,
)

__all__ = [
    # HSM
    'NitrokeyHSMManager',
    'MockHSMManager',
    'get_hsm_manager',
    'PKCS11_AVAILABLE',
    'HSM_KEY_LABELS',
    'HSMStatus',
    'HSMKeyInfo',
    'SignedLogEntry',
    'PolicyVerificationResult',
    
    # FIDO2
    'OperationClassifier',
    'CredentialStore',
    'FIDO2ApprovalServer',
    'FIDO2ApprovalClient',
    'FIDO2_AVAILABLE',
    'FLASK_AVAILABLE',
    'CRYPTO_AVAILABLE',
    'ApprovalTier',
    'ApprovalStatus',
    'UserRole',
    'RegisteredCredential',
    'RegisteredUser',
    'HardwareApprovalRequest',
    
    # Credentials
    'CredentialRedactor',
]
