#!/usr/bin/env python3
"""
AIOHAI Core Crypto — FIDO2/WebAuthn Gate

Provides hardware-based approval for high-security operations using:
- Nitrokey 3A NFC (roaming authenticator, USB/NFC)
- iPhone Face ID (platform authenticator via Safari)
- Android fingerprint (platform authenticator via Chrome)

This module is part of the AIOHAI Core layer and provides accessor-agnostic
FIDO2/WebAuthn functionality. Both the AI proxy and direct user access use
this module for Tier 3/4 approvals.

Architecture:
  Any Accessor --> FIDOGate --> FIDO2ApprovalServer --> User Device
       |              |                  |                   |
       |   Request    |  WebAuthn        |  Face ID/Touch/   |
       |   Approval   |  challenge       |  NFC key tap      |
       |              |                  |                   |
       +--------------+------------------+-------------------+

Migration Note:
    The implementation currently resides in security/fido2_approval.py
    and is re-exported here. Future refactoring will move the full
    implementation to this location.
    
    For new code, import from aiohai.core.crypto.fido_gate.
"""

import logging

logger = logging.getLogger("aiohai.core.crypto.fido")

# Import types from core
from aiohai.core.types import (
    ApprovalTier,
    ApprovalStatus, 
    UserRole,
    RegisteredCredential,
    RegisteredUser,
    HardwareApprovalRequest,
)

# Import implementation from security module
# These will be moved here in a future phase
try:
    from security.fido2_approval import (
        OperationClassifier,
        CredentialStore,
        FIDO2ApprovalServer,
        FIDO2ApprovalClient,
        FIDO2_AVAILABLE,
        FLASK_AVAILABLE,
        CRYPTO_AVAILABLE,
    )
    _FIDO2_IMPL_AVAILABLE = True
except ImportError as e:
    logger.warning(f"FIDO2 implementation not available: {e}")
    _FIDO2_IMPL_AVAILABLE = False
    FIDO2_AVAILABLE = False
    FLASK_AVAILABLE = False
    CRYPTO_AVAILABLE = False
    
    # Provide stub classes for import compatibility
    class OperationClassifier:
        """Stub - FIDO2 not available."""
        @classmethod
        def classify(cls, action_type, target="", content=""):
            return ApprovalTier.TIER_1
        @classmethod
        def get_required_role(cls, tier, target=""):
            return UserRole.GUEST

    class CredentialStore:
        """Stub - FIDO2 not available."""
        def __init__(self, storage_path):
            raise ImportError("FIDO2 components not available")

    class FIDO2ApprovalServer:
        """Stub - FIDO2 not available."""
        def __init__(self, config):
            raise ImportError("FIDO2 components not available")

    class FIDO2ApprovalClient:
        """Stub - FIDO2 not available."""
        def __init__(self, server_url, api_secret):
            raise ImportError("FIDO2 components not available")


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Types (from core.types)
    'ApprovalTier',
    'ApprovalStatus',
    'UserRole',
    'RegisteredCredential',
    'RegisteredUser',
    'HardwareApprovalRequest',
    
    # Classes (from security.fido2_approval or stubs)
    'OperationClassifier',
    'CredentialStore',
    'FIDO2ApprovalServer',
    'FIDO2ApprovalClient',
    
    # Availability flags
    'FIDO2_AVAILABLE',
    'FLASK_AVAILABLE',
    'CRYPTO_AVAILABLE',
]
