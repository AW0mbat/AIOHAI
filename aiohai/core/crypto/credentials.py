#!/usr/bin/env python3
"""
AIOHAI Core Crypto — Credential Management

Provides credential redaction and storage functionality:
- CredentialRedactor: Redacts sensitive credentials from text for safe display
- CredentialStore: Thread-safe persistent storage for WebAuthn credentials

This module is part of the AIOHAI Core layer and provides accessor-agnostic
credential management. Both the AI proxy and direct user access use these
utilities for handling sensitive credential data.

Migration Note:
    - CredentialRedactor implementation resides in security/security_components.py
    - CredentialStore implementation resides in security/fido2_approval.py
    These are re-exported here. Future refactoring may consolidate implementations.
"""

import logging

logger = logging.getLogger("aiohai.core.crypto.credentials")

# Import types from core
from aiohai.core.types import (
    RegisteredCredential,
    RegisteredUser,
)

# Import CredentialRedactor from security_components
try:
    from security.security_components import CredentialRedactor
    _REDACTOR_AVAILABLE = True
except ImportError as e:
    logger.warning(f"CredentialRedactor not available: {e}")
    _REDACTOR_AVAILABLE = False
    
    # Stub implementation
    class CredentialRedactor:
        """Stub - security_components not available."""
        def redact(self, text):
            return text
        def redact_for_preview(self, text, max_length=100):
            if len(text) > max_length:
                return text[:max_length] + '...'
            return text

# Import CredentialStore from fido2_approval
try:
    from security.fido2_approval import CredentialStore
    _STORE_AVAILABLE = True
except ImportError as e:
    logger.warning(f"CredentialStore not available: {e}")
    _STORE_AVAILABLE = False
    
    # Stub implementation
    class CredentialStore:
        """Stub - fido2_approval not available."""
        def __init__(self, storage_path):
            raise ImportError("FIDO2 credential store not available")


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Types
    'RegisteredCredential',
    'RegisteredUser',
    
    # Classes
    'CredentialRedactor',
    'CredentialStore',
]
