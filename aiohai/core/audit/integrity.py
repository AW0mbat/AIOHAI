#!/usr/bin/env python3
"""
AIOHAI Core Audit — Integrity Verifier

Provides file integrity monitoring:
- SHA-256 hashing of policy and framework files
- Lockdown mode on tampering detection
- Background re-check thread

This module is part of the AIOHAI Core layer.
"""

import logging

logger = logging.getLogger("aiohai.core.audit.integrity")

try:
    from proxy.aiohai_proxy import IntegrityVerifier, ALLOWED_FRAMEWORK_NAMES
    _INTEGRITY_AVAILABLE = True
except ImportError as e:
    logger.error(f"IntegrityVerifier not available: {e}")
    _INTEGRITY_AVAILABLE = False
    ALLOWED_FRAMEWORK_NAMES = frozenset()
    
    class IntegrityVerifier:
        """Stub."""
        def __init__(self, config, logger, alerts):
            raise ImportError("IntegrityVerifier requires proxy module")


__all__ = ['IntegrityVerifier', 'ALLOWED_FRAMEWORK_NAMES']
