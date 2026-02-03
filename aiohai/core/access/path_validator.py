#!/usr/bin/env python3
"""
AIOHAI Core Access — Path Validator

Provides two-tier path validation:
1. Hard blocks: Attack infrastructure, credential stores, OS internals
2. Tier 3 gates: Sensitive personal data requiring FIDO2 approval

This module is part of the AIOHAI Core layer and provides accessor-agnostic
path validation. Both the AI proxy and future Agent layer use this validator.

Migration Note:
    The implementation currently resides in proxy/aiohai_proxy.py
    and is re-exported here. Future refactoring may move the full
    implementation to this location.
"""

import logging

logger = logging.getLogger("aiohai.core.access.path")

# Import the implementation from proxy
try:
    from proxy.aiohai_proxy import (
        PathValidator,
        BLOCKED_PATH_PATTERNS,
        TIER3_PATH_PATTERNS,
    )
    _PATH_IMPL_AVAILABLE = True
except ImportError as e:
    logger.error(f"PathValidator not available: {e}")
    _PATH_IMPL_AVAILABLE = False
    
    # Minimal stub
    BLOCKED_PATH_PATTERNS = []
    TIER3_PATH_PATTERNS = []
    
    class PathValidator:
        """Stub - proxy not available."""
        def __init__(self, config, logger):
            raise ImportError("PathValidator requires proxy module")
        def validate(self, path):
            return False, path, "PathValidator not available"


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    'PathValidator',
    'BLOCKED_PATH_PATTERNS',
    'TIER3_PATH_PATTERNS',
]
