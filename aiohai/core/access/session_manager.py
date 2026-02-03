#!/usr/bin/env python3
"""
AIOHAI Core Access — Session Manager

Provides human-in-the-loop approval queue with:
- Timing-safe HMAC approval tokens
- Session-bound, time-limited approvals
- Rate limiting and expiry

This module is part of the AIOHAI Core layer and provides accessor-agnostic
session and approval management. The name "SessionManager" reflects its
generalized role beyond just AI approvals.

Migration Note:
    The implementation currently resides in proxy/aiohai_proxy.py as
    ApprovalManager and is re-exported here. Future refactoring may
    generalize and move the implementation to this location.
"""

import logging

logger = logging.getLogger("aiohai.core.access.session")

# Import the implementation from proxy
try:
    from proxy.aiohai_proxy import ApprovalManager
    # Alias for the new name
    SessionManager = ApprovalManager
    _SESSION_IMPL_AVAILABLE = True
except ImportError as e:
    logger.error(f"ApprovalManager not available: {e}")
    _SESSION_IMPL_AVAILABLE = False
    
    class ApprovalManager:
        """Stub - proxy not available."""
        def __init__(self, config, logger):
            raise ImportError("ApprovalManager requires proxy module")
    
    SessionManager = ApprovalManager


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    'ApprovalManager',  # Original name for backward compat
    'SessionManager',   # New generalized name
]
