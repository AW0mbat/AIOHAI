#!/usr/bin/env python3
"""
AIOHAI Core Access — Session Manager

Provides SessionManager as a lazy alias for ApprovalManager from the proxy layer.
Uses deferred import to avoid circular dependency (core must not import proxy at
module load time).
"""

import logging

logger = logging.getLogger("aiohai.core.access.session")


def _get_approval_manager():
    """Lazy import to break circular dependency."""
    try:
        from aiohai.proxy.approval import ApprovalManager
        return ApprovalManager
    except ImportError as e:
        logger.error(f"ApprovalManager not available: {e}")
        return None


class SessionManager:
    """Lazy proxy for ApprovalManager.

    Defers the import of ApprovalManager from aiohai.proxy until first
    instantiation, avoiding circular imports at module load time.
    """
    def __new__(cls, *args, **kwargs):
        impl = _get_approval_manager()
        if impl is None:
            raise ImportError("ApprovalManager requires proxy module")
        return impl(*args, **kwargs)


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    'SessionManager',
]
