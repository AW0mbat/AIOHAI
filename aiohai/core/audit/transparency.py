#!/usr/bin/env python3
"""
AIOHAI Core Audit — Session Transparency Tracker

Records all actions for the REPORT command:
- Per-session action tracking
- API query recording
- Transparency reports

This module is part of the AIOHAI Core layer.
"""

import logging

logger = logging.getLogger("aiohai.core.audit.transparency")

try:
    from security.security_components import SessionTransparencyTracker
    _TRACKER_AVAILABLE = True
except ImportError as e:
    logger.error(f"SessionTransparencyTracker not available: {e}")
    _TRACKER_AVAILABLE = False
    
    class SessionTransparencyTracker:
        """Stub."""
        def __init__(self):
            raise ImportError("SessionTransparencyTracker requires security_components")


__all__ = ['SessionTransparencyTracker']
