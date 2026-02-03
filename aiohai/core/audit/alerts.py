#!/usr/bin/env python3
"""
AIOHAI Core Audit — Alert Manager

Provides desktop notifications and alert routing.

This module is part of the AIOHAI Core layer.
"""

import logging

logger = logging.getLogger("aiohai.core.audit.alerts")

from aiohai.core.types import AlertSeverity

try:
    from proxy.aiohai_proxy import AlertManager
    _ALERTS_AVAILABLE = True
except ImportError as e:
    logger.error(f"AlertManager not available: {e}")
    _ALERTS_AVAILABLE = False
    
    class AlertManager:
        """Stub."""
        def __init__(self, config, logger):
            raise ImportError("AlertManager requires proxy module")


__all__ = ['AlertManager', 'AlertSeverity']
