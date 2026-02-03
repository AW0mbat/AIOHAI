#!/usr/bin/env python3
"""
AIOHAI Core Audit — Security Logger

Provides tamper-evident logging with:
- Chain hashing for integrity
- PII redaction
- Optional HSM signing

This module is part of the AIOHAI Core layer.
"""

import logging

logger = logging.getLogger("aiohai.core.audit.logger")

from aiohai.core.types import AlertSeverity

try:
    from proxy.aiohai_proxy import SecurityLogger
    _LOGGER_AVAILABLE = True
except ImportError as e:
    logger.error(f"SecurityLogger not available: {e}")
    _LOGGER_AVAILABLE = False
    
    class SecurityLogger:
        """Stub."""
        def __init__(self, config, hsm_manager=None):
            raise ImportError("SecurityLogger requires proxy module")


__all__ = ['SecurityLogger', 'AlertSeverity']
