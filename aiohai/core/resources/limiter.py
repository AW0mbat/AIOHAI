#!/usr/bin/env python3
"""
AIOHAI Core Resources — Resource Limiter

Provides DoS protection:
- Track concurrent processes
- Track file operations
- Session duration limits

This module is part of the AIOHAI Core layer.
"""

import logging

logger = logging.getLogger("aiohai.core.resources.limiter")

from aiohai.core.types import ResourceLimits, ResourceLimitExceeded

try:
    from security.security_components import ResourceLimiter
    _LIMITER_AVAILABLE = True
except ImportError as e:
    logger.error(f"ResourceLimiter not available: {e}")
    _LIMITER_AVAILABLE = False
    
    class ResourceLimiter:
        """Stub."""
        def __init__(self, limits=None):
            raise ImportError("ResourceLimiter requires security_components")


__all__ = ['ResourceLimiter', 'ResourceLimits', 'ResourceLimitExceeded']
