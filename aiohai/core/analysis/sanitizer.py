#!/usr/bin/env python3
"""
AIOHAI Core Analysis — Content Sanitizer

Provides content sanitization including:
- Injection pattern detection (40+ patterns)
- Invisible Unicode character stripping
- Homoglyph and fullwidth character normalization
- Trust level assignment for external content

This module is part of the AIOHAI Core layer.

Migration Note:
    The implementation currently resides in proxy/aiohai_proxy.py
    and is re-exported here.
"""

import logging

logger = logging.getLogger("aiohai.core.analysis.sanitizer")

# Import types
from aiohai.core.types import TrustLevel

# Import the implementation from proxy
try:
    from proxy.aiohai_proxy import (
        ContentSanitizer,
        INJECTION_PATTERNS,
    )
    _SANITIZER_AVAILABLE = True
except ImportError as e:
    logger.error(f"ContentSanitizer not available: {e}")
    _SANITIZER_AVAILABLE = False
    
    INJECTION_PATTERNS = []
    
    class ContentSanitizer:
        """Stub - proxy not available."""
        def __init__(self, logger, alerts):
            raise ImportError("ContentSanitizer requires proxy module")


__all__ = [
    'ContentSanitizer',
    'INJECTION_PATTERNS',
    'TrustLevel',
]
