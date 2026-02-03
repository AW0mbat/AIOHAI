#!/usr/bin/env python3
"""
AIOHAI Core Analysis — PII Protector

Provides PII detection and redaction:
- Email addresses, phone numbers, SSNs
- Credit card numbers, IP addresses
- AWS keys, API keys, private keys

This module is part of the AIOHAI Core layer.

Migration Note:
    The implementation currently resides in security/security_components.py
    and is re-exported here.
"""

import logging

logger = logging.getLogger("aiohai.core.analysis.pii")

# Import types
from aiohai.core.types import PIIType, PIIFinding

# Import the implementation
try:
    from security.security_components import PIIProtector
    _PII_AVAILABLE = True
except ImportError as e:
    logger.error(f"PIIProtector not available: {e}")
    _PII_AVAILABLE = False
    
    class PIIProtector:
        """Stub - security_components not available."""
        def __init__(self):
            raise ImportError("PIIProtector requires security_components")


__all__ = [
    'PIIProtector',
    'PIIType',
    'PIIFinding',
]
