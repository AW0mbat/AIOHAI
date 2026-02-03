#!/usr/bin/env python3
"""
AIOHAI Core Analysis — Static Security Analyzer

Provides Bandit-style static analysis of code:
- Dangerous function calls detection
- Code injection patterns
- Security findings with severity and CWE IDs

Also includes SensitiveOperationDetector for categorizing sensitive operations.

This module is part of the AIOHAI Core layer.

Migration Note:
    The implementation currently resides in security/security_components.py
    and is re-exported here.
"""

import logging

logger = logging.getLogger("aiohai.core.analysis.static")

# Import types
from aiohai.core.types import Severity, Verdict, SecurityFinding

# Import the implementations
try:
    from security.security_components import (
        StaticSecurityAnalyzer,
        SensitiveOperationDetector,
    )
    _STATIC_AVAILABLE = True
except ImportError as e:
    logger.error(f"StaticSecurityAnalyzer not available: {e}")
    _STATIC_AVAILABLE = False
    
    class StaticSecurityAnalyzer:
        """Stub - security_components not available."""
        def __init__(self):
            raise ImportError("StaticSecurityAnalyzer requires security_components")
    
    class SensitiveOperationDetector:
        """Stub - security_components not available."""
        def __init__(self):
            raise ImportError("SensitiveOperationDetector requires security_components")


__all__ = [
    'StaticSecurityAnalyzer',
    'SensitiveOperationDetector',
    'Severity',
    'Verdict',
    'SecurityFinding',
]
