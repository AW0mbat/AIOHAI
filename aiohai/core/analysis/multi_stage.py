#!/usr/bin/env python3
"""
AIOHAI Core Analysis — Multi-Stage Attack Detector

Detects multi-stage attack patterns:
- Reconnaissance → Weaponization → Execution chains
- Progressive behavior analysis across session

This module is part of the AIOHAI Core layer.

Migration Note:
    The implementation currently resides in security/security_components.py
    and is re-exported here.
"""

import logging

logger = logging.getLogger("aiohai.core.analysis.multistage")

# Import the implementation
try:
    from security.security_components import MultiStageDetector
    _MULTISTAGE_AVAILABLE = True
except ImportError as e:
    logger.error(f"MultiStageDetector not available: {e}")
    _MULTISTAGE_AVAILABLE = False
    
    class MultiStageDetector:
        """Stub - security_components not available."""
        def __init__(self):
            raise ImportError("MultiStageDetector requires security_components")


__all__ = [
    'MultiStageDetector',
]
