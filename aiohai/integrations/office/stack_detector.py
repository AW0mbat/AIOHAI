#!/usr/bin/env python3
"""Office Stack Detector - Detect installed Office components."""
import logging
logger = logging.getLogger("aiohai.integrations.office")

try:
    from security.security_components import OfficeStackDetector
except ImportError:
    class OfficeStackDetector:
        def __init__(self): raise ImportError("Requires security_components")

__all__ = ['OfficeStackDetector']
