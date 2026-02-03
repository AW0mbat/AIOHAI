#!/usr/bin/env python3
"""Smart Home Stack Detector - Docker container auto-discovery."""
import logging
logger = logging.getLogger("aiohai.integrations.smart_home")

try:
    from security.security_components import SmartHomeStackDetector
except ImportError:
    class SmartHomeStackDetector:
        def __init__(self): raise ImportError("Requires security_components")

__all__ = ['SmartHomeStackDetector']
