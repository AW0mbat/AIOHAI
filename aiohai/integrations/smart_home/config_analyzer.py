#!/usr/bin/env python3
"""Smart Home Config Analyzer - Docker/YAML security audit."""
import logging
logger = logging.getLogger("aiohai.integrations.smart_home")

try:
    from security.security_components import SmartHomeConfigAnalyzer
except ImportError:
    class SmartHomeConfigAnalyzer:
        def __init__(self): raise ImportError("Requires security_components")

__all__ = ['SmartHomeConfigAnalyzer']
