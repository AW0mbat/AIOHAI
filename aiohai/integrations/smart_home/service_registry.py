#!/usr/bin/env python3
"""
AIOHAI Integrations — Smart Home Service Registry

Allowlist of queryable local services with port verification.
"""

import logging
logger = logging.getLogger("aiohai.integrations.smart_home")

try:
    from proxy.aiohai_proxy import LocalServiceRegistry
    _REGISTRY_AVAILABLE = True
except ImportError:
    _REGISTRY_AVAILABLE = False
    class LocalServiceRegistry:
        def __init__(self, logger):
            raise ImportError("Requires proxy module")

__all__ = ['LocalServiceRegistry']
