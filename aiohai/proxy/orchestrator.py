#!/usr/bin/env python3
"""Proxy Orchestrator - Main startup and component wiring."""
import logging
logger = logging.getLogger("aiohai.proxy.orchestrator")

try:
    from proxy.aiohai_proxy import UnifiedSecureProxy
except ImportError:
    class UnifiedSecureProxy:
        def __init__(self, config=None): raise ImportError("Requires proxy module")

__all__ = ['UnifiedSecureProxy']
