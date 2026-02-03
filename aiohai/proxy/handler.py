#!/usr/bin/env python3
"""Proxy Handler - HTTP request handling."""
import logging
logger = logging.getLogger("aiohai.proxy.handler")

try:
    from proxy.aiohai_proxy import UnifiedProxyHandler
except ImportError:
    class UnifiedProxyHandler:
        def __init__(self, *args, **kwargs): raise ImportError("Requires proxy module")

__all__ = ['UnifiedProxyHandler']
