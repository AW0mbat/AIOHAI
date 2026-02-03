#!/usr/bin/env python3
"""
AIOHAI Core Network — Network Interceptor

Provides socket-level network interception:
- Hooks on socket.connect, getaddrinfo, gethostbyname
- Blocks private IPs (including 100.64.0.0/10 Tailscale/CGNAT)
- Blocks DNS-over-HTTPS servers
- DNS tunneling detection

This module is part of the AIOHAI Core layer.
"""

import logging

logger = logging.getLogger("aiohai.core.network.interceptor")

try:
    from proxy.aiohai_proxy import NetworkInterceptor
    _INTERCEPTOR_AVAILABLE = True
except ImportError as e:
    logger.error(f"NetworkInterceptor not available: {e}")
    _INTERCEPTOR_AVAILABLE = False
    
    class NetworkInterceptor:
        """Stub."""
        def __init__(self, config, logger, alerts):
            raise ImportError("NetworkInterceptor requires proxy module")


__all__ = ['NetworkInterceptor']
