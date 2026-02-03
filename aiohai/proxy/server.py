#!/usr/bin/env python3
"""Proxy Server - HTTP server infrastructure."""
import logging
logger = logging.getLogger("aiohai.proxy.server")

try:
    from proxy.aiohai_proxy import ThreadedHTTPServer
except ImportError:
    class ThreadedHTTPServer:
        def __init__(self, *args, **kwargs): raise ImportError("Requires proxy module")

__all__ = ['ThreadedHTTPServer']
