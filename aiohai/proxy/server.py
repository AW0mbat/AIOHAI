#!/usr/bin/env python3
"""
Proxy Server — HTTP server infrastructure.

Provides a threaded HTTP server that handles concurrent requests
to the AIOHAI proxy.

Phase 5 extraction from proxy/aiohai_proxy.py.
"""

from http.server import HTTPServer
from socketserver import ThreadingMixIn

__all__ = ['ThreadedHTTPServer']


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """HTTP server that handles each request in a separate thread."""
    daemon_threads = True
