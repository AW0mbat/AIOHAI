#!/usr/bin/env python3
"""Startup Security Verifier - Pre-flight security checks."""
import logging
logger = logging.getLogger("aiohai.proxy.startup")

try:
    from proxy.aiohai_proxy import StartupSecurityVerifier
except ImportError:
    class StartupSecurityVerifier:
        @staticmethod
        def verify(): raise ImportError("Requires proxy module")

__all__ = ['StartupSecurityVerifier']
