#!/usr/bin/env python3
"""Startup Security Verifier - re-export from aiohai.core.audit.startup."""

try:
    from aiohai.core.audit.startup import StartupSecurityVerifier
except ImportError:
    from proxy.aiohai_proxy import StartupSecurityVerifier

__all__ = ['StartupSecurityVerifier']
