#!/usr/bin/env python3
"""Secure Executor - Sandboxed file/command execution."""
import logging
logger = logging.getLogger("aiohai.proxy.executor")

try:
    from proxy.aiohai_proxy import SecureExecutor
except ImportError:
    class SecureExecutor:
        def __init__(self, config, logger, path_validator, command_validator): 
            raise ImportError("Requires proxy module")

__all__ = ['SecureExecutor']
