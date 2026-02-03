#!/usr/bin/env python3
"""
AIOHAI Core Access — Command Validator

Validates shell commands against:
- Blocked patterns (encoded PowerShell, credential theft, persistence)
- Executable whitelist
- Obfuscation detection
- Docker command tier classification

This module is part of the AIOHAI Core layer and provides accessor-agnostic
command validation. Both the AI proxy and future Agent layer use this validator.

Migration Note:
    The implementation currently resides in proxy/aiohai_proxy.py
    and is re-exported here. Future refactoring may move the full
    implementation to this location.
"""

import logging

logger = logging.getLogger("aiohai.core.access.command")

# Import the implementation from proxy
try:
    from proxy.aiohai_proxy import (
        CommandValidator,
        BLOCKED_COMMAND_PATTERNS,
        UAC_BYPASS_PATTERNS,
        WHITELISTED_EXECUTABLES,
        DOCKER_COMMAND_TIERS,
    )
    _COMMAND_IMPL_AVAILABLE = True
except ImportError as e:
    logger.error(f"CommandValidator not available: {e}")
    _COMMAND_IMPL_AVAILABLE = False
    
    # Minimal stubs
    BLOCKED_COMMAND_PATTERNS = []
    UAC_BYPASS_PATTERNS = []
    WHITELISTED_EXECUTABLES = set()
    DOCKER_COMMAND_TIERS = {}
    
    class CommandValidator:
        """Stub - proxy not available."""
        def __init__(self, config, logger, macro_blocker=None):
            raise ImportError("CommandValidator requires proxy module")
        def validate(self, command):
            return False, "CommandValidator not available"


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    'CommandValidator',
    'BLOCKED_COMMAND_PATTERNS',
    'UAC_BYPASS_PATTERNS',
    'WHITELISTED_EXECUTABLES',
    'DOCKER_COMMAND_TIERS',
]
