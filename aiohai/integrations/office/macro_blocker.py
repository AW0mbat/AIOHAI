#!/usr/bin/env python3
"""Macro Blocker - Block macro-enabled Office formats."""
import logging
logger = logging.getLogger("aiohai.integrations.office")

try:
    from proxy.aiohai_proxy import MacroBlocker
except ImportError:
    class MacroBlocker:
        def __init__(self): raise ImportError("Requires proxy module")

__all__ = ['MacroBlocker']
