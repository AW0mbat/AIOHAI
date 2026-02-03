#!/usr/bin/env python3
"""Action Parser - Parse <action> XML blocks from LLM responses."""
import logging
logger = logging.getLogger("aiohai.proxy.action")

try:
    from proxy.aiohai_proxy import ActionParser
except ImportError:
    class ActionParser:
        def __init__(self): raise ImportError("Requires proxy module")

__all__ = ['ActionParser']
