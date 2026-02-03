#!/usr/bin/env python3
"""Graph API Registry - Security gateway for Microsoft Graph API."""
import logging
logger = logging.getLogger("aiohai.integrations.office")

try:
    from proxy.aiohai_proxy import GraphAPIRegistry
except ImportError:
    class GraphAPIRegistry:
        def __init__(self, logger): raise ImportError("Requires proxy module")

__all__ = ['GraphAPIRegistry']
