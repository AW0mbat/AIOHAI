#!/usr/bin/env python3
"""Office Document Scanner - PII/credential scanning in Office docs."""
import logging
logger = logging.getLogger("aiohai.integrations.office")

try:
    from proxy.aiohai_proxy import DocumentContentScanner
except ImportError:
    class DocumentContentScanner:
        def __init__(self, pii_protector): raise ImportError("Requires proxy module")

__all__ = ['DocumentContentScanner']
