#!/usr/bin/env python3
"""Metadata Sanitizer - Strip author/revision/tracking metadata."""
import logging
logger = logging.getLogger("aiohai.integrations.office")

try:
    from proxy.aiohai_proxy import MetadataSanitizer
except ImportError:
    class MetadataSanitizer:
        def __init__(self): raise ImportError("Requires proxy module")

__all__ = ['MetadataSanitizer']
