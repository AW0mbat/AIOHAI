#!/usr/bin/env python3
"""Document Audit Logger - Document operation audit trail."""
import logging
logger = logging.getLogger("aiohai.integrations.office")

try:
    from security.security_components import DocumentAuditLogger
except ImportError:
    class DocumentAuditLogger:
        def __init__(self, logger): raise ImportError("Requires security_components")

__all__ = ['DocumentAuditLogger']
