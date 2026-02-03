"""
Office Integration — Microsoft Office + Graph API.

Classes:
- DocumentContentScanner: Scan Office docs for PII, credentials, formulas
- MacroBlocker: Block macro-enabled Office formats
- MetadataSanitizer: Strip author, revision, tracking metadata
- GraphAPIRegistry: Security gateway for Microsoft Graph API
- OfficeStackDetector: Detect installed Office components
- DocumentAuditLogger: Document operation audit trail
"""

from aiohai.integrations.office.document_scanner import DocumentContentScanner
from aiohai.integrations.office.macro_blocker import MacroBlocker
from aiohai.integrations.office.metadata_sanitizer import MetadataSanitizer
from aiohai.integrations.office.graph_registry import GraphAPIRegistry
from aiohai.integrations.office.stack_detector import OfficeStackDetector
from aiohai.integrations.office.audit_logger import DocumentAuditLogger

__all__ = [
    'DocumentContentScanner',
    'MacroBlocker',
    'MetadataSanitizer',
    'GraphAPIRegistry',
    'OfficeStackDetector',
    'DocumentAuditLogger',
]
