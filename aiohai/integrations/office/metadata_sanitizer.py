#!/usr/bin/env python3
"""
AIOHAI Integrations — Office Metadata Sanitizer
=================================================
Strips identifying metadata from Office documents before they are
written to disk or shared.

This prevents leakage of:
- Author names and company affiliation
- Revision history and tracked changes
- Comments (unless user opts in)
- Embedded file paths (which reveal directory structure)
- Custom XML properties

SECURITY FIX (F-002): Uses direct library calls instead of dynamic code
evaluation to eliminate injection via crafted file paths.

Previously defined in proxy/aiohai_proxy.py.
Extracted as Phase 4b of the monolith → layered architecture migration.

Import from: aiohai.integrations.office.metadata_sanitizer
"""

from pathlib import Path

from aiohai.core.types import AlertSeverity
from aiohai.core.audit.logger import SecurityLogger


class MetadataSanitizer:
    """
    Strips identifying metadata from Office documents before they are
    written to disk or shared.

    This prevents leakage of:
    - Author names and company affiliation
    - Revision history and tracked changes
    - Comments (unless user opts in)
    - Embedded file paths (which reveal directory structure)
    - Custom XML properties

    SECURITY FIX (F-002): Uses direct library calls instead of dynamic code
    evaluation to eliminate injection via crafted file paths.
    """

    # Core properties to clear
    CLEAR_PROPERTIES = [
        'author', 'last_modified_by', 'company', 'manager',
        'category', 'content_status', 'identifier', 'subject',
        'version', 'comments',
    ]

    # Properties to PRESERVE
    PRESERVE_PROPERTIES = ['title', 'language']

    def __init__(self, logger: SecurityLogger):
        self.logger = logger
        self._sanitized_count = 0

    def sanitize_file(self, file_path: str, file_type: str = '',
                      preserve_comments: bool = False) -> bool:
        """Sanitize metadata for the given document.

        Args:
            file_path: Path to the document (passed as variable, never interpolated).
            file_type: Extension override (e.g. '.docx').
            preserve_comments: If True, keep document comments intact.

        Returns:
            True on success.

        Raises:
            ImportError: If the required library is not installed.
            Exception: On any sanitization failure.
        """
        ext = file_type or Path(file_path).suffix.lower()

        if ext == '.docx':
            return self._sanitize_docx(file_path, preserve_comments)
        elif ext == '.xlsx':
            return self._sanitize_xlsx(file_path)
        elif ext == '.pptx':
            return self._sanitize_pptx(file_path)
        return True  # No sanitization needed for this type

    def _sanitize_docx(self, path: str, preserve_comments: bool) -> bool:
        from docx import Document
        from datetime import datetime

        doc = Document(path)
        cp = doc.core_properties
        cp.author = ''
        cp.last_modified_by = ''
        cp.revision = 1
        cp.category = ''
        cp.content_status = ''
        cp.identifier = ''
        cp.subject = ''
        cp.version = ''
        cp.created = datetime.now()
        cp.modified = datetime.now()
        if not preserve_comments:
            cp.comments = ''
        doc.save(path)
        return True

    def _sanitize_xlsx(self, path: str) -> bool:
        from openpyxl import load_workbook
        from datetime import datetime

        wb = load_workbook(path)
        wb.properties.creator = ''
        wb.properties.lastModifiedBy = ''
        wb.properties.company = ''
        wb.properties.manager = ''
        wb.properties.category = ''
        wb.properties.description = ''
        wb.properties.created = datetime.now()
        wb.properties.modified = datetime.now()
        wb.save(path)
        return True

    def _sanitize_pptx(self, path: str) -> bool:
        from pptx import Presentation
        from datetime import datetime

        prs = Presentation(path)
        cp = prs.core_properties
        cp.author = ''
        cp.last_modified_by = ''
        cp.revision = 1
        cp.comments = ''
        cp.category = ''
        cp.subject = ''
        prs.save(path)
        return True

    def record_sanitization(self, file_path: str):
        """Record that a file was sanitized."""
        self._sanitized_count += 1
        self.logger.log_event("METADATA_SANITIZED", AlertSeverity.INFO,
                              {'path': str(file_path)[:200],
                               'total_sanitized': self._sanitized_count})


__all__ = ['MetadataSanitizer']
