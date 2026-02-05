#!/usr/bin/env python3
"""
AIOHAI Integrations — Office Document Audit Logger
====================================================
Audit trail for all document operations.

Tracks reads, writes, creates, modifications, conversions, and uploads
with content hashes and PII scan results.

Previously defined in security/security_components.py.
Extracted as Phase 4b of the monolith -> layered architecture migration.

Import from: aiohai.integrations.office.audit_logger
"""

import os
import json
import hashlib
import logging
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, List


class DocumentAuditLogger:
    """
    Audit trail for all document operations.

    Tracks reads, writes, creates, modifications, conversions, and uploads
    with content hashes and PII scan results.
    """

    def __init__(self, log_dir: Path = None, retention_days: int = 30,
                 log_content_hashes: bool = True):
        if log_dir:
            self.log_dir = Path(log_dir)
        else:
            home = os.environ.get('AIOHAI_HOME', os.path.expanduser('~'))
            self.log_dir = Path(home) / 'logs' / 'document_audit'

        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.retention_days = retention_days
        self.log_content_hashes = log_content_hashes
        self._lock = threading.Lock()
        self.logger = logging.getLogger('aiohai.doc_audit')

        # In-memory recent operations (last 100)
        self._recent: List[Dict] = []
        self._max_recent = 100

    def log_operation(self, operation: str, file_path: str,
                      file_type: str = '', details: Dict = None,
                      content_hash: str = '', pii_findings: List = None,
                      metadata_stripped: bool = False) -> Dict:
        """
        Log a document operation.

        Args:
            operation: CREATE, READ, MODIFY, CONVERT, UPLOAD, DELETE
            file_path: Path to the document
            file_type: Extension (.docx, .xlsx, .pptx, etc.)
            details: Additional operation details
            content_hash: SHA-256 of first 1024 bytes (for fingerprinting)
            pii_findings: List of PII findings from scanner
            metadata_stripped: Whether metadata was sanitized

        Returns:
            The logged entry dict.
        """
        entry = {
            'timestamp': datetime.now().isoformat(),
            'operation': operation,
            'file_path': self._sanitize_path(file_path),
            'file_type': file_type or self._get_ext(file_path),
            'content_hash': content_hash,
            'pii_findings_count': len(pii_findings) if pii_findings else 0,
            'pii_categories': list(set(f.get('type', 'unknown')
                                       for f in (pii_findings or []))),
            'metadata_stripped': metadata_stripped,
            'details': details or {},
        }

        with self._lock:
            # Write to daily log file
            date_str = datetime.now().strftime('%Y-%m-%d')
            log_file = self.log_dir / f'doc_audit_{date_str}.jsonl'
            try:
                with open(log_file, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(entry) + '\n')
            except OSError as e:
                self.logger.error(f"Failed to write audit log: {e}")

            # Add to in-memory recent
            self._recent.append(entry)
            if len(self._recent) > self._max_recent:
                self._recent = self._recent[-self._max_recent:]

        self.logger.info(f"DOC_AUDIT: {operation} | {entry['file_type']} | "
                         f"PII: {entry['pii_findings_count']}")
        return entry

    def hash_content(self, content: bytes, max_bytes: int = 1024) -> str:
        """Generate a content fingerprint hash."""
        if not self.log_content_hashes:
            return ''
        return hashlib.sha256(content[:max_bytes]).hexdigest()

    def get_recent(self, count: int = 20) -> List[Dict]:
        """Get recent operations."""
        with self._lock:
            return list(self._recent[-count:])

    def get_stats(self) -> Dict:
        """Get operation statistics from recent history."""
        with self._lock:
            ops = {}
            types = {}
            pii_total = 0
            for entry in self._recent:
                op = entry['operation']
                ops[op] = ops.get(op, 0) + 1
                ft = entry['file_type']
                types[ft] = types.get(ft, 0) + 1
                pii_total += entry['pii_findings_count']

            return {
                'total_operations': len(self._recent),
                'by_operation': ops,
                'by_file_type': types,
                'total_pii_findings': pii_total,
            }

    def cleanup_old_logs(self):
        """Remove audit logs older than retention period."""
        if self.retention_days <= 0:
            return

        cutoff = datetime.now().timestamp() - (self.retention_days * 86400)
        removed = 0
        for log_file in self.log_dir.glob('doc_audit_*.jsonl'):
            if log_file.stat().st_mtime < cutoff:
                log_file.unlink()
                removed += 1

        if removed:
            self.logger.info(f"Cleaned up {removed} old audit log files")

    def _sanitize_path(self, path: str) -> str:
        """Remove user-identifying path components for logging."""
        parts = Path(path).parts
        sanitized = []
        for part in parts:
            if part.lower() in ('users', 'home'):
                sanitized.append(part)
                continue
            sanitized.append(part)
        return str(Path(*sanitized)) if sanitized else path

    def _get_ext(self, path: str) -> str:
        """Extract file extension."""
        return Path(path).suffix.lower()


__all__ = ['DocumentAuditLogger']
