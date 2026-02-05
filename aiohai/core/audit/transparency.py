#!/usr/bin/env python3
"""
AIOHAI Core Audit — Session Transparency Tracker
==================================================
Records all AI actions for the REPORT command:
- Files read/written/deleted, commands executed, directories listed
- API queries (Home Assistant, Frigate, etc.)
- Sensitive data access tracking
- Blocked attempt recording
- Approval grant/reject counts
- Full transparency report generation

Previously defined inline in security/security_components.py.
Extracted as Phase 2b of the monolith → layered architecture migration.

Import from: aiohai.core.audit.transparency
"""

import os
import threading
from typing import List, Dict
from datetime import datetime

from aiohai.core.analysis.sensitive_ops import SensitiveOperationDetector


class SessionTransparencyTracker:
    """Tracks all AI actions for transparency reporting."""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.start_time = datetime.now()
        self.files_read: List[Dict] = []
        self.files_written: List[Dict] = []
        self.files_deleted: List[Dict] = []
        self.commands_executed: List[Dict] = []
        self.directories_listed: List[Dict] = []
        self.api_queries: List[Dict] = []
        self.sensitive_access: List[Dict] = []
        self.blocked_attempts: List[Dict] = []
        self.approvals_granted: int = 0
        self.approvals_rejected: int = 0
        self.lock = threading.Lock()

        self.sensitive_detector = SensitiveOperationDetector()

    def record_read(self, path: str, size: int, success: bool):
        with self.lock:
            record = {
                'path': path,
                'filename': os.path.basename(path),
                'size': size,
                'success': success,
                'timestamp': datetime.now().isoformat(),
            }
            self.files_read.append(record)

            matches = self.sensitive_detector.detect(path)
            if matches:
                self.sensitive_access.append({
                    'action': 'READ',
                    'path': path,
                    'categories': [m['category'] for m in matches],
                    'timestamp': datetime.now().isoformat(),
                })

    def record_write(self, path: str, size: int, success: bool):
        with self.lock:
            self.files_written.append({
                'path': path, 'filename': os.path.basename(path),
                'size': size, 'success': success,
                'timestamp': datetime.now().isoformat(),
            })

    def record_delete(self, path: str, success: bool):
        with self.lock:
            self.files_deleted.append({
                'path': path, 'filename': os.path.basename(path),
                'success': success, 'timestamp': datetime.now().isoformat(),
            })

    def record_command(self, command: str, success: bool, output_preview: str = ""):
        with self.lock:
            self.commands_executed.append({
                'command': command[:200], 'success': success,
                'output_preview': output_preview[:100] if output_preview else "",
                'timestamp': datetime.now().isoformat(),
            })

    def record_list(self, path: str, count: int, success: bool):
        with self.lock:
            self.directories_listed.append({
                'path': path, 'item_count': count,
                'success': success, 'timestamp': datetime.now().isoformat(),
            })

    def record_api_query(self, service: str, endpoint: str,
                         sensitivity: str = "standard", success: bool = True):
        with self.lock:
            self.api_queries.append({
                'service': service, 'endpoint': endpoint[:200],
                'sensitivity': sensitivity, 'success': success,
                'timestamp': datetime.now().isoformat(),
            })

    def record_blocked(self, action_type: str, target: str, reason: str):
        with self.lock:
            self.blocked_attempts.append({
                'action': action_type, 'target': target[:100],
                'reason': reason, 'timestamp': datetime.now().isoformat(),
            })

    def record_approval(self, approved: bool):
        with self.lock:
            if approved:
                self.approvals_granted += 1
            else:
                self.approvals_rejected += 1

    def get_duration(self) -> str:
        delta = datetime.now() - self.start_time
        hours, remainder = divmod(int(delta.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        if hours:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"

    def generate_report(self) -> str:
        """Generate full transparency report."""
        with self.lock:
            lines = [
                "# \U0001f4cb Session Transparency Report\n",
                f"**Session ID:** `{self.session_id[:8]}`",
                f"**Started:** {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}",
                f"**Duration:** {self.get_duration()}",
                f"**Approvals:** \u2705 {self.approvals_granted} granted \u00b7 \u274c {self.approvals_rejected} rejected\n",
            ]

            if self.sensitive_access:
                lines.append("## \U0001f6a8 Sensitive Data Accessed\n")
                lines.append("| Time | Action | Path | Categories |")
                lines.append("|------|--------|------|------------|")
                for s in self.sensitive_access:
                    time_str = s['timestamp'].split('T')[1][:8]
                    cats = ', '.join(s['categories'])
                    path = os.path.basename(s['path'])
                    lines.append(f"| {time_str} | {s['action']} | `{path}` | {cats} |")
                lines.append("")

            lines.append(f"## \U0001f4d6 Files Read ({len(self.files_read)})\n")
            if self.files_read:
                lines.append("| File | Size | Status |")
                lines.append("|------|------|--------|")
                for f in self.files_read[-20:]:
                    status = "\u2705" if f['success'] else "\u274c"
                    size = self._format_size(f['size'])
                    lines.append(f"| `{f['filename']}` | {size} | {status} |")
                if len(self.files_read) > 20:
                    lines.append(f"| ... and {len(self.files_read) - 20} more | | |")
            else:
                lines.append("*No files read*")
            lines.append("")

            lines.append(f"## \U0001f4dd Files Written ({len(self.files_written)})\n")
            if self.files_written:
                lines.append("| File | Size | Status |")
                lines.append("|------|------|--------|")
                for f in self.files_written[-20:]:
                    status = "\u2705" if f['success'] else "\u274c"
                    size = self._format_size(f['size'])
                    lines.append(f"| `{f['filename']}` | {size} | {status} |")
            else:
                lines.append("*No files written*")
            lines.append("")

            if self.files_deleted:
                lines.append(f"## \U0001f5d1\ufe0f Files Deleted ({len(self.files_deleted)})\n")
                lines.append("| File | Status |")
                lines.append("|------|--------|")
                for f in self.files_deleted:
                    status = "\u2705" if f['success'] else "\u274c"
                    lines.append(f"| `{f['filename']}` | {status} |")
                lines.append("")

            lines.append(f"## \u26a1 Commands Executed ({len(self.commands_executed)})\n")
            if self.commands_executed:
                lines.append("| Command | Status |")
                lines.append("|---------|--------|")
                for c in self.commands_executed[-15:]:
                    status = "\u2705" if c['success'] else "\u274c"
                    cmd = c['command'][:50] + ('...' if len(c['command']) > 50 else '')
                    lines.append(f"| `{cmd}` | {status} |")
                if len(self.commands_executed) > 15:
                    lines.append(f"| ... and {len(self.commands_executed) - 15} more | |")
            else:
                lines.append("*No commands executed*")
            lines.append("")

            if self.api_queries:
                lines.append(f"## \U0001f310 API Queries ({len(self.api_queries)})\n")
                lines.append("| Service | Endpoint | Sensitivity | Status |")
                lines.append("|---------|----------|-------------|--------|")
                for q in self.api_queries[-15:]:
                    status = "\u2705" if q['success'] else "\u274c"
                    ep = q['endpoint'][:40] + ('...' if len(q['endpoint']) > 40 else '')
                    lines.append(f"| {q['service']} | `{ep}` | {q['sensitivity']} | {status} |")
                if len(self.api_queries) > 15:
                    lines.append(f"| ... and {len(self.api_queries) - 15} more | | | |")
                lines.append("")

            if self.blocked_attempts:
                lines.append(f"## \U0001f6e1\ufe0f Blocked Attempts ({len(self.blocked_attempts)})\n")
                lines.append("| Action | Target | Reason |")
                lines.append("|--------|--------|--------|")
                for b in self.blocked_attempts[-10:]:
                    target = b['target'][:30] + ('...' if len(b['target']) > 30 else '')
                    reason = b['reason'][:30] + ('...' if len(b['reason']) > 30 else '')
                    lines.append(f"| {b['action']} | `{target}` | {reason} |")
                lines.append("")

            lines.append("---")
            lines.append("*This report shows all actions the AI performed or attempted this session.*")

            return "\n".join(lines)

    def _format_size(self, size: int) -> str:
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        else:
            return f"{size / (1024*1024):.1f} MB"


__all__ = ['SessionTransparencyTracker']
