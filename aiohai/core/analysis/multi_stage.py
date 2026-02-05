#!/usr/bin/env python3
"""
AIOHAI Core Analysis — Multi-Stage Attack Detector
====================================================
Detects attack patterns across multiple actions within a time window:
- Write-then-execute patterns
- Mass deletion detection
- Rapid credential path access attempts

Previously defined inline in security/security_components.py.
Extracted as Phase 2b of the monolith → layered architecture migration.

Import from: aiohai.core.analysis.multi_stage
"""

import time
import threading
from typing import List, Dict, Optional


class MultiStageDetector:
    """Detects attack patterns across multiple actions."""

    def __init__(self, window_seconds: int = 600):
        self.window = window_seconds
        self.actions: List[Dict] = []
        self.lock = threading.Lock()

    def record(self, action_type: str, target: str, content: str = ""):
        with self.lock:
            now = time.time()
            self.actions.append({
                'type': action_type, 'target': target,
                'content': content[:200], 'time': now
            })
            # Clean old
            self.actions = [a for a in self.actions if now - a['time'] < self.window]

    def check(self) -> Optional[str]:
        with self.lock:
            types = [a['type'] for a in self.actions]

            # Write then execute pattern
            if 'WRITE' in types and 'COMMAND' in types:
                write_targets = [a['target'] for a in self.actions if a['type'] == 'WRITE']
                cmd_targets = [a['target'] for a in self.actions if a['type'] == 'COMMAND']

                for wt in write_targets:
                    for ct in cmd_targets:
                        if wt in ct:
                            return f"Write-then-execute pattern: {wt}"

            # Multiple deletions
            deletes = [a for a in self.actions if a['type'] == 'DELETE']
            if len(deletes) > 5:
                return f"Mass deletion detected: {len(deletes)} files"

            # Rapid credential path access
            cred_patterns = ['.ssh', '.aws', 'credential', 'password', '.env']
            cred_attempts = sum(1 for a in self.actions
                               if any(p in a['target'].lower() for p in cred_patterns))
            if cred_attempts >= 3:
                return f"Multiple credential path access attempts: {cred_attempts}"

            return None


__all__ = ['MultiStageDetector']
