#!/usr/bin/env python3
"""
AIOHAI Core Trust — Session Store
===================================
Append-only JSONL persistence for session elevation audit trail.

Each line is a JSON object representing a completed (closed) session.
This file is append-only at runtime and is included in HSM-signed
audit if HSM is available.

File: config/session_log.jsonl

Phase 2 of Approval Gate Taxonomy v3 implementation.

Import from: aiohai.core.trust.session_store
"""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import List, Optional

__all__ = ['SessionStore']

logger = logging.getLogger("aiohai.core.trust.session_store")

# Default location relative to AIOHAI_HOME
DEFAULT_SESSION_LOG = "config/session_log.jsonl"


class SessionStore:
    """Append-only JSONL store for session elevation audit trail.

    Thread-safe. Creates the log file and parent directories on first write.

    Usage:
        store = SessionStore("/path/to/session_log.jsonl")
        store.append(session)  # Writes one JSON line

        # Read back for admin UI
        entries = store.read_recent(limit=50)
    """

    def __init__(self, path: Optional[str] = None):
        """Initialize the session store.

        Args:
            path: Path to the JSONL file. Defaults to
                  $AIOHAI_HOME/config/session_log.jsonl.
        """
        if path is None:
            aiohai_home = os.environ.get('AIOHAI_HOME', '.')
            path = os.path.join(aiohai_home, DEFAULT_SESSION_LOG)

        self._path = Path(path)
        self._lock = threading.Lock()
        self._ensure_dir()

    def _ensure_dir(self):
        """Create parent directories if they don't exist."""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            logger.warning("Cannot create session log directory: %s", e)

    def append(self, session) -> bool:
        """Append a session record to the log.

        Args:
            session: An ElevationSession (or any object with a to_dict() method).

        Returns:
            True if successfully written, False on error.
        """
        try:
            data = session.to_dict()
        except Exception as e:
            logger.error("Cannot serialize session for logging: %s", e)
            return False

        line = json.dumps(data, separators=(',', ':'), default=str) + '\n'

        with self._lock:
            try:
                with open(self._path, 'a', encoding='utf-8') as f:
                    f.write(line)
                return True
            except OSError as e:
                logger.error("Cannot write to session log %s: %s",
                           self._path, e)
                return False

    def read_recent(self, limit: int = 50) -> List[dict]:
        """Read the most recent session entries.

        Args:
            limit: Maximum number of entries to return (most recent first).

        Returns:
            List of session dicts, newest first. Empty list if file
            doesn't exist or is empty.
        """
        with self._lock:
            return self._read_recent_unlocked(limit)

    def _read_recent_unlocked(self, limit: int) -> List[dict]:
        """Internal read without lock (for use when lock already held)."""
        if not self._path.exists():
            return []

        entries = []
        try:
            with open(self._path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            logger.warning("Skipping malformed session log line")
                            continue
        except OSError as e:
            logger.error("Cannot read session log %s: %s", self._path, e)
            return []

        # Return most recent first, limited
        return entries[-limit:][::-1]

    def read_all(self) -> List[dict]:
        """Read all session entries (for admin export)."""
        return self.read_recent(limit=10_000)

    @property
    def path(self) -> str:
        """Get the path to the session log file."""
        return str(self._path)

    @property
    def entry_count(self) -> int:
        """Count the number of entries in the log."""
        if not self._path.exists():
            return 0
        count = 0
        try:
            with open(self._path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        count += 1
        except OSError:
            return 0
        return count
