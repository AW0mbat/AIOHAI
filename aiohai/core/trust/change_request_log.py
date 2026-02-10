#!/usr/bin/env python3
"""
AIOHAI Core Trust — Change Request Log
=========================================
Persistence for gate-level change requests that cannot be applied at
runtime. Provides a viewable record of all requests the user has made
for changes that require code-level modification.

What Gets Logged
-----------------
1. Gate demotion requests (BIOMETRIC → SOFTWARE, PHYSICAL → BIOMETRIC)
2. DENY gate unlock requests (HARDBLOCK/SOFTBLOCK → any other level)
3. Runtime-rejected adjustments from the companion app or LLM

What The Admin Can Do
---------------------
- View all pending and previously applied requests
- Mark requests as "pending application" (for non-DENY items)
- Apply pending changes via restart (requires NFC tap at server)
- DENY gate items can NEVER be applied through this interface

File: config/change_requests.json

Phase 3 of Approval Gate Taxonomy v3 implementation.

Import from: aiohai.core.trust.change_request_log
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

__all__ = ['ChangeRequestLog']

logger = logging.getLogger("aiohai.core.trust.change_request_log")

# Default file path relative to AIOHAI_HOME
DEFAULT_CHANGE_REQUESTS = "config/change_requests.json"
SCHEMA_VERSION = "1.0"

# Request ID prefix
REQUEST_ID_PREFIX = "req"

# Maximum stored requests (prevent unbounded growth)
MAX_REQUESTS = 500


class ChangeRequestLog:
    """Append-only log of gate-level change requests.

    Thread-safe. Creates the file and parent directories on first write.

    Usage:
        log = ChangeRequestLog()

        # Add a change request from a rejected adjustment
        request_id = log.add_request(
            user="admin",
            category="TRANSFER",
            domain="OFF_ESEND",
            current_level=5,
            current_gate="BIOMETRIC",
            requested_level=9,
            requested_gate="SOFTWARE",
            boundary_violated="BIOMETRIC_TO_SOFTWARE",
            boundary_type="code_change_required",
            user_context="I send dozens of emails a day"
        )

        # View pending requests
        pending = log.get_pending()

        # Mark a request as applied (admin action)
        log.mark_applied(request_id, applied_by="admin",
                         code_diff="tier_matrix.py: TRANSFER:OFF_ESEND: 5 → 9")

        # Persistence
        log.save()
    """

    def __init__(self, path: Optional[str] = None):
        """Initialize the change request log.

        Args:
            path: Path to change_requests.json. Defaults to
                  $AIOHAI_HOME/config/change_requests.json.
        """
        if path is None:
            aiohai_home = os.environ.get('AIOHAI_HOME', '.')
            path = os.path.join(aiohai_home, DEFAULT_CHANGE_REQUESTS)

        self._path = Path(path)
        self._lock = threading.Lock()
        self._requests: List[Dict] = []
        self._loaded = False

    def _ensure_loaded(self):
        """Lazy-load from file on first access.

        Must be called with self._lock held.
        """
        if self._loaded:
            return

        if self._path.exists():
            try:
                with open(self._path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self._requests = data.get('requests', [])
            except (json.JSONDecodeError, OSError) as e:
                logger.error("Cannot read change request log %s: %s",
                           self._path, e)
                self._requests = []

        self._loaded = True

    def add_request(
        self, *,
        user: str,
        category: str,
        domain: str,
        current_level: int,
        current_gate: str,
        requested_level: int,
        requested_gate: str,
        boundary_violated: str,
        boundary_type: str,
        user_context: str = "",
    ) -> str:
        """Add a change request to the log.

        Args:
            user: Who made the request.
            category: ActionCategory value string.
            domain: TargetDomain value string.
            current_level: Current ApprovalLevel numeric value.
            current_gate: Current SecurityGate name.
            requested_level: Requested ApprovalLevel numeric value.
            requested_gate: Requested SecurityGate name.
            boundary_violated: Which boundary was hit (e.g. 'BIOMETRIC_TO_SOFTWARE').
            boundary_type: 'code_change_required' or 'manual_code_edit_only'.
            user_context: User's explanation of why they need this change.

        Returns:
            The generated request_id.
        """
        now = datetime.now()
        request_id = (
            f"{REQUEST_ID_PREFIX}_{now.strftime('%Y%m%d')}_{secrets.token_hex(4)}"
        )

        entry = {
            'request_id': request_id,
            'timestamp': now.isoformat(),
            'user': user,
            'category': category,
            'domain': domain,
            'current_level': current_level,
            'current_gate': current_gate,
            'requested_level': requested_level,
            'requested_gate': requested_gate,
            'boundary_violated': boundary_violated,
            'boundary_type': boundary_type,
            'user_context': user_context,
            'status': 'logged',
            'applied': None,
            'applied_by': None,
            'applied_at': None,
        }

        with self._lock:
            self._ensure_loaded()

            # Trim old entries if over limit
            if len(self._requests) >= MAX_REQUESTS:
                # Remove oldest non-pending entries first
                applied_indices = [
                    i for i, r in enumerate(self._requests)
                    if r.get('status') in ('applied', 'rejected', 'cancelled')
                ]
                if applied_indices:
                    del self._requests[applied_indices[0]]
                else:
                    # All pending — remove oldest
                    del self._requests[0]

            self._requests.append(entry)

        logger.info(
            "Change request logged: %s (%s:%s, %s → %s, boundary: %s)",
            request_id, category, domain,
            current_gate, requested_gate, boundary_violated,
        )

        return request_id

    def add_from_adjustment_result(
        self, result, user: str = "unknown"
    ) -> Optional[str]:
        """Add a change request from an AdjustmentResult.

        Returns the request_id, or None if the result doesn't warrant
        a change request (i.e., it was allowed or has no boundary violation).
        """
        if result.allowed or not result.boundary_violated:
            return None

        return self.add_request(
            user=user,
            category=result.category.value if result.category else "UNKNOWN",
            domain=result.domain.value if result.domain else "UNKNOWN",
            current_level=(result.current_level.value
                          if result.current_level else -1),
            current_gate=(result.current_level.gate.name
                         if result.current_level else "UNKNOWN"),
            requested_level=(result.requested_level.value
                            if result.requested_level else -1),
            requested_gate=(result.requested_level.gate.name
                           if result.requested_level else "UNKNOWN"),
            boundary_violated=result.boundary_violated,
            boundary_type=(
                'manual_code_edit_only'
                if result.boundary_violated == 'DENY_GATE'
                else 'code_change_required'
            ),
            user_context=result.reason,
        )

    def get_pending(self) -> List[Dict]:
        """Get all pending (not yet applied) change requests."""
        with self._lock:
            self._ensure_loaded()
            return [
                r for r in self._requests
                if r.get('status') == 'logged'
            ]

    def get_applied(self) -> List[Dict]:
        """Get all previously applied change requests."""
        with self._lock:
            self._ensure_loaded()
            return [
                r for r in self._requests
                if r.get('status') == 'applied'
            ]

    def get_all(self) -> List[Dict]:
        """Get all change requests (pending + applied + rejected)."""
        with self._lock:
            self._ensure_loaded()
            return list(self._requests)

    def get_request(self, request_id: str) -> Optional[Dict]:
        """Get a specific request by ID or prefix."""
        with self._lock:
            self._ensure_loaded()
            for r in self._requests:
                if r['request_id'] == request_id:
                    return dict(r)
                if r['request_id'].startswith(request_id):
                    return dict(r)
            return None

    def mark_applied(
        self, request_id: str, *,
        applied_by: str,
        code_diff: str = "",
        nfc_verification: bool = False,
    ) -> Tuple[bool, str]:
        """Mark a change request as applied.

        DENY gate requests cannot be marked as applied through this
        interface — they require manual code editing.

        Args:
            request_id: Full or prefix of the request ID.
            applied_by: Who applied the change.
            code_diff: Description of the code change made.
            nfc_verification: Whether NFC verification was performed.

        Returns:
            (success, message)
        """
        with self._lock:
            self._ensure_loaded()

            target = None
            for r in self._requests:
                if (r['request_id'] == request_id or
                        r['request_id'].startswith(request_id)):
                    target = r
                    break

            if target is None:
                return False, f"Request {request_id!r} not found"

            # DENY gate cannot be applied through this mechanism
            if target.get('boundary_type') == 'manual_code_edit_only':
                return False, (
                    f"Request {target['request_id']} is a DENY gate change. "
                    f"This cannot be applied through the companion app or "
                    f"any automated mechanism. Manual source code editing is "
                    f"required."
                )

            if target.get('status') != 'logged':
                return False, (
                    f"Request {target['request_id']} is already "
                    f"{target.get('status', 'unknown')}"
                )

            now = datetime.now().isoformat()
            target['status'] = 'applied'
            target['applied'] = True
            target['applied_by'] = applied_by
            target['applied_at'] = now
            target['applied_via'] = 'companion_app_restart'
            target['nfc_verification'] = nfc_verification
            target['code_diff'] = code_diff

            logger.info(
                "Change request %s applied by %s (NFC: %s)",
                target['request_id'], applied_by, nfc_verification,
            )
            return True, f"Request {target['request_id']} marked as applied"

    def mark_rejected(
        self, request_id: str, *, rejected_by: str, reason: str = ""
    ) -> Tuple[bool, str]:
        """Mark a change request as rejected (admin decided not to apply)."""
        with self._lock:
            self._ensure_loaded()

            target = None
            for r in self._requests:
                if (r['request_id'] == request_id or
                        r['request_id'].startswith(request_id)):
                    target = r
                    break

            if target is None:
                return False, f"Request {request_id!r} not found"

            if target.get('status') != 'logged':
                return False, (
                    f"Request {target['request_id']} is already "
                    f"{target.get('status', 'unknown')}"
                )

            target['status'] = 'rejected'
            target['applied'] = False
            target['applied_by'] = rejected_by
            target['applied_at'] = datetime.now().isoformat()
            if reason:
                target['rejection_reason'] = reason

            return True, f"Request {target['request_id']} marked as rejected"

    def save(self) -> bool:
        """Save the log to disk.

        Returns True on success.
        """
        with self._lock:
            self._ensure_loaded()
            data = {
                '_schema_version': SCHEMA_VERSION,
                'requests': self._requests,
            }

        # Ensure directory exists
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            logger.error("Cannot create directory: %s", e)
            return False

        # Write atomically
        tmp_path = self._path.with_suffix('.tmp')
        try:
            with open(tmp_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
                f.write('\n')
            tmp_path.replace(self._path)
            return True
        except OSError as e:
            logger.error("Cannot write change request log: %s", e)
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            return False

    @property
    def path(self) -> str:
        """Get the path to the change request log file."""
        return str(self._path)

    @property
    def pending_count(self) -> int:
        """Count pending (not yet applied) requests."""
        with self._lock:
            self._ensure_loaded()
            return sum(1 for r in self._requests
                      if r.get('status') == 'logged')

    @property
    def total_count(self) -> int:
        """Count total requests."""
        with self._lock:
            self._ensure_loaded()
            return len(self._requests)
