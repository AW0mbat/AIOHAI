#!/usr/bin/env python3
"""
Approval Manager — Manages action approval lifecycle.

Handles creation, validation, approval, rejection, and expiration of
action requests. Includes session binding, rate limiting, content
integrity verification, and sensitivity detection.

Phase 5 extraction from proxy/aiohai_proxy.py.
"""

import hashlib
import hmac
import secrets
import threading
from datetime import datetime, timedelta
from typing import Dict, Optional

from aiohai.core.types import (
    SecurityError, AlertSeverity,
    ActionCategory, TargetDomain, ApprovalLevel, SecurityGate,
)
from aiohai.core.constants import APPROVAL_ID_BYTES
from aiohai.core.config import UnifiedConfig
from aiohai.core.audit.logger import SecurityLogger
from aiohai.core.access.target_classifier import TargetClassifier
from aiohai.core.access.tier_matrix import TierMatrix, TIER_MATRIX

__all__ = ['ApprovalManager']


class ApprovalManager:
    """Manages approvals with rate limiting and proper session binding."""

    MAX_PENDING_PER_SESSION = 10  # Prevent approval flooding

    def __init__(self, config: UnifiedConfig, logger: SecurityLogger,
                 tier_matrix: TierMatrix = None):
        self.config = config
        self.logger = logger
        self.pending: Dict[str, Dict] = {}
        self.lock = threading.Lock()
        self.tier_matrix = tier_matrix or TIER_MATRIX

        # Sensitive operation detector (optional)
        self.sensitive_detector = None
        try:
            from aiohai.core.analysis.sensitive_ops import SensitiveOperationDetector
            self.sensitive_detector = SensitiveOperationDetector()
        except ImportError:
            pass

    def classify_action(self, action_type: str, target: str,
                        content: str = "") -> Dict:
        """Classify an action through the taxonomy pipeline.

        Maps legacy action type → ActionCategory, classifies target → TargetDomain,
        looks up (category, domain) → ApprovalLevel in the tier matrix.

        Returns dict with:
            category: ActionCategory enum
            domain: TargetDomain enum
            approval_level: ApprovalLevel enum
            gate: SecurityGate enum
        """
        category = ActionCategory.from_legacy_action_type(action_type)

        # Determine classification hint from action type
        hint_map = {
            'READ': 'file', 'WRITE': 'file', 'DELETE': 'file', 'LIST': 'file',
            'FILE_READ': 'file', 'FILE_WRITE': 'file',
            'FILE_DELETE': 'file', 'DIRECTORY_LIST': 'file',
            'COMMAND': 'command', 'COMMAND_EXEC': 'command',
            'API_QUERY': 'api', 'LOCAL_API_QUERY': 'api',
            'DOCUMENT_OP': 'office',
        }
        hint = hint_map.get(action_type)

        domain = TargetClassifier.classify(
            target, hint=hint, action_type=action_type)
        approval_level = self.tier_matrix.lookup(category, domain)

        return {
            'category': category,
            'domain': domain,
            'approval_level': approval_level,
            'gate': approval_level.gate,
        }

    def create_request(self, action_type: str, target: str, content: str,
                       user_id: str = "", session_id: str = "",
                       taxonomy: Dict = None) -> str:
        """Create an approval request. session_id MUST be provided by the caller.

        Args:
            taxonomy: Optional pre-computed taxonomy dict with keys:
                category, domain, approval_level, gate.
                If not provided, classify_action() is called automatically.

        Raises SecurityError if session_id is empty (H-5 fix).
        """
        if not session_id:
            raise SecurityError("session_id is required for approval requests (H-5 fix)")

        with self.lock:
            # Rate limit check
            session_pending = sum(1 for a in self.pending.values()
                                  if a.get('session_id') == session_id)
            if session_pending >= self.MAX_PENDING_PER_SESSION:
                raise SecurityError(
                    f"Too many pending approvals ({session_pending}). "
                    "Please review existing actions with `PENDING` command."
                )

        # Compute taxonomy if not provided
        if taxonomy is None:
            taxonomy = self.classify_action(action_type, target, content)

        approval_id = secrets.token_hex(APPROVAL_ID_BYTES)
        expires = datetime.now() + timedelta(minutes=self.config.approval_expiry_minutes)

        # Detect sensitivity
        sensitivity = []
        if self.sensitive_detector:
            sensitivity = self.sensitive_detector.detect(target, content)

        # Hash the content for integrity verification
        # C4 FIX: Include action_type and target in hash to prevent
        # cross-action substitution attacks.
        hash_input = f"{action_type}:{target}:{content}"
        content_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:16]

        with self.lock:
            self.pending[approval_id] = {
                'type': action_type,
                'target': target,
                'content': content,
                'content_hash': content_hash,
                'user_id': user_id,
                'session_id': session_id,
                'sensitivity': sensitivity,
                'created': datetime.now().isoformat(),
                'expires': expires.isoformat(),
                # Taxonomy metadata (Phase 1B)
                'category': taxonomy['category'].value,
                'domain': taxonomy['domain'].value,
                'approval_level': taxonomy['approval_level'].value,
                'gate': taxonomy['gate'].name,
            }

        self.logger.log_event("APPROVAL_CREATED", AlertSeverity.INFO,
                             {'id': approval_id[:8], 'type': action_type,
                              'gate': taxonomy['gate'].name,
                              'level': taxonomy['approval_level'].value,
                              'sensitive': len(sensitivity) > 0})
        return approval_id

    def approve(self, approval_id: str, user_id: str = "default",
                session_id: str = "default") -> Optional[Dict]:
        """Timing-safe approval check with session validation."""
        with self.lock:
            # Timing-safe lookup
            found_id = None
            for pending_id in self.pending.keys():
                if hmac.compare_digest(pending_id, approval_id):
                    found_id = pending_id
                    break

            if found_id is None:
                return None

            action = self.pending[found_id]

            # H-5 FIX: Always enforce session binding — never skip for 'default'.
            # Both stored and provided session IDs must be non-empty and match.
            stored_session = action.get('session_id', '')
            if not stored_session or not session_id:
                self.logger.log_event("APPROVAL_SESSION_MISSING", AlertSeverity.HIGH,
                                     {'id': approval_id[:8]})
                return None
            if not hmac.compare_digest(stored_session, session_id):
                self.logger.log_event("APPROVAL_SESSION_MISMATCH", AlertSeverity.HIGH,
                                     {'id': approval_id[:8]})
                return None

            # Expiration check
            if datetime.fromisoformat(action['expires']) < datetime.now():
                del self.pending[found_id]
                return None

            # Verify content integrity
            if action.get('content_hash'):
                # C4 FIX: Recompute with same inputs as create_request()
                hash_input = f"{action['type']}:{action['target']}:{action['content']}"
                current_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:16]
                if not hmac.compare_digest(action['content_hash'], current_hash):
                    self.logger.log_event("APPROVAL_CONTENT_TAMPERED", AlertSeverity.CRITICAL,
                                         {'id': approval_id[:8]})
                    del self.pending[found_id]
                    return None

            approved = self.pending.pop(found_id)
            self.logger.log_event("APPROVAL_GRANTED", AlertSeverity.INFO,
                                 {'id': approval_id[:8], 'type': action['type']})
            return approved

    def reject(self, approval_id: str) -> bool:
        with self.lock:
            for pending_id in list(self.pending.keys()):
                if hmac.compare_digest(pending_id, approval_id) or \
                        pending_id.startswith(approval_id):
                    del self.pending[pending_id]
                    self.logger.log_event("APPROVAL_REJECTED", AlertSeverity.INFO,
                                         {'id': approval_id[:8]})
                    return True
            return False

    def get_all_pending(self) -> Dict[str, Dict]:
        with self.lock:
            now = datetime.now()
            expired = [k for k, v in self.pending.items()
                      if datetime.fromisoformat(v['expires']) < now]
            for k in expired:
                del self.pending[k]
            return self.pending.copy()

    def has_destructive_pending(self) -> bool:
        """Check if any pending actions are destructive (DELETE)."""
        with self.lock:
            return any(a['type'] == 'DELETE' for a in self.pending.values())

    def get_destructive_pending(self) -> Dict[str, Dict]:
        """Get only destructive pending actions."""
        with self.lock:
            return {k: v for k, v in self.pending.items() if v['type'] == 'DELETE'}

    def clear_all(self) -> int:
        with self.lock:
            count = len(self.pending)
            self.pending.clear()
            return count
