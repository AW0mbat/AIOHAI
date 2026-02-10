#!/usr/bin/env python3
"""
AIOHAI Core Trust — Session Manager
=====================================
Manages session elevation: temporary approval gate step-downs within
strict bounds.

The Gate is a Door
------------------
When a batch of gate-level actions is needed, the user authenticates
ONCE at the gate level ("opens the door"). Subsequent actions within
the same narrowly-scoped session drop to SOFTWARE or PASSIVE level.
When the session ends — by time, count, circuit breaker, or explicit
termination — the door closes and the next action requires fresh
gate-level authentication.

Session elevation is NOT permanent gate demotion. The action's default
gate assignment never changes. The session is a temporary overlay.

Key Invariants
--------------
- Sessions are narrowly scoped to a set of (ActionCategory, TargetDomain) pairs.
- Actions outside the declared scope require their normal gate-level auth.
- Scope expansion requires re-authentication at the gate level.
- Only one session per (category, domain) pair at a time (no stacking).
- Circuit breakers: rejection, undo, 2+ failures → immediate session end.
- Strict defaults: 10 actions, 15 minutes.
- Minimum elevated level for hardware gates: CONFIRM_QUICK (level 10).
- Default elevated level: NOTIFY_AND_PROCEED (level 11).

Phase 2 of Approval Gate Taxonomy v3 implementation.

Import from: aiohai.core.trust.session
"""

from __future__ import annotations

import logging
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple

from aiohai.core.types import (
    ActionCategory, TargetDomain, ApprovalLevel, SecurityGate,
)

__all__ = ['SessionManager', 'ElevationSession', 'SessionScope']

logger = logging.getLogger("aiohai.core.trust.session")


# =============================================================================
# CONSTANTS
# =============================================================================

# Strict defaults — admin can increase via companion app settings
DEFAULT_MAX_ACTIONS = 10
DEFAULT_MAX_DURATION_MINUTES = 15

# For PHYSICAL and BIOMETRIC sessions, the elevated level cannot be
# lower (less restrictive) than CONFIRM_QUICK (level 10). The door
# opens into the house, not into the yard.
MIN_ELEVATED_LEVEL_FOR_HARDWARE = ApprovalLevel.CONFIRM_QUICK  # level 10

# Default elevated level: NOTIFY_AND_PROCEED (auto-execute with undo)
DEFAULT_ELEVATED_LEVEL = ApprovalLevel.NOTIFY_AND_PROCEED  # level 11

# Maximum number of execution failures before circuit-breaker fires
MAX_FAILURES_BEFORE_CLOSE = 2

# Session ID entropy
SESSION_ID_BYTES = 12  # 24 hex chars


# =============================================================================
# SESSION SCOPE
# =============================================================================

@dataclass(frozen=True)
class SessionScope:
    """An immutable (category, domain) pair defining one axis of session scope.

    A session's full scope is a frozenset of SessionScope objects.
    """
    category: ActionCategory
    domain: TargetDomain

    def __str__(self) -> str:
        return f"{self.category.value}:{self.domain.value}"

    @classmethod
    def from_string(cls, s: str) -> 'SessionScope':
        """Parse 'CATEGORY:DOMAIN' string."""
        parts = s.split(':', 1)
        if len(parts) != 2:
            raise ValueError(f"Invalid scope string: {s!r} (expected CATEGORY:DOMAIN)")
        return cls(
            category=ActionCategory(parts[0]),
            domain=TargetDomain(parts[1]),
        )


# =============================================================================
# ELEVATION SESSION
# =============================================================================

@dataclass
class ElevationSession:
    """A single active elevation session.

    Tracks scope, limits, authentication gate, and circuit-breaker state.
    """
    session_id: str
    scope: frozenset  # frozenset[SessionScope]
    gate_authenticated: SecurityGate
    elevated_level: ApprovalLevel
    max_actions: int
    expires_at: datetime
    created_at: datetime = field(default_factory=datetime.now)

    # Mutable counters
    actions_used: int = 0
    failure_count: int = 0
    rejection_count: int = 0
    undo_count: int = 0
    ended_at: Optional[datetime] = None
    end_reason: Optional[str] = None

    @property
    def is_active(self) -> bool:
        """True if this session is still valid (not expired, ended, or exhausted)."""
        if self.ended_at is not None:
            return False
        if datetime.now() >= self.expires_at:
            return False
        if self.actions_used >= self.max_actions:
            return False
        return True

    @property
    def actions_remaining(self) -> int:
        return max(0, self.max_actions - self.actions_used)

    @property
    def time_remaining_seconds(self) -> float:
        delta = (self.expires_at - datetime.now()).total_seconds()
        return max(0.0, delta)

    def covers(self, category: ActionCategory, domain: TargetDomain) -> bool:
        """Check if this session's scope covers a (category, domain) pair."""
        return SessionScope(category, domain) in self.scope

    def use_action(self) -> bool:
        """Record an action execution within this session.

        Returns True if the action was allowed (session still active).
        Returns False if the session is exhausted/expired/ended.
        """
        if not self.is_active:
            return False
        self.actions_used += 1
        return True

    def record_failure(self) -> bool:
        """Record an execution failure. Returns True if session should close."""
        self.failure_count += 1
        return self.failure_count >= MAX_FAILURES_BEFORE_CLOSE

    def record_rejection(self):
        """Record a user rejection — immediately closes the session."""
        self.rejection_count += 1
        self.close("rejection_circuit_breaker")

    def record_undo(self):
        """Record a user undo — immediately closes the session."""
        self.undo_count += 1
        self.close("undo_circuit_breaker")

    def close(self, reason: str):
        """Close this session with a reason string."""
        if self.ended_at is None:
            self.ended_at = datetime.now()
            self.end_reason = reason
            logger.info(
                "Session %s closed: %s (used %d/%d actions, %d failures)",
                self.session_id[:8], reason,
                self.actions_used, self.max_actions,
                self.failure_count,
            )

    def to_dict(self) -> Dict:
        """Serialize to JSON-safe dict for audit logging."""
        return {
            'session_id': self.session_id,
            'scope': [str(s) for s in sorted(self.scope, key=str)],
            'gate_authenticated': self.gate_authenticated.name,
            'elevated_level': self.elevated_level.value,
            'elevated_level_name': self.elevated_level.name,
            'max_actions': self.max_actions,
            'actions_used': self.actions_used,
            'failure_count': self.failure_count,
            'rejection_count': self.rejection_count,
            'undo_count': self.undo_count,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat(),
            'ended_at': self.ended_at.isoformat() if self.ended_at else None,
            'end_reason': self.end_reason,
        }


# =============================================================================
# SESSION MANAGER
# =============================================================================

class SessionManager:
    """Manages elevation sessions with strict scope, time, and count bounds.

    Thread-safe. All public methods acquire self._lock.

    Usage:
        mgr = SessionManager()

        # Open a session after user authenticates at BIOMETRIC gate
        session = mgr.open_session(
            scope=[SessionScope(ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS),
                   SessionScope(ActionCategory.OBSERVE, TargetDomain.FS_DOC_SENS)],
            gate_authenticated=SecurityGate.BIOMETRIC,
            elevated_level=ApprovalLevel.NOTIFY_AND_PROCEED,
        )

        # Check if a subsequent action can use the session
        result = mgr.check_elevation(ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS)
        if result:
            session, elevated_level = result
            # Execute at elevated_level instead of gate level
    """

    def __init__(self, *, max_actions: int = DEFAULT_MAX_ACTIONS,
                 max_duration_minutes: int = DEFAULT_MAX_DURATION_MINUTES,
                 min_hardware_level: ApprovalLevel = MIN_ELEVATED_LEVEL_FOR_HARDWARE,
                 default_elevated_level: ApprovalLevel = DEFAULT_ELEVATED_LEVEL,
                 store=None):
        """Initialize the session manager.

        Args:
            max_actions: Default max actions per session.
            max_duration_minutes: Default max session duration.
            min_hardware_level: Minimum elevated level for PHYSICAL/BIOMETRIC sessions.
            default_elevated_level: Default level that elevated actions execute at.
            store: Optional SessionStore for JSONL persistence.
        """
        self._lock = threading.Lock()
        self._sessions: Dict[str, ElevationSession] = {}
        # Index: (category, domain) → session_id for fast scope lookup
        self._scope_index: Dict[SessionScope, str] = {}

        # Configurable defaults
        self.max_actions = max_actions
        self.max_duration_minutes = max_duration_minutes
        self.min_hardware_level = min_hardware_level
        self.default_elevated_level = default_elevated_level

        # Optional persistence
        self._store = store

    def open_session(
        self,
        scope: List[SessionScope],
        gate_authenticated: SecurityGate,
        elevated_level: ApprovalLevel = None,
        max_actions: int = None,
        max_duration_minutes: int = None,
    ) -> ElevationSession:
        """Open a new elevation session after user authenticates at gate level.

        Args:
            scope: List of (category, domain) pairs this session covers.
            gate_authenticated: The gate the user actually authenticated at.
            elevated_level: Level subsequent actions execute at.
                           Defaults to self.default_elevated_level.
            max_actions: Override default max actions.
            max_duration_minutes: Override default max duration.

        Returns:
            The created ElevationSession.

        Raises:
            ValueError: If scope is empty, gate is DENY/PASSIVE, or
                       elevated_level is invalid for the gate.
        """
        if not scope:
            raise ValueError("Session scope cannot be empty")

        if gate_authenticated == SecurityGate.DENY:
            raise ValueError("Cannot open a session for DENY gate actions")

        if gate_authenticated == SecurityGate.PASSIVE:
            raise ValueError(
                "Cannot open a session for PASSIVE gate actions "
                "(they already execute without confirmation)"
            )

        if elevated_level is None:
            elevated_level = self.default_elevated_level

        # Validate elevated level for hardware gates
        if gate_authenticated.is_hardware:
            if elevated_level.value < self.min_hardware_level.value:
                raise ValueError(
                    f"Elevated level {elevated_level.name} (level {elevated_level.value}) "
                    f"is below minimum {self.min_hardware_level.name} "
                    f"(level {self.min_hardware_level.value}) for "
                    f"{gate_authenticated.name} gate sessions. "
                    f"The door opens into the house, not into the yard."
                )

        # Elevated level must be less restrictive than the gate's levels
        # (otherwise the session doesn't reduce friction)
        gate_max_level = {
            SecurityGate.PHYSICAL: 4,   # PHYSICAL_QUICK
            SecurityGate.BIOMETRIC: 7,  # BIOMETRIC_QUICK
            SecurityGate.SOFTWARE: 10,  # CONFIRM_QUICK
        }.get(gate_authenticated, 10)
        if elevated_level.value <= gate_max_level:
            raise ValueError(
                f"Elevated level {elevated_level.name} ({elevated_level.value}) "
                f"is not less restrictive than {gate_authenticated.name} gate "
                f"(max level {gate_max_level}). Session elevation must reduce "
                f"approval friction."
            )

        max_actions = max_actions or self.max_actions
        max_duration = max_duration_minutes or self.max_duration_minutes

        session_id = f"sess_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(SESSION_ID_BYTES)}"
        scope_set = frozenset(scope)

        now = datetime.now()
        session = ElevationSession(
            session_id=session_id,
            scope=scope_set,
            gate_authenticated=gate_authenticated,
            elevated_level=elevated_level,
            max_actions=max_actions,
            expires_at=now + timedelta(minutes=max_duration),
            created_at=now,
        )

        with self._lock:
            # No stacking: replace existing sessions for overlapping scopes
            replaced = []
            for scope_item in scope_set:
                existing_sid = self._scope_index.get(scope_item)
                if existing_sid and existing_sid != session_id:
                    existing = self._sessions.get(existing_sid)
                    if existing and existing.is_active:
                        existing.close("replaced_by_new_session")
                        self._persist_session(existing)
                        replaced.append(existing_sid)
                    # Clean up old index entries
                    self._scope_index[scope_item] = session_id

            # Register the new session
            self._sessions[session_id] = session
            for scope_item in scope_set:
                self._scope_index[scope_item] = session_id

            if replaced:
                logger.info(
                    "Session %s replaced %d existing session(s) with overlapping scope",
                    session_id[:8], len(set(replaced)),
                )

        logger.info(
            "Session %s opened: gate=%s, elevated=%s, scope=%s, max=%d actions / %d min",
            session_id[:8], gate_authenticated.name, elevated_level.name,
            [str(s) for s in scope_set], max_actions, max_duration,
        )

        return session

    def check_elevation(
        self, category: ActionCategory, domain: TargetDomain
    ) -> Optional[Tuple[ElevationSession, ApprovalLevel]]:
        """Check if an active session covers this (category, domain) pair.

        Returns (session, elevated_level) if covered, None otherwise.

        This does NOT consume an action slot — call use_session_action()
        after the action actually executes.
        """
        scope_key = SessionScope(category, domain)

        with self._lock:
            session_id = self._scope_index.get(scope_key)
            if session_id is None:
                return None

            session = self._sessions.get(session_id)
            if session is None:
                # Stale index entry
                del self._scope_index[scope_key]
                return None

            if not session.is_active:
                self._cleanup_session(session)
                return None

            return (session, session.elevated_level)

    def use_session_action(self, session_id: str) -> bool:
        """Record that an action executed under this session.

        Returns True if successfully recorded, False if session is no longer active.
        Call this AFTER the action executes successfully.
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return False

            if not session.use_action():
                # Session exhausted — close it
                if session.actions_used >= session.max_actions:
                    session.close("action_count_exhausted")
                else:
                    session.close("expired")
                self._persist_session(session)
                self._cleanup_session(session)
                return False

            # Check if this was the last allowed action
            if not session.is_active:
                session.close("action_count_exhausted")
                self._persist_session(session)
                self._cleanup_session(session)

            return True

    def record_failure(self, session_id: str) -> bool:
        """Record an execution failure within a session.

        Returns True if the session was closed due to failure circuit-breaker.
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return False

            should_close = session.record_failure()
            if should_close:
                session.close("failure_circuit_breaker")
                self._persist_session(session)
                self._cleanup_session(session)
                return True
            return False

    def record_rejection(self, session_id: str):
        """Record a user rejection — immediately closes the session."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return

            session.record_rejection()
            self._persist_session(session)
            self._cleanup_session(session)

    def record_undo(self, session_id: str):
        """Record a user undo — immediately closes the session."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return

            session.record_undo()
            self._persist_session(session)
            self._cleanup_session(session)

    def close_session(self, session_id: str, reason: str = "user_closed"):
        """Explicitly close a session (e.g., user clicks "End Session")."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return

            session.close(reason)
            self._persist_session(session)
            self._cleanup_session(session)

    def close_all(self, reason: str = "proxy_restart"):
        """Close all active sessions (e.g., on proxy restart)."""
        with self._lock:
            for session in list(self._sessions.values()):
                if session.is_active:
                    session.close(reason)
                    self._persist_session(session)
            self._sessions.clear()
            self._scope_index.clear()

    def get_active_sessions(self) -> List[ElevationSession]:
        """Get all currently active sessions (for UI display)."""
        with self._lock:
            self._gc_expired()
            return [s for s in self._sessions.values() if s.is_active]

    def get_session(self, session_id: str) -> Optional[ElevationSession]:
        """Get a specific session by ID."""
        with self._lock:
            return self._sessions.get(session_id)

    def get_session_for_scope(
        self, category: ActionCategory, domain: TargetDomain
    ) -> Optional[ElevationSession]:
        """Get the active session covering a (category, domain), if any."""
        scope_key = SessionScope(category, domain)
        with self._lock:
            session_id = self._scope_index.get(scope_key)
            if session_id is None:
                return None
            session = self._sessions.get(session_id)
            if session and session.is_active:
                return session
            return None

    def expand_scope(
        self, session_id: str, additional_scope: List[SessionScope]
    ) -> Tuple[bool, str]:
        """Expand an existing session's scope (requires re-authentication).

        The caller is responsible for verifying the user re-authenticated
        at the gate level before calling this.

        Returns (success, message).
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return False, "Session not found"
            if not session.is_active:
                return False, "Session is no longer active"

            new_scope_items = []
            for scope_item in additional_scope:
                # Check for stacking conflicts with OTHER sessions
                existing_sid = self._scope_index.get(scope_item)
                if existing_sid and existing_sid != session_id:
                    existing = self._sessions.get(existing_sid)
                    if existing and existing.is_active:
                        existing.close("replaced_by_scope_expansion")
                        self._persist_session(existing)
                new_scope_items.append(scope_item)

            # Expand the scope (need to create new frozenset)
            expanded = session.scope | frozenset(new_scope_items)
            # We can't mutate a frozen dataclass field easily, so we
            # replace it via object.__setattr__ since scope is defined
            # in the dataclass but ElevationSession isn't frozen
            session.scope = expanded

            for scope_item in new_scope_items:
                self._scope_index[scope_item] = session_id

            logger.info(
                "Session %s scope expanded by %d items (total: %d)",
                session_id[:8], len(new_scope_items), len(expanded),
            )
            return True, f"Scope expanded to {len(expanded)} (category, domain) pairs"

    def build_session_plan(
        self, actions: List[Dict]
    ) -> Optional[Dict]:
        """Build a session plan from a list of parsed action dicts.

        Analyzes the actions to determine:
        - Which (category, domain) pairs are involved
        - What gate level is required
        - Suggested session parameters

        Args:
            actions: List of action dicts with 'category', 'domain',
                    'approval_level', 'gate' keys (from ActionParser).

        Returns:
            None if no session is needed (all passive or only 1 non-passive),
            or a dict with:
                'scope': list of SessionScope
                'gate_required': SecurityGate (highest gate among actions)
                'action_count': int
                'suggested_max_actions': int
                'suggested_duration_minutes': int
                'gate_counts': dict of gate_name → count
                'passive_count': int (actions that don't need elevation)
        """
        if not actions:
            return None

        # Collect non-passive actions that would benefit from elevation
        scope_set: Set[SessionScope] = set()
        highest_gate = SecurityGate.PASSIVE
        gate_counts: Dict[str, int] = {}
        passive_count = 0
        non_passive_count = 0

        for action in actions:
            category = action.get('category')
            domain = action.get('domain')
            gate = action.get('gate')
            level = action.get('approval_level')

            if category is None or domain is None or gate is None:
                continue

            # Ensure we're working with enums
            if isinstance(gate, str):
                gate = SecurityGate[gate]
            if isinstance(category, str):
                category = ActionCategory(category)
            if isinstance(domain, str):
                domain = TargetDomain(domain)
            if isinstance(level, int):
                level = ApprovalLevel(level)

            gate_name = gate.name
            gate_counts[gate_name] = gate_counts.get(gate_name, 0) + 1

            if gate == SecurityGate.PASSIVE or gate == SecurityGate.DENY:
                passive_count += 1
                continue

            non_passive_count += 1
            scope_set.add(SessionScope(category, domain))

            if gate < highest_gate:  # Lower value = more restrictive
                highest_gate = gate

        # Don't suggest a session for 0-1 non-passive actions
        if non_passive_count <= 1:
            return None

        # Suggest generous but bounded limits
        margin = max(5, non_passive_count // 4)
        suggested_max = non_passive_count + margin

        # Scale duration with action count, capped
        if non_passive_count <= 10:
            suggested_duration = DEFAULT_MAX_DURATION_MINUTES
        elif non_passive_count <= 30:
            suggested_duration = 20
        else:
            suggested_duration = 30

        return {
            'scope': sorted(scope_set, key=str),
            'gate_required': highest_gate,
            'action_count': non_passive_count,
            'suggested_max_actions': suggested_max,
            'suggested_duration_minutes': suggested_duration,
            'gate_counts': gate_counts,
            'passive_count': passive_count,
        }

    # ---- Internal helpers ----

    def _cleanup_session(self, session: ElevationSession):
        """Remove a closed/expired session from indices.

        Must be called with self._lock held.
        """
        sid = session.session_id
        # Remove scope index entries pointing to this session
        stale_keys = [k for k, v in self._scope_index.items() if v == sid]
        for k in stale_keys:
            del self._scope_index[k]
        # Don't remove from _sessions immediately — keep for get_session() lookups
        # until GC sweep

    def _gc_expired(self):
        """Garbage-collect expired sessions.

        Must be called with self._lock held.
        """
        now = datetime.now()
        expired_ids = []
        for sid, session in self._sessions.items():
            if not session.is_active and session.ended_at is None:
                # Auto-close expired/exhausted sessions
                if now >= session.expires_at:
                    session.close("expired")
                elif session.actions_used >= session.max_actions:
                    session.close("action_count_exhausted")
                self._persist_session(session)

            # Remove sessions that ended more than 5 minutes ago
            if session.ended_at and (now - session.ended_at).total_seconds() > 300:
                expired_ids.append(sid)

        for sid in expired_ids:
            session = self._sessions.pop(sid, None)
            if session:
                stale_keys = [k for k, v in self._scope_index.items() if v == sid]
                for k in stale_keys:
                    del self._scope_index[k]

    def _persist_session(self, session: ElevationSession):
        """Write session to the JSONL store if available."""
        if self._store:
            try:
                self._store.append(session)
            except Exception as e:
                logger.warning("Failed to persist session %s: %s",
                             session.session_id[:8], e)
