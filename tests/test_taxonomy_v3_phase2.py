#!/usr/bin/env python3
"""
Tests for Approval Gate Taxonomy v3 — Phase 2 Session Elevation

Run: python -m pytest tests/test_taxonomy_v3_phase2.py -v
  or: python tests/test_taxonomy_v3_phase2.py
"""

import json
import os
import sys
import tempfile
import time
import threading
import unittest
from datetime import datetime, timedelta
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from aiohai.core.types import (
    SecurityGate, ActionCategory, TargetDomain, ApprovalLevel,
    SecurityError, AlertSeverity,
)
from aiohai.core.trust.session import (
    SessionManager, ElevationSession, SessionScope,
    DEFAULT_MAX_ACTIONS, DEFAULT_MAX_DURATION_MINUTES,
    MIN_ELEVATED_LEVEL_FOR_HARDWARE, DEFAULT_ELEVATED_LEVEL,
    MAX_FAILURES_BEFORE_CLOSE,
)
from aiohai.core.trust.session_store import SessionStore
from aiohai.core.config import UnifiedConfig
from aiohai.core.audit.logger import SecurityLogger
from aiohai.proxy.approval import ApprovalManager


# =============================================================================
# Helper
# =============================================================================

def _scope(cat, dom):
    return SessionScope(cat, dom)


# =============================================================================
# SessionScope Tests
# =============================================================================

class TestSessionScope(unittest.TestCase):

    def test_creation_and_str(self):
        s = _scope(ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS)
        self.assertEqual(str(s), "TRANSFER:FS_DOC_SENS")

    def test_from_string_roundtrip(self):
        original = _scope(ActionCategory.DELETE, TargetDomain.FS_TEMP)
        parsed = SessionScope.from_string(str(original))
        self.assertEqual(original, parsed)

    def test_from_string_invalid(self):
        with self.assertRaises(ValueError):
            SessionScope.from_string("NOCOLON")

    def test_equality_and_hashing(self):
        a = _scope(ActionCategory.OBSERVE, TargetDomain.FS_DOC)
        b = _scope(ActionCategory.OBSERVE, TargetDomain.FS_DOC)
        c = _scope(ActionCategory.DELETE, TargetDomain.FS_DOC)
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)
        self.assertEqual(hash(a), hash(b))
        self.assertEqual(len(frozenset([a, b, c])), 2)

    def test_frozen(self):
        s = _scope(ActionCategory.OBSERVE, TargetDomain.FS_DOC)
        with self.assertRaises(AttributeError):
            s.category = ActionCategory.DELETE


# =============================================================================
# ElevationSession Tests
# =============================================================================

class TestElevationSession(unittest.TestCase):

    def _make(self, **kw):
        defaults = dict(
            session_id='sess_test',
            scope=frozenset([_scope(ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS)]),
            gate_authenticated=SecurityGate.BIOMETRIC,
            elevated_level=ApprovalLevel.NOTIFY_AND_PROCEED,
            max_actions=10,
            expires_at=datetime.now() + timedelta(minutes=15),
        )
        defaults.update(kw)
        return ElevationSession(**defaults)

    def test_active_fresh(self):
        self.assertTrue(self._make().is_active)

    def test_not_active_expired(self):
        s = self._make(expires_at=datetime.now() - timedelta(seconds=1))
        self.assertFalse(s.is_active)

    def test_not_active_exhausted(self):
        s = self._make(max_actions=2)
        s.actions_used = 2
        self.assertFalse(s.is_active)

    def test_not_active_closed(self):
        s = self._make()
        s.close("done")
        self.assertFalse(s.is_active)

    def test_covers_matching(self):
        s = self._make()
        self.assertTrue(s.covers(ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS))

    def test_covers_non_matching(self):
        s = self._make()
        self.assertFalse(s.covers(ActionCategory.DELETE, TargetDomain.FS_DOC_SENS))
        self.assertFalse(s.covers(ActionCategory.TRANSFER, TargetDomain.FS_DOC))

    def test_use_action_consumes_slot(self):
        s = self._make(max_actions=3)
        self.assertTrue(s.use_action())
        self.assertEqual(s.actions_used, 1)
        self.assertTrue(s.use_action())
        self.assertTrue(s.use_action())
        self.assertFalse(s.use_action())  # exhausted

    def test_failure_circuit_breaker(self):
        s = self._make()
        self.assertFalse(s.record_failure())
        self.assertTrue(s.record_failure())  # 2nd → close

    def test_rejection_closes(self):
        s = self._make()
        s.record_rejection()
        self.assertEqual(s.end_reason, "rejection_circuit_breaker")
        self.assertFalse(s.is_active)

    def test_undo_closes(self):
        s = self._make()
        s.record_undo()
        self.assertEqual(s.end_reason, "undo_circuit_breaker")

    def test_close_idempotent(self):
        s = self._make()
        s.close("first")
        t = s.ended_at
        s.close("second")
        self.assertEqual(s.end_reason, "first")
        self.assertEqual(s.ended_at, t)

    def test_to_dict_serializable(self):
        s = self._make()
        d = s.to_dict()
        j = json.dumps(d)  # Must not raise
        self.assertIn("TRANSFER:FS_DOC_SENS", j)
        self.assertEqual(d['gate_authenticated'], 'BIOMETRIC')
        self.assertEqual(d['elevated_level'], 11)

    def test_time_remaining(self):
        s = self._make(expires_at=datetime.now() + timedelta(seconds=60))
        self.assertGreater(s.time_remaining_seconds, 50)
        self.assertLessEqual(s.time_remaining_seconds, 60)

    def test_actions_remaining_clamped(self):
        s = self._make(max_actions=5)
        s.actions_used = 100
        self.assertEqual(s.actions_remaining, 0)


# =============================================================================
# SessionManager — Core Lifecycle
# =============================================================================

class TestSessionManagerLifecycle(unittest.TestCase):

    def setUp(self):
        self.mgr = SessionManager()

    def test_open_and_check(self):
        scope = [_scope(ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS)]
        session = self.mgr.open_session(
            scope=scope, gate_authenticated=SecurityGate.BIOMETRIC)
        result = self.mgr.check_elevation(
            ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS)
        self.assertIsNotNone(result)
        s, level = result
        self.assertEqual(level, DEFAULT_ELEVATED_LEVEL)
        self.assertEqual(s.session_id, session.session_id)

    def test_non_covered_returns_none(self):
        scope = [_scope(ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS)]
        self.mgr.open_session(
            scope=scope, gate_authenticated=SecurityGate.BIOMETRIC)
        self.assertIsNone(self.mgr.check_elevation(
            ActionCategory.DELETE, TargetDomain.FS_DOC_SENS))
        self.assertIsNone(self.mgr.check_elevation(
            ActionCategory.TRANSFER, TargetDomain.FS_DOC))

    def test_close_makes_elevation_unavailable(self):
        scope = [_scope(ActionCategory.OBSERVE, TargetDomain.FS_DOC_SENS)]
        session = self.mgr.open_session(
            scope=scope, gate_authenticated=SecurityGate.SOFTWARE)
        self.mgr.close_session(session.session_id)
        self.assertIsNone(self.mgr.check_elevation(
            ActionCategory.OBSERVE, TargetDomain.FS_DOC_SENS))

    def test_use_action_and_exhaust(self):
        scope = [_scope(ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS)]
        session = self.mgr.open_session(
            scope=scope, gate_authenticated=SecurityGate.BIOMETRIC,
            max_actions=3)
        self.assertTrue(self.mgr.use_session_action(session.session_id))
        self.assertTrue(self.mgr.use_session_action(session.session_id))
        self.assertTrue(self.mgr.use_session_action(session.session_id))
        # Exhausted
        self.assertFalse(self.mgr.use_session_action(session.session_id))
        self.assertIsNone(self.mgr.check_elevation(
            ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS))

    def test_close_all(self):
        scope1 = [_scope(ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS)]
        scope2 = [_scope(ActionCategory.OBSERVE, TargetDomain.FS_DOC)]
        self.mgr.open_session(scope=scope1, gate_authenticated=SecurityGate.BIOMETRIC)
        self.mgr.open_session(scope=scope2, gate_authenticated=SecurityGate.SOFTWARE)
        self.mgr.close_all("test_cleanup")
        self.assertEqual(len(self.mgr.get_active_sessions()), 0)

    def test_get_active_sessions(self):
        scope1 = [_scope(ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS)]
        scope2 = [_scope(ActionCategory.OBSERVE, TargetDomain.FS_DOC)]
        s1 = self.mgr.open_session(scope=scope1, gate_authenticated=SecurityGate.BIOMETRIC)
        s2 = self.mgr.open_session(scope=scope2, gate_authenticated=SecurityGate.SOFTWARE)
        active = self.mgr.get_active_sessions()
        self.assertEqual(len(active), 2)

    def test_get_session_by_id(self):
        scope = [_scope(ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS)]
        session = self.mgr.open_session(
            scope=scope, gate_authenticated=SecurityGate.BIOMETRIC)
        retrieved = self.mgr.get_session(session.session_id)
        self.assertEqual(retrieved.session_id, session.session_id)

    def test_get_session_for_scope(self):
        scope = [_scope(ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS)]
        session = self.mgr.open_session(
            scope=scope, gate_authenticated=SecurityGate.BIOMETRIC)
        found = self.mgr.get_session_for_scope(
            ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS)
        self.assertIsNotNone(found)
        self.assertEqual(found.session_id, session.session_id)


# =============================================================================
# SessionManager — Validation
# =============================================================================

class TestSessionManagerValidation(unittest.TestCase):

    def setUp(self):
        self.mgr = SessionManager()

    def test_empty_scope_rejected(self):
        with self.assertRaises(ValueError):
            self.mgr.open_session(scope=[], gate_authenticated=SecurityGate.SOFTWARE)

    def test_deny_gate_rejected(self):
        with self.assertRaises(ValueError):
            self.mgr.open_session(
                scope=[_scope(ActionCategory.ADMIN, TargetDomain.FS_SYSTEM)],
                gate_authenticated=SecurityGate.DENY)

    def test_passive_gate_rejected(self):
        with self.assertRaises(ValueError):
            self.mgr.open_session(
                scope=[_scope(ActionCategory.OBSERVE, TargetDomain.FS_TEMP)],
                gate_authenticated=SecurityGate.PASSIVE)

    def test_hardware_gate_minimum_level_enforced(self):
        """PHYSICAL/BIOMETRIC sessions can't go below CONFIRM_QUICK (10)."""
        with self.assertRaises(ValueError):
            self.mgr.open_session(
                scope=[_scope(ActionCategory.EXECUTE, TargetDomain.HA_LOCK)],
                gate_authenticated=SecurityGate.PHYSICAL,
                elevated_level=ApprovalLevel.CONFIRM_STANDARD)  # 9 < 10

    def test_hardware_gate_allows_confirm_quick(self):
        session = self.mgr.open_session(
            scope=[_scope(ActionCategory.EXECUTE, TargetDomain.HA_LOCK)],
            gate_authenticated=SecurityGate.PHYSICAL,
            elevated_level=ApprovalLevel.CONFIRM_QUICK)  # 10 == min
        self.assertTrue(session.is_active)

    def test_elevated_must_be_less_restrictive_than_gate(self):
        """Elevated level must actually reduce friction vs the gate."""
        # BIOMETRIC gate max level is 7 (BIOMETRIC_QUICK). Elevated must be > 7.
        with self.assertRaises(ValueError):
            self.mgr.open_session(
                scope=[_scope(ActionCategory.MODIFY, TargetDomain.FS_DOC_SENS)],
                gate_authenticated=SecurityGate.BIOMETRIC,
                elevated_level=ApprovalLevel.BIOMETRIC_QUICK)  # 7 == gate max

    def test_software_gate_can_elevate_to_passive(self):
        session = self.mgr.open_session(
            scope=[_scope(ActionCategory.MODIFY, TargetDomain.FS_DOC)],
            gate_authenticated=SecurityGate.SOFTWARE,
            elevated_level=ApprovalLevel.NOTIFY_AND_PROCEED)
        self.assertTrue(session.is_active)


# =============================================================================
# SessionManager — Circuit Breakers
# =============================================================================

class TestSessionCircuitBreakers(unittest.TestCase):

    def setUp(self):
        self.mgr = SessionManager()
        scope = [_scope(ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS)]
        self.session = self.mgr.open_session(
            scope=scope, gate_authenticated=SecurityGate.BIOMETRIC)

    def test_rejection_closes_session(self):
        self.mgr.record_rejection(self.session.session_id)
        self.assertIsNone(self.mgr.check_elevation(
            ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS))
        self.assertEqual(self.session.end_reason, "rejection_circuit_breaker")

    def test_undo_closes_session(self):
        self.mgr.record_undo(self.session.session_id)
        self.assertIsNone(self.mgr.check_elevation(
            ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS))
        self.assertEqual(self.session.end_reason, "undo_circuit_breaker")

    def test_failure_circuit_breaker(self):
        # 1st failure: session stays open
        self.assertFalse(self.mgr.record_failure(self.session.session_id))
        self.assertIsNotNone(self.mgr.check_elevation(
            ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS))
        # 2nd failure: session closes
        self.assertTrue(self.mgr.record_failure(self.session.session_id))
        self.assertIsNone(self.mgr.check_elevation(
            ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS))

    def test_rejection_on_nonexistent_session(self):
        # Should not raise
        self.mgr.record_rejection("nonexistent_id")

    def test_undo_on_nonexistent_session(self):
        self.mgr.record_undo("nonexistent_id")

    def test_failure_on_nonexistent_session(self):
        self.assertFalse(self.mgr.record_failure("nonexistent_id"))


# =============================================================================
# SessionManager — Scope Isolation
# =============================================================================

class TestSessionScopeIsolation(unittest.TestCase):

    def setUp(self):
        self.mgr = SessionManager()

    def test_multi_scope_session(self):
        """A session can cover multiple (category, domain) pairs."""
        scope = [
            _scope(ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS),
            _scope(ActionCategory.OBSERVE, TargetDomain.FS_DOC_SENS),
            _scope(ActionCategory.CREATE, TargetDomain.FS_DOC_SENS),
        ]
        session = self.mgr.open_session(
            scope=scope, gate_authenticated=SecurityGate.BIOMETRIC)

        # All covered
        self.assertIsNotNone(self.mgr.check_elevation(
            ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS))
        self.assertIsNotNone(self.mgr.check_elevation(
            ActionCategory.OBSERVE, TargetDomain.FS_DOC_SENS))
        self.assertIsNotNone(self.mgr.check_elevation(
            ActionCategory.CREATE, TargetDomain.FS_DOC_SENS))

        # Not covered
        self.assertIsNone(self.mgr.check_elevation(
            ActionCategory.DELETE, TargetDomain.FS_DOC_SENS))

    def test_no_scope_creep(self):
        """Session for TRANSFER:FS_DOC_SENS does NOT cover DELETE:FS_DOC_SENS."""
        scope = [_scope(ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS)]
        self.mgr.open_session(scope=scope, gate_authenticated=SecurityGate.BIOMETRIC)
        self.assertIsNone(self.mgr.check_elevation(
            ActionCategory.DELETE, TargetDomain.FS_DOC_SENS))

    def test_no_stacking_overlapping_scope(self):
        """Opening a new session with overlapping scope replaces the old one."""
        scope = [_scope(ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS)]
        s1 = self.mgr.open_session(
            scope=scope, gate_authenticated=SecurityGate.BIOMETRIC)
        s2 = self.mgr.open_session(
            scope=scope, gate_authenticated=SecurityGate.BIOMETRIC,
            max_actions=50)

        # s1 should be closed
        self.assertFalse(s1.is_active)
        self.assertEqual(s1.end_reason, "replaced_by_new_session")

        # s2 should be active
        result = self.mgr.check_elevation(
            ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS)
        self.assertIsNotNone(result)
        self.assertEqual(result[0].session_id, s2.session_id)

    def test_non_overlapping_sessions_coexist(self):
        """Sessions for non-overlapping scopes can coexist."""
        scope1 = [_scope(ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS)]
        scope2 = [_scope(ActionCategory.EXECUTE, TargetDomain.HA_LIGHT)]
        s1 = self.mgr.open_session(scope=scope1, gate_authenticated=SecurityGate.BIOMETRIC)
        s2 = self.mgr.open_session(scope=scope2, gate_authenticated=SecurityGate.SOFTWARE)

        self.assertTrue(s1.is_active)
        self.assertTrue(s2.is_active)
        self.assertEqual(len(self.mgr.get_active_sessions()), 2)

    def test_scope_expansion(self):
        scope = [_scope(ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS)]
        session = self.mgr.open_session(
            scope=scope, gate_authenticated=SecurityGate.BIOMETRIC)

        # Initially doesn't cover CREATE
        self.assertIsNone(self.mgr.check_elevation(
            ActionCategory.CREATE, TargetDomain.FS_DOC_SENS))

        # Expand scope
        ok, msg = self.mgr.expand_scope(
            session.session_id,
            [_scope(ActionCategory.CREATE, TargetDomain.FS_DOC_SENS)])
        self.assertTrue(ok)

        # Now covers CREATE too
        self.assertIsNotNone(self.mgr.check_elevation(
            ActionCategory.CREATE, TargetDomain.FS_DOC_SENS))


# =============================================================================
# SessionManager — Session Plan Builder
# =============================================================================

class TestSessionPlanBuilder(unittest.TestCase):

    def setUp(self):
        self.mgr = SessionManager()

    def _action(self, cat, dom, gate, level):
        return {
            'category': cat,
            'domain': dom,
            'gate': gate,
            'approval_level': level,
        }

    def test_no_plan_for_single_action(self):
        actions = [
            self._action(ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS,
                         SecurityGate.BIOMETRIC, ApprovalLevel.BIOMETRIC_STANDARD),
        ]
        self.assertIsNone(self.mgr.build_session_plan(actions))

    def test_no_plan_for_all_passive(self):
        actions = [
            self._action(ActionCategory.OBSERVE, TargetDomain.FS_TEMP,
                         SecurityGate.PASSIVE, ApprovalLevel.SILENT),
            self._action(ActionCategory.LIST, TargetDomain.FS_TEMP,
                         SecurityGate.PASSIVE, ApprovalLevel.TRANSPARENT),
        ]
        self.assertIsNone(self.mgr.build_session_plan(actions))

    def test_plan_for_multiple_biometric_actions(self):
        actions = [
            self._action(ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS,
                         SecurityGate.BIOMETRIC, ApprovalLevel.BIOMETRIC_STANDARD),
            self._action(ActionCategory.OBSERVE, TargetDomain.FS_DOC_SENS,
                         SecurityGate.BIOMETRIC, ApprovalLevel.BIOMETRIC_STANDARD),
            self._action(ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS,
                         SecurityGate.BIOMETRIC, ApprovalLevel.BIOMETRIC_STANDARD),
        ]
        plan = self.mgr.build_session_plan(actions)
        self.assertIsNotNone(plan)
        self.assertEqual(plan['gate_required'], SecurityGate.BIOMETRIC)
        self.assertEqual(plan['action_count'], 3)
        self.assertGreaterEqual(plan['suggested_max_actions'], 3)

    def test_plan_mixed_gates_uses_highest(self):
        actions = [
            self._action(ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS,
                         SecurityGate.BIOMETRIC, ApprovalLevel.BIOMETRIC_STANDARD),
            self._action(ActionCategory.EXECUTE, TargetDomain.HA_LOCK,
                         SecurityGate.PHYSICAL, ApprovalLevel.PHYSICAL_STANDARD),
        ]
        plan = self.mgr.build_session_plan(actions)
        self.assertIsNotNone(plan)
        # PHYSICAL < BIOMETRIC numerically, meaning more restrictive
        self.assertEqual(plan['gate_required'], SecurityGate.PHYSICAL)

    def test_plan_excludes_passive_from_count(self):
        actions = [
            self._action(ActionCategory.OBSERVE, TargetDomain.FS_TEMP,
                         SecurityGate.PASSIVE, ApprovalLevel.SILENT),
            self._action(ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS,
                         SecurityGate.BIOMETRIC, ApprovalLevel.BIOMETRIC_STANDARD),
            self._action(ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS,
                         SecurityGate.BIOMETRIC, ApprovalLevel.BIOMETRIC_STANDARD),
        ]
        plan = self.mgr.build_session_plan(actions)
        self.assertIsNotNone(plan)
        self.assertEqual(plan['action_count'], 2)
        self.assertEqual(plan['passive_count'], 1)

    def test_empty_actions(self):
        self.assertIsNone(self.mgr.build_session_plan([]))


# =============================================================================
# SessionStore Tests
# =============================================================================

class TestSessionStore(unittest.TestCase):

    def setUp(self):
        self.tmpfile = tempfile.NamedTemporaryFile(
            suffix='.jsonl', delete=False)
        self.tmpfile.close()
        self.store = SessionStore(self.tmpfile.name)

    def tearDown(self):
        try:
            os.unlink(self.tmpfile.name)
        except OSError:
            pass

    def _make_session(self, sid='sess_001', end_reason='test'):
        session = ElevationSession(
            session_id=sid,
            scope=frozenset([_scope(ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS)]),
            gate_authenticated=SecurityGate.BIOMETRIC,
            elevated_level=ApprovalLevel.NOTIFY_AND_PROCEED,
            max_actions=10,
            expires_at=datetime.now() + timedelta(minutes=15),
        )
        session.close(end_reason)
        return session

    def test_append_and_read(self):
        s = self._make_session()
        self.assertTrue(self.store.append(s))
        entries = self.store.read_recent()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]['session_id'], 'sess_001')

    def test_multiple_entries(self):
        for i in range(5):
            self.store.append(self._make_session(f'sess_{i:03d}'))
        entries = self.store.read_recent()
        self.assertEqual(len(entries), 5)
        # Most recent first
        self.assertEqual(entries[0]['session_id'], 'sess_004')

    def test_read_limit(self):
        for i in range(10):
            self.store.append(self._make_session(f'sess_{i:03d}'))
        entries = self.store.read_recent(limit=3)
        self.assertEqual(len(entries), 3)

    def test_read_empty(self):
        entries = self.store.read_recent()
        self.assertEqual(entries, [])

    def test_entry_count(self):
        self.assertEqual(self.store.entry_count, 0)
        self.store.append(self._make_session('a'))
        self.store.append(self._make_session('b'))
        self.assertEqual(self.store.entry_count, 2)

    def test_path_property(self):
        self.assertEqual(self.store.path, self.tmpfile.name)

    def test_jsonl_format(self):
        """Each entry should be a single JSON line."""
        self.store.append(self._make_session())
        with open(self.tmpfile.name) as f:
            lines = f.readlines()
        self.assertEqual(len(lines), 1)
        data = json.loads(lines[0])
        self.assertIn('session_id', data)


# =============================================================================
# ApprovalManager — Session Elevation Integration
# =============================================================================

class TestApprovalManagerSessionIntegration(unittest.TestCase):

    def setUp(self):
        self.config = UnifiedConfig()
        self.logger = SecurityLogger(self.config)
        self.session_mgr = SessionManager()
        self.approval = ApprovalManager(
            self.config, self.logger, session_manager=self.session_mgr)

    def test_no_session_returns_default(self):
        level, sid = self.approval.check_session_elevation(
            ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS,
            ApprovalLevel.BIOMETRIC_STANDARD)
        self.assertEqual(level, ApprovalLevel.BIOMETRIC_STANDARD)
        self.assertIsNone(sid)

    def test_with_session_returns_elevated(self):
        scope = [_scope(ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS)]
        session = self.session_mgr.open_session(
            scope=scope, gate_authenticated=SecurityGate.BIOMETRIC)
        level, sid = self.approval.check_session_elevation(
            ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS,
            ApprovalLevel.BIOMETRIC_STANDARD)
        self.assertEqual(level, ApprovalLevel.NOTIFY_AND_PROCEED)
        self.assertEqual(sid, session.session_id)

    def test_non_covered_scope_returns_default(self):
        scope = [_scope(ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS)]
        self.session_mgr.open_session(
            scope=scope, gate_authenticated=SecurityGate.BIOMETRIC)
        level, sid = self.approval.check_session_elevation(
            ActionCategory.DELETE, TargetDomain.FS_DOC,
            ApprovalLevel.CONFIRM_STANDARD)
        self.assertEqual(level, ApprovalLevel.CONFIRM_STANDARD)
        self.assertIsNone(sid)

    def test_no_session_manager_returns_default(self):
        approval = ApprovalManager(self.config, self.logger, session_manager=None)
        level, sid = approval.check_session_elevation(
            ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS,
            ApprovalLevel.BIOMETRIC_STANDARD)
        self.assertEqual(level, ApprovalLevel.BIOMETRIC_STANDARD)
        self.assertIsNone(sid)

    def test_build_session_plan_delegates(self):
        actions = [
            {'category': ActionCategory.TRANSFER, 'domain': TargetDomain.FS_DOC_SENS,
             'gate': SecurityGate.BIOMETRIC, 'approval_level': ApprovalLevel.BIOMETRIC_STANDARD},
            {'category': ActionCategory.OBSERVE, 'domain': TargetDomain.FS_DOC_SENS,
             'gate': SecurityGate.BIOMETRIC, 'approval_level': ApprovalLevel.BIOMETRIC_STANDARD},
        ]
        plan = self.approval.build_session_plan(actions)
        self.assertIsNotNone(plan)
        self.assertEqual(plan['action_count'], 2)

    def test_build_session_plan_without_manager(self):
        approval = ApprovalManager(self.config, self.logger, session_manager=None)
        self.assertIsNone(approval.build_session_plan([]))


# =============================================================================
# SessionManager — Thread Safety
# =============================================================================

class TestSessionManagerThreadSafety(unittest.TestCase):

    def test_concurrent_open_and_check(self):
        """Open sessions and check elevations from multiple threads."""
        mgr = SessionManager()
        errors = []

        def worker(i):
            try:
                cat = ActionCategory.TRANSFER
                # Use different domains for each thread to avoid collisions
                domains = list(TargetDomain)
                dom = domains[i % len(domains)]
                scope = [_scope(cat, dom)]
                session = mgr.open_session(
                    scope=scope, gate_authenticated=SecurityGate.SOFTWARE)
                result = mgr.check_elevation(cat, dom)
                if result is None:
                    errors.append(f"Thread {i}: elevation check returned None")
                mgr.use_session_action(session.session_id)
                mgr.close_session(session.session_id)
            except Exception as e:
                errors.append(f"Thread {i}: {e}")

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [], f"Thread errors: {errors}")


# =============================================================================
# SessionManager — Persistence Integration
# =============================================================================

class TestSessionManagerPersistence(unittest.TestCase):

    def test_closed_sessions_persisted(self):
        tmpfile = tempfile.NamedTemporaryFile(suffix='.jsonl', delete=False)
        tmpfile.close()
        try:
            store = SessionStore(tmpfile.name)
            mgr = SessionManager(store=store)

            scope = [_scope(ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS)]
            session = mgr.open_session(
                scope=scope, gate_authenticated=SecurityGate.BIOMETRIC)
            mgr.close_session(session.session_id, "test_persist")

            entries = store.read_recent()
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]['end_reason'], 'test_persist')
        finally:
            os.unlink(tmpfile.name)

    def test_rejection_persisted(self):
        tmpfile = tempfile.NamedTemporaryFile(suffix='.jsonl', delete=False)
        tmpfile.close()
        try:
            store = SessionStore(tmpfile.name)
            mgr = SessionManager(store=store)

            scope = [_scope(ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS)]
            session = mgr.open_session(
                scope=scope, gate_authenticated=SecurityGate.BIOMETRIC)
            mgr.record_rejection(session.session_id)

            entries = store.read_recent()
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]['end_reason'], 'rejection_circuit_breaker')
            self.assertEqual(entries[0]['rejection_count'], 1)
        finally:
            os.unlink(tmpfile.name)


# =============================================================================
# SessionManager — Defaults Verification
# =============================================================================

class TestSessionDefaults(unittest.TestCase):
    """Verify strict defaults from the spec."""

    def test_default_max_actions(self):
        self.assertEqual(DEFAULT_MAX_ACTIONS, 10)

    def test_default_max_duration(self):
        self.assertEqual(DEFAULT_MAX_DURATION_MINUTES, 15)

    def test_min_hardware_level(self):
        self.assertEqual(MIN_ELEVATED_LEVEL_FOR_HARDWARE, ApprovalLevel.CONFIRM_QUICK)

    def test_default_elevated_level(self):
        self.assertEqual(DEFAULT_ELEVATED_LEVEL, ApprovalLevel.NOTIFY_AND_PROCEED)

    def test_max_failures(self):
        self.assertEqual(MAX_FAILURES_BEFORE_CLOSE, 2)


# =============================================================================
# Import Verification
# =============================================================================

class TestImports(unittest.TestCase):
    """Verify all Phase 2 modules import correctly."""

    def test_session_module(self):
        from aiohai.core.trust.session import SessionManager, ElevationSession, SessionScope
        self.assertTrue(callable(SessionManager))

    def test_session_store_module(self):
        from aiohai.core.trust.session_store import SessionStore
        self.assertTrue(callable(SessionStore))

    def test_trust_package(self):
        import aiohai.core.trust
        self.assertTrue(hasattr(aiohai.core.trust, '__file__'))

    def test_approval_manager_accepts_session_manager(self):
        """ApprovalManager constructor should accept session_manager kwarg."""
        import inspect
        sig = inspect.signature(ApprovalManager.__init__)
        self.assertIn('session_manager', sig.parameters)

    def test_handler_context_has_session_slot(self):
        from aiohai.proxy.handler import HandlerContext
        self.assertIn('session_manager', HandlerContext.__slots__)

    def test_version_bumped(self):
        from aiohai.core.version import __version__
        self.assertEqual(__version__, "6.0.0")


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases(unittest.TestCase):

    def test_use_action_on_nonexistent_session(self):
        mgr = SessionManager()
        self.assertFalse(mgr.use_session_action("nonexistent"))

    def test_close_nonexistent_session(self):
        mgr = SessionManager()
        mgr.close_session("nonexistent")  # Should not raise

    def test_expand_scope_nonexistent(self):
        mgr = SessionManager()
        ok, msg = mgr.expand_scope("nonexistent", [])
        self.assertFalse(ok)

    def test_expand_scope_closed_session(self):
        mgr = SessionManager()
        scope = [_scope(ActionCategory.TRANSFER, TargetDomain.FS_DOC_SENS)]
        session = mgr.open_session(
            scope=scope, gate_authenticated=SecurityGate.BIOMETRIC)
        mgr.close_session(session.session_id)
        ok, msg = mgr.expand_scope(
            session.session_id,
            [_scope(ActionCategory.DELETE, TargetDomain.FS_DOC_SENS)])
        self.assertFalse(ok)

    def test_session_plan_with_string_enums(self):
        """build_session_plan should handle string enum values from parsed dicts."""
        mgr = SessionManager()
        actions = [
            {'category': 'TRANSFER', 'domain': 'FS_DOC_SENS',
             'gate': 'BIOMETRIC', 'approval_level': 6},
            {'category': 'OBSERVE', 'domain': 'FS_DOC_SENS',
             'gate': 'BIOMETRIC', 'approval_level': 6},
        ]
        plan = mgr.build_session_plan(actions)
        self.assertIsNotNone(plan)
        self.assertEqual(plan['action_count'], 2)


# =============================================================================
# Run
# =============================================================================

if __name__ == '__main__':
    unittest.main(verbosity=2)
