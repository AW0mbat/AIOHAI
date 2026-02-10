#!/usr/bin/env python3
"""
AIOHAI v5.4.0 — Phase 3 Test Suite
=====================================
Tests for Runtime Trust Matrix Adjustments and Change Request Log.

Phase 3 of Approval Gate Taxonomy v3 implementation.
"""

import json
import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from aiohai.core.types import (
    ActionCategory, TargetDomain, ApprovalLevel, SecurityGate,
    AlertSeverity,
)
from aiohai.core.access.tier_matrix import TierMatrix, TIER_MATRIX
from aiohai.core.trust.matrix_adjuster import (
    TrustMatrixAdjuster, AdjustmentResult,
    OVERRIDES_SCHEMA_VERSION, MAX_OVERRIDES,
)
from aiohai.core.trust.change_request_log import (
    ChangeRequestLog, SCHEMA_VERSION, MAX_REQUESTS,
)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def tmp_config(tmp_path):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "backups").mkdir()
    return tmp_path

@pytest.fixture
def fresh_matrix():
    return TierMatrix()

@pytest.fixture
def adjuster(tmp_config, fresh_matrix):
    return TrustMatrixAdjuster(
        tier_matrix=fresh_matrix,
        overrides_path=str(tmp_config / "config" / "user_overrides.json"),
    )

@pytest.fixture
def change_log(tmp_config):
    return ChangeRequestLog(
        path=str(tmp_config / "config" / "change_requests.json")
    )

@pytest.fixture
def adjuster_with_log(tmp_config, fresh_matrix, change_log):
    return TrustMatrixAdjuster(
        tier_matrix=fresh_matrix,
        overrides_path=str(tmp_config / "config" / "user_overrides.json"),
        change_request_log=change_log,
    )


# =============================================================================
# TrustMatrixAdjuster — Proposal & Validation
# =============================================================================

class TestAdjusterProposal:
    def test_within_gate_passive_allowed(self, adjuster):
        result = adjuster.propose_adjustment(
            ActionCategory.EXECUTE, TargetDomain.HA_LIGHT,
            ApprovalLevel.SILENT, reason="Make lights silent")
        assert result.allowed is True
        assert result.boundary_violated is None

    def test_within_gate_software_allowed(self, adjuster):
        result = adjuster.propose_adjustment(
            ActionCategory.MODIFY, TargetDomain.FS_DOC,
            ApprovalLevel.CONFIRM_DETAILED)
        assert result.allowed is True

    def test_within_gate_biometric_allowed(self, adjuster):
        result = adjuster.propose_adjustment(
            ActionCategory.MODIFY, TargetDomain.FS_DOC_SENS,
            ApprovalLevel.BIOMETRIC_QUICK)
        assert result.allowed is True

    def test_gate_promotion_passive_to_software(self, adjuster):
        result = adjuster.propose_adjustment(
            ActionCategory.OBSERVE, TargetDomain.FS_DOC,
            ApprovalLevel.CONFIRM_STANDARD)
        assert result.allowed is True

    def test_gate_promotion_software_to_biometric(self, adjuster):
        result = adjuster.propose_adjustment(
            ActionCategory.MODIFY, TargetDomain.FS_DOC,
            ApprovalLevel.BIOMETRIC_STANDARD)
        assert result.allowed is True

    def test_gate_demotion_physical_to_software(self, adjuster):
        result = adjuster.propose_adjustment(
            ActionCategory.EXECUTE, TargetDomain.HA_LOCK,
            ApprovalLevel.CONFIRM_STANDARD)
        assert result.allowed is False
        assert result.boundary_violated == 'PHYSICAL_TO_SOFTWARE'

    def test_gate_demotion_physical_to_biometric(self, adjuster):
        result = adjuster.propose_adjustment(
            ActionCategory.EXECUTE, TargetDomain.HA_LOCK,
            ApprovalLevel.BIOMETRIC_STANDARD)
        assert result.allowed is False
        assert 'PHYSICAL' in result.boundary_violated

    def test_gate_demotion_physical_to_passive(self, adjuster):
        result = adjuster.propose_adjustment(
            ActionCategory.EXECUTE, TargetDomain.HA_LOCK,
            ApprovalLevel.SILENT)
        assert result.allowed is False

    def test_gate_demotion_biometric_to_software(self, adjuster):
        result = adjuster.propose_adjustment(
            ActionCategory.MODIFY, TargetDomain.FS_DOC_SENS,
            ApprovalLevel.CONFIRM_STANDARD)
        assert result.allowed is False
        assert result.boundary_violated == 'BIOMETRIC_TO_SOFTWARE'

    def test_gate_demotion_biometric_to_passive(self, adjuster):
        result = adjuster.propose_adjustment(
            ActionCategory.MODIFY, TargetDomain.FS_DOC_SENS,
            ApprovalLevel.SILENT)
        assert result.allowed is False

    def test_deny_gate_hardblock_immutable(self, adjuster):
        result = adjuster.propose_adjustment(
            ActionCategory.ADMIN, TargetDomain.FS_SYSTEM,
            ApprovalLevel.CONFIRM_STANDARD)
        assert result.allowed is False
        assert result.boundary_violated == 'DENY_GATE'
        assert len(result.alternatives) == 0

    def test_deny_gate_softblock_immutable(self, adjuster):
        result = adjuster.propose_adjustment(
            ActionCategory.CREATE, TargetDomain.OFF_MACRO,
            ApprovalLevel.CONFIRM_STANDARD)
        assert result.allowed is False
        assert result.boundary_violated == 'DENY_GATE'

    def test_deny_gate_to_passive_immutable(self, adjuster):
        result = adjuster.propose_adjustment(
            ActionCategory.OBSERVE, TargetDomain.FS_SYSTEM,
            ApprovalLevel.SILENT)
        assert result.allowed is False
        assert result.boundary_violated == 'DENY_GATE'

    def test_alternatives_for_physical_demotion(self, adjuster):
        result = adjuster.propose_adjustment(
            ActionCategory.EXECUTE, TargetDomain.HA_LOCK,
            ApprovalLevel.CONFIRM_STANDARD)
        alt_levels = {a['level'] for a in result.alternatives}
        assert ApprovalLevel.PHYSICAL_QUICK.value in alt_levels
        assert ApprovalLevel.PHYSICAL_DETAILED.value in alt_levels

    def test_alternatives_for_biometric_demotion(self, adjuster):
        result = adjuster.propose_adjustment(
            ActionCategory.MODIFY, TargetDomain.FS_DOC_SENS,
            ApprovalLevel.CONFIRM_STANDARD)
        alt_levels = {a['level'] for a in result.alternatives}
        assert ApprovalLevel.BIOMETRIC_QUICK.value in alt_levels
        assert ApprovalLevel.BIOMETRIC_DETAILED.value in alt_levels

    def test_no_alternatives_for_deny(self, adjuster):
        result = adjuster.propose_adjustment(
            ActionCategory.ADMIN, TargetDomain.FS_SYSTEM,
            ApprovalLevel.SILENT)
        assert len(result.alternatives) == 0

    def test_same_level_noop(self, adjuster):
        result = adjuster.propose_adjustment(
            ActionCategory.EXECUTE, TargetDomain.HA_LIGHT,
            ApprovalLevel.NOTIFY_AND_PROCEED)
        assert result.allowed is True

    def test_unknown_pair_defaults_to_confirm_standard(self, adjuster):
        current = adjuster.get_current_level(
            ActionCategory.INSTALL, TargetDomain.FS_MEDIA)
        assert current == ApprovalLevel.CONFIRM_STANDARD


# =============================================================================
# TrustMatrixAdjuster — Apply & Remove
# =============================================================================

class TestAdjusterApply:
    def test_apply_allowed(self, adjuster):
        result = adjuster.propose_adjustment(
            ActionCategory.EXECUTE, TargetDomain.HA_LIGHT,
            ApprovalLevel.SILENT)
        assert adjuster.apply_adjustment(result) is True
        assert adjuster.get_current_level(
            ActionCategory.EXECUTE, TargetDomain.HA_LIGHT
        ) == ApprovalLevel.SILENT

    def test_apply_rejected_fails(self, adjuster):
        result = adjuster.propose_adjustment(
            ActionCategory.ADMIN, TargetDomain.FS_SYSTEM,
            ApprovalLevel.CONFIRM_STANDARD)
        assert adjuster.apply_adjustment(result) is False

    def test_remove_reverts_to_default(self, adjuster):
        result = adjuster.propose_adjustment(
            ActionCategory.EXECUTE, TargetDomain.HA_LIGHT,
            ApprovalLevel.SILENT)
        adjuster.apply_adjustment(result)
        removed = adjuster.remove_adjustment(
            ActionCategory.EXECUTE, TargetDomain.HA_LIGHT)
        assert removed is True
        assert adjuster.get_current_level(
            ActionCategory.EXECUTE, TargetDomain.HA_LIGHT
        ) == ApprovalLevel.NOTIFY_AND_PROCEED

    def test_remove_nonexistent(self, adjuster):
        assert adjuster.remove_adjustment(
            ActionCategory.OBSERVE, TargetDomain.FS_TEMP) is False

    def test_reset_all(self, adjuster):
        r = adjuster.propose_adjustment(
            ActionCategory.EXECUTE, TargetDomain.HA_LIGHT,
            ApprovalLevel.SILENT)
        adjuster.apply_adjustment(r)
        r = adjuster.propose_adjustment(
            ActionCategory.EXECUTE, TargetDomain.HA_MEDIA,
            ApprovalLevel.SILENT)
        adjuster.apply_adjustment(r)
        count = adjuster.reset_all()
        assert count >= 2
        assert not adjuster.has_overrides()

    def test_get_all_overrides(self, adjuster):
        r = adjuster.propose_adjustment(
            ActionCategory.EXECUTE, TargetDomain.HA_LIGHT,
            ApprovalLevel.SILENT)
        adjuster.apply_adjustment(r)
        overrides = adjuster.get_all_overrides()
        assert 'EXECUTE:HA_LIGHT' in overrides
        assert overrides['EXECUTE:HA_LIGHT']['level'] == 14


# =============================================================================
# TrustMatrixAdjuster — Natural Language API
# =============================================================================

class TestAdjusterNaturalLanguage:
    def test_valid_proposal(self, adjuster):
        result = adjuster.propose_from_natural_language(
            "EXECUTE", "HA_LIGHT", 14, reason="Silent lights")
        assert result.allowed is True

    def test_invalid_category(self, adjuster):
        result = adjuster.propose_from_natural_language(
            "INVALID_CAT", "HA_LIGHT", 14)
        assert result.allowed is False
        assert "Unknown category" in result.explanation

    def test_invalid_domain(self, adjuster):
        result = adjuster.propose_from_natural_language(
            "EXECUTE", "INVALID_DOM", 14)
        assert result.allowed is False
        assert "Unknown domain" in result.explanation

    def test_invalid_level(self, adjuster):
        result = adjuster.propose_from_natural_language(
            "EXECUTE", "HA_LIGHT", 99)
        assert result.allowed is False
        assert "Unknown level" in result.explanation

    def test_gate_demotion_via_nl(self, adjuster):
        result = adjuster.propose_from_natural_language(
            "EXECUTE", "HA_LOCK", 9)
        assert result.allowed is False
        assert result.boundary_violated is not None


# =============================================================================
# TrustMatrixAdjuster — Persistence
# =============================================================================

class TestAdjusterPersistence:
    def test_save_and_load_roundtrip(self, adjuster):
        # Apply some overrides
        r = adjuster.propose_adjustment(
            ActionCategory.EXECUTE, TargetDomain.HA_LIGHT,
            ApprovalLevel.SILENT, reason="Silent lights")
        adjuster.apply_adjustment(r)
        adjuster.set_path_classification(
            "C:\\Users\\test\\Documents\\Recipes", "FS_DOC", "Not sensitive")
        adjuster.add_command("ollama show", "CMD_INFO", "Safe info command")
        adjuster.set_ha_entity_override(
            "switch.office_fan", "HA_CLIM", "Fan not switch")
        adjuster.set_session_defaults(max_actions=25)

        # Save
        assert adjuster.save_to_file() is True

        # Load in a fresh adjuster
        fresh = TrustMatrixAdjuster(
            tier_matrix=TierMatrix(),
            overrides_path=adjuster.overrides_path,
        )
        ok, errors = fresh.load_from_file()
        assert ok is True
        assert len(errors) == 0

        # Verify
        assert fresh.get_current_level(
            ActionCategory.EXECUTE, TargetDomain.HA_LIGHT
        ) == ApprovalLevel.SILENT
        assert "C:\\Users\\test\\Documents\\Recipes" in fresh.path_classifications
        assert "ollama show" in fresh.command_additions
        assert "switch.office_fan" in fresh.ha_entity_overrides
        assert fresh.session_defaults.get('max_actions') == 25

    def test_load_nonexistent_file(self, tmp_config):
        adj = TrustMatrixAdjuster(
            overrides_path=str(tmp_config / "nonexistent.json"))
        ok, errors = adj.load_from_file()
        assert ok is True
        assert len(errors) == 0

    def test_load_with_rejected_overrides(self, tmp_config):
        # Write a file with an invalid override (DENY gate change)
        data = {
            '_schema_version': '3.0',
            'tier_overrides': {
                'ADMIN:FS_SYSTEM': {'level': 9},
            },
        }
        path = tmp_config / "config" / "user_overrides.json"
        path.write_text(json.dumps(data))

        adj = TrustMatrixAdjuster(
            tier_matrix=TierMatrix(),
            overrides_path=str(path),
        )
        ok, errors = adj.load_from_file()
        assert ok is False
        assert len(errors) == 1
        assert 'DENY' in errors[0]

    def test_save_creates_backup(self, adjuster):
        # Save once
        r = adjuster.propose_adjustment(
            ActionCategory.EXECUTE, TargetDomain.HA_LIGHT,
            ApprovalLevel.SILENT)
        adjuster.apply_adjustment(r)
        adjuster.save_to_file()

        # Save again (should create backup)
        r = adjuster.propose_adjustment(
            ActionCategory.EXECUTE, TargetDomain.HA_MEDIA,
            ApprovalLevel.SILENT)
        adjuster.apply_adjustment(r)
        adjuster.save_to_file()

        backup_dir = Path(adjuster.overrides_path).parent / "backups"
        backups = list(backup_dir.glob("user_overrides_*.json"))
        assert len(backups) >= 1

    def test_schema_version_in_saved_file(self, adjuster):
        adjuster.save_to_file()
        with open(adjuster.overrides_path) as f:
            data = json.load(f)
        assert data['_schema_version'] == OVERRIDES_SCHEMA_VERSION


# =============================================================================
# TrustMatrixAdjuster — Path/Command/HA Overrides
# =============================================================================

class TestAdjusterClassifications:
    def test_set_path_classification(self, adjuster):
        ok, msg = adjuster.set_path_classification(
            "C:\\Users\\test\\Recipes", "FS_DOC", "Not sensitive")
        assert ok is True
        assert "C:\\Users\\test\\Recipes" in adjuster.path_classifications

    def test_remove_path_classification(self, adjuster):
        adjuster.set_path_classification("C:\\test", "FS_DOC")
        assert adjuster.remove_path_classification("C:\\test") is True
        assert "C:\\test" not in adjuster.path_classifications

    def test_invalid_path_domain(self, adjuster):
        ok, _ = adjuster.set_path_classification("C:\\test", "INVALID")
        assert ok is False

    def test_add_command(self, adjuster):
        ok, msg = adjuster.add_command("ollama show", "CMD_INFO", "Safe")
        assert ok is True
        assert "ollama show" in adjuster.command_additions

    def test_remove_command(self, adjuster):
        adjuster.add_command("test cmd", "CMD_INFO")
        assert adjuster.remove_command("test cmd") is True
        assert "test cmd" not in adjuster.command_additions

    def test_invalid_command_domain(self, adjuster):
        ok, _ = adjuster.add_command("test", "INVALID_DOMAIN")
        assert ok is False

    def test_set_ha_entity_override(self, adjuster):
        ok, msg = adjuster.set_ha_entity_override(
            "switch.fan", "HA_CLIM", "Fan")
        assert ok is True
        assert "switch.fan" in adjuster.ha_entity_overrides

    def test_remove_ha_entity_override(self, adjuster):
        adjuster.set_ha_entity_override("switch.fan", "HA_CLIM")
        assert adjuster.remove_ha_entity_override("switch.fan") is True

    def test_invalid_ha_domain(self, adjuster):
        ok, _ = adjuster.set_ha_entity_override("x", "BAD_DOMAIN")
        assert ok is False


# =============================================================================
# TrustMatrixAdjuster — Session Defaults
# =============================================================================

class TestAdjusterSessionDefaults:
    def test_set_max_actions(self, adjuster):
        ok, _ = adjuster.set_session_defaults(max_actions=25)
        assert ok is True
        assert adjuster.session_defaults['max_actions'] == 25

    def test_set_duration(self, adjuster):
        ok, _ = adjuster.set_session_defaults(max_duration_minutes=30)
        assert ok is True
        assert adjuster.session_defaults['max_duration_minutes'] == 30

    def test_set_elevated_level(self, adjuster):
        ok, _ = adjuster.set_session_defaults(default_elevated_level=12)
        assert ok is True

    def test_invalid_max_actions(self, adjuster):
        ok, _ = adjuster.set_session_defaults(max_actions=0)
        assert ok is False
        ok, _ = adjuster.set_session_defaults(max_actions=999)
        assert ok is False

    def test_invalid_duration(self, adjuster):
        ok, _ = adjuster.set_session_defaults(max_duration_minutes=0)
        assert ok is False
        ok, _ = adjuster.set_session_defaults(max_duration_minutes=100)
        assert ok is False

    def test_non_passive_elevated_level_rejected(self, adjuster):
        ok, _ = adjuster.set_session_defaults(default_elevated_level=9)
        assert ok is False

    def test_invalid_elevated_level(self, adjuster):
        ok, _ = adjuster.set_session_defaults(default_elevated_level=99)
        assert ok is False


# =============================================================================
# AdjustmentResult
# =============================================================================

class TestAdjustmentResult:
    def test_to_dict_serializable(self, adjuster):
        result = adjuster.propose_adjustment(
            ActionCategory.EXECUTE, TargetDomain.HA_LIGHT,
            ApprovalLevel.SILENT, reason="test")
        d = result.to_dict()
        assert isinstance(d, dict)
        json_str = json.dumps(d)  # Should not raise
        assert 'allowed' in d
        assert d['category'] == 'EXECUTE'
        assert d['domain'] == 'HA_LIGHT'

    def test_to_change_request_for_rejection(self, adjuster):
        result = adjuster.propose_adjustment(
            ActionCategory.EXECUTE, TargetDomain.HA_LOCK,
            ApprovalLevel.CONFIRM_STANDARD, reason="No NFC")
        cr = result.to_change_request(user="admin")
        assert cr['user'] == 'admin'
        assert cr['boundary_violated'] == 'PHYSICAL_TO_SOFTWARE'
        assert cr['boundary_type'] == 'code_change_required'
        assert cr['status'] == 'logged'

    def test_to_change_request_for_deny(self, adjuster):
        result = adjuster.propose_adjustment(
            ActionCategory.ADMIN, TargetDomain.FS_SYSTEM,
            ApprovalLevel.CONFIRM_STANDARD)
        cr = result.to_change_request(user="test")
        assert cr['boundary_type'] == 'manual_code_edit_only'

    def test_to_dict_with_none_values(self):
        """Result with None values should still serialize."""
        result = AdjustmentResult(
            category=None, domain=None,
            current_level=None, default_level=None,
            requested_level=None,
            allowed=False, explanation="bad input",
            boundary_violated=None, alternatives=[], reason="")
        d = result.to_dict()
        assert d['category'] is None
        json.dumps(d)  # Should not raise


# =============================================================================
# ChangeRequestLog
# =============================================================================

class TestChangeRequestLog:
    def test_add_request(self, change_log):
        req_id = change_log.add_request(
            user="admin",
            category="TRANSFER", domain="OFF_ESEND",
            current_level=5, current_gate="BIOMETRIC",
            requested_level=9, requested_gate="SOFTWARE",
            boundary_violated="BIOMETRIC_TO_SOFTWARE",
            boundary_type="code_change_required",
            user_context="Fingerprint slow")
        assert req_id.startswith("req_")
        assert change_log.pending_count == 1
        assert change_log.total_count == 1

    def test_get_pending(self, change_log):
        change_log.add_request(
            user="admin", category="TRANSFER", domain="OFF_ESEND",
            current_level=5, current_gate="BIOMETRIC",
            requested_level=9, requested_gate="SOFTWARE",
            boundary_violated="BIOMETRIC_TO_SOFTWARE",
            boundary_type="code_change_required")
        pending = change_log.get_pending()
        assert len(pending) == 1
        assert pending[0]['category'] == 'TRANSFER'

    def test_get_request_by_id(self, change_log):
        req_id = change_log.add_request(
            user="admin", category="TRANSFER", domain="OFF_ESEND",
            current_level=5, current_gate="BIOMETRIC",
            requested_level=9, requested_gate="SOFTWARE",
            boundary_violated="BIOMETRIC_TO_SOFTWARE",
            boundary_type="code_change_required")
        found = change_log.get_request(req_id)
        assert found is not None
        assert found['request_id'] == req_id

    def test_get_request_by_prefix(self, change_log):
        req_id = change_log.add_request(
            user="admin", category="EXECUTE", domain="HA_LOCK",
            current_level=3, current_gate="PHYSICAL",
            requested_level=9, requested_gate="SOFTWARE",
            boundary_violated="PHYSICAL_TO_SOFTWARE",
            boundary_type="code_change_required")
        prefix = req_id[:12]
        found = change_log.get_request(prefix)
        assert found is not None

    def test_mark_applied(self, change_log):
        req_id = change_log.add_request(
            user="admin", category="TRANSFER", domain="OFF_ESEND",
            current_level=5, current_gate="BIOMETRIC",
            requested_level=9, requested_gate="SOFTWARE",
            boundary_violated="BIOMETRIC_TO_SOFTWARE",
            boundary_type="code_change_required")
        ok, msg = change_log.mark_applied(
            req_id, applied_by="admin",
            code_diff="tier_matrix.py: TRANSFER:OFF_ESEND: 5 → 9",
            nfc_verification=True)
        assert ok is True
        assert change_log.pending_count == 0
        applied = change_log.get_applied()
        assert len(applied) == 1
        assert applied[0]['nfc_verification'] is True

    def test_deny_gate_cannot_be_applied(self, change_log):
        req_id = change_log.add_request(
            user="admin", category="OBSERVE", domain="FS_SYSTEM",
            current_level=0, current_gate="DENY",
            requested_level=9, requested_gate="SOFTWARE",
            boundary_violated="DENY_GATE",
            boundary_type="manual_code_edit_only")
        ok, msg = change_log.mark_applied(req_id, applied_by="admin")
        assert ok is False
        assert "DENY" in msg
        assert change_log.pending_count == 1

    def test_mark_rejected(self, change_log):
        req_id = change_log.add_request(
            user="admin", category="TRANSFER", domain="OFF_ESEND",
            current_level=5, current_gate="BIOMETRIC",
            requested_level=9, requested_gate="SOFTWARE",
            boundary_violated="BIOMETRIC_TO_SOFTWARE",
            boundary_type="code_change_required")
        ok, msg = change_log.mark_rejected(
            req_id, rejected_by="admin", reason="Not needed")
        assert ok is True
        assert change_log.pending_count == 0

    def test_cannot_apply_already_applied(self, change_log):
        req_id = change_log.add_request(
            user="admin", category="TRANSFER", domain="OFF_ESEND",
            current_level=5, current_gate="BIOMETRIC",
            requested_level=9, requested_gate="SOFTWARE",
            boundary_violated="BIOMETRIC_TO_SOFTWARE",
            boundary_type="code_change_required")
        change_log.mark_applied(req_id, applied_by="admin")
        ok, msg = change_log.mark_applied(req_id, applied_by="admin")
        assert ok is False

    def test_save_and_load_roundtrip(self, change_log):
        change_log.add_request(
            user="admin", category="TRANSFER", domain="OFF_ESEND",
            current_level=5, current_gate="BIOMETRIC",
            requested_level=9, requested_gate="SOFTWARE",
            boundary_violated="BIOMETRIC_TO_SOFTWARE",
            boundary_type="code_change_required",
            user_context="Fingerprint slow")
        change_log.save()

        # Load in fresh instance
        fresh = ChangeRequestLog(path=change_log.path)
        assert fresh.pending_count == 1
        pending = fresh.get_pending()
        assert pending[0]['user_context'] == 'Fingerprint slow'

    def test_add_from_adjustment_result_rejected(self, change_log, adjuster):
        result = adjuster.propose_adjustment(
            ActionCategory.EXECUTE, TargetDomain.HA_LOCK,
            ApprovalLevel.CONFIRM_STANDARD, reason="No NFC")
        req_id = change_log.add_from_adjustment_result(result, user="admin")
        assert req_id is not None
        assert change_log.pending_count == 1

    def test_add_from_adjustment_result_allowed_returns_none(self, change_log, adjuster):
        result = adjuster.propose_adjustment(
            ActionCategory.EXECUTE, TargetDomain.HA_LIGHT,
            ApprovalLevel.SILENT)
        req_id = change_log.add_from_adjustment_result(result)
        assert req_id is None

    def test_get_all(self, change_log):
        change_log.add_request(
            user="a", category="X", domain="Y",
            current_level=5, current_gate="BIOMETRIC",
            requested_level=9, requested_gate="SOFTWARE",
            boundary_violated="BIOMETRIC_TO_SOFTWARE",
            boundary_type="code_change_required")
        change_log.add_request(
            user="b", category="Z", domain="W",
            current_level=0, current_gate="DENY",
            requested_level=9, requested_gate="SOFTWARE",
            boundary_violated="DENY_GATE",
            boundary_type="manual_code_edit_only")
        all_reqs = change_log.get_all()
        assert len(all_reqs) == 2

    def test_request_not_found(self, change_log):
        ok, msg = change_log.mark_applied("nonexistent", applied_by="x")
        assert ok is False

    def test_schema_version_in_saved_file(self, change_log):
        change_log.add_request(
            user="admin", category="X", domain="Y",
            current_level=5, current_gate="BIOMETRIC",
            requested_level=9, requested_gate="SOFTWARE",
            boundary_violated="BIOMETRIC_TO_SOFTWARE",
            boundary_type="code_change_required")
        change_log.save()
        with open(change_log.path) as f:
            data = json.load(f)
        assert data['_schema_version'] == SCHEMA_VERSION


# =============================================================================
# Handler Integration Tests
# =============================================================================

class TestHandlerIntegration:
    """Test that Phase 3 commands work through the handler's command parsing."""

    def _make_mock_handler(self, adjuster, change_log):
        """Create a mock handler with Phase 3 wired in."""
        from aiohai.proxy.handler import HandlerContext

        mock_logger = MagicMock()
        mock_logger.session_id = "test-session"
        mock_logger.stats = {}

        ctx = HandlerContext(
            config=MagicMock(),
            logger=mock_logger,
            alerts=MagicMock(),
            approval_mgr=MagicMock(),
            matrix_adjuster=adjuster,
            change_request_log=change_log,
        )
        return ctx

    def test_setlevel_command_allowed(self, adjuster, change_log):
        ctx = self._make_mock_handler(adjuster, change_log)

        # Import after HandlerContext is available
        from aiohai.proxy.handler import UnifiedProxyHandler
        handler = MagicMock(spec=UnifiedProxyHandler)
        handler.ctx = ctx

        # Call the method directly
        result = UnifiedProxyHandler._propose_trust_adjustment(
            handler, "EXECUTE", "HA_LIGHT", 14, "Silent lights")
        assert "✅" in result
        assert "SILENT" in result

    def test_setlevel_command_denied(self, adjuster, change_log):
        ctx = self._make_mock_handler(adjuster, change_log)

        from aiohai.proxy.handler import UnifiedProxyHandler
        handler = MagicMock(spec=UnifiedProxyHandler)
        handler.ctx = ctx

        result = UnifiedProxyHandler._propose_trust_adjustment(
            handler, "EXECUTE", "HA_LOCK", 9, "No NFC")
        assert "❌" in result
        assert "Alternatives" in result or "alternative" in result.lower() or "PHYSICAL" in result

    def test_overrides_command_empty(self, adjuster, change_log):
        ctx = self._make_mock_handler(adjuster, change_log)

        from aiohai.proxy.handler import UnifiedProxyHandler
        handler = MagicMock(spec=UnifiedProxyHandler)
        handler.ctx = ctx

        result = UnifiedProxyHandler._show_overrides(handler)
        assert "No trust level overrides" in result

    def test_overrides_command_with_data(self, adjuster, change_log):
        r = adjuster.propose_adjustment(
            ActionCategory.EXECUTE, TargetDomain.HA_LIGHT,
            ApprovalLevel.SILENT)
        adjuster.apply_adjustment(r)

        ctx = self._make_mock_handler(adjuster, change_log)

        from aiohai.proxy.handler import UnifiedProxyHandler
        handler = MagicMock(spec=UnifiedProxyHandler)
        handler.ctx = ctx

        result = UnifiedProxyHandler._show_overrides(handler)
        assert "EXECUTE:HA_LIGHT" in result

    def test_changerequests_command_empty(self, adjuster, change_log):
        ctx = self._make_mock_handler(adjuster, change_log)

        from aiohai.proxy.handler import UnifiedProxyHandler
        handler = MagicMock(spec=UnifiedProxyHandler)
        handler.ctx = ctx

        result = UnifiedProxyHandler._show_change_requests(handler)
        assert "No pending" in result

    def test_changerequests_command_with_data(self, adjuster, change_log):
        change_log.add_request(
            user="admin", category="TRANSFER", domain="OFF_ESEND",
            current_level=5, current_gate="BIOMETRIC",
            requested_level=9, requested_gate="SOFTWARE",
            boundary_violated="BIOMETRIC_TO_SOFTWARE",
            boundary_type="code_change_required",
            user_context="Fingerprint slow")

        ctx = self._make_mock_handler(adjuster, change_log)

        from aiohai.proxy.handler import UnifiedProxyHandler
        handler = MagicMock(spec=UnifiedProxyHandler)
        handler.ctx = ctx

        result = UnifiedProxyHandler._show_change_requests(handler)
        assert "TRANSFER" in result
        assert "OFF_ESEND" in result

    def test_handler_context_has_phase3_slots(self):
        from aiohai.proxy.handler import HandlerContext
        ctx = HandlerContext()
        assert hasattr(ctx, 'matrix_adjuster')
        assert hasattr(ctx, 'change_request_log')


# =============================================================================
# Gate Boundary — Comprehensive Matrix Tests
# =============================================================================

class TestGateBoundaryComprehensive:
    """Test every gate boundary direction to ensure immutability."""

    PHYSICAL_ACTIONS = [
        (ActionCategory.EXECUTE, TargetDomain.HA_LOCK),
        (ActionCategory.EXECUTE, TargetDomain.HA_ALARM),
    ]

    BIOMETRIC_ACTIONS = [
        (ActionCategory.MODIFY, TargetDomain.FS_DOC_SENS),
        (ActionCategory.EXECUTE, TargetDomain.CMD_SVC),
        (ActionCategory.CREATE, TargetDomain.HA_AUTO),
    ]

    SOFTWARE_ACTIONS = [
        (ActionCategory.MODIFY, TargetDomain.FS_DOC),
        (ActionCategory.EXECUTE, TargetDomain.CMD_FOPS),
        (ActionCategory.EXECUTE, TargetDomain.HA_CLIM),
    ]

    PASSIVE_ACTIONS = [
        (ActionCategory.EXECUTE, TargetDomain.HA_LIGHT),
        (ActionCategory.OBSERVE, TargetDomain.HA_SENS),
        (ActionCategory.OBSERVE, TargetDomain.FS_TEMP),
    ]

    DENY_ACTIONS = [
        (ActionCategory.ADMIN, TargetDomain.FS_SYSTEM),
        (ActionCategory.OBSERVE, TargetDomain.FS_CRED),
        (ActionCategory.EXECUTE, TargetDomain.CMD_ADMIN),
    ]

    def test_all_deny_immutable(self, adjuster):
        for cat, dom in self.DENY_ACTIONS:
            for level in ApprovalLevel:
                if level.gate != SecurityGate.DENY:
                    result = adjuster.propose_adjustment(cat, dom, level)
                    assert result.allowed is False, (
                        f"DENY action {cat}:{dom} should reject level {level}")
                    assert result.boundary_violated == 'DENY_GATE'

    def test_physical_cannot_demote(self, adjuster):
        for cat, dom in self.PHYSICAL_ACTIONS:
            # Cannot demote to BIOMETRIC
            for level in (ApprovalLevel.BIOMETRIC_DETAILED,
                          ApprovalLevel.BIOMETRIC_STANDARD,
                          ApprovalLevel.BIOMETRIC_QUICK):
                result = adjuster.propose_adjustment(cat, dom, level)
                assert result.allowed is False, (
                    f"PHYSICAL {cat}:{dom} should reject BIOMETRIC {level}")

            # Cannot demote to SOFTWARE
            for level in (ApprovalLevel.CONFIRM_DETAILED,
                          ApprovalLevel.CONFIRM_STANDARD,
                          ApprovalLevel.CONFIRM_QUICK):
                result = adjuster.propose_adjustment(cat, dom, level)
                assert result.allowed is False

            # Cannot demote to PASSIVE
            for level in (ApprovalLevel.NOTIFY_AND_PROCEED,
                          ApprovalLevel.SILENT):
                result = adjuster.propose_adjustment(cat, dom, level)
                assert result.allowed is False

    def test_biometric_cannot_demote(self, adjuster):
        for cat, dom in self.BIOMETRIC_ACTIONS:
            # Cannot demote to SOFTWARE
            for level in (ApprovalLevel.CONFIRM_DETAILED,
                          ApprovalLevel.CONFIRM_STANDARD,
                          ApprovalLevel.CONFIRM_QUICK):
                result = adjuster.propose_adjustment(cat, dom, level)
                assert result.allowed is False, (
                    f"BIOMETRIC {cat}:{dom} should reject SOFTWARE {level}")

            # Cannot demote to PASSIVE
            for level in (ApprovalLevel.NOTIFY_AND_PROCEED,
                          ApprovalLevel.SILENT):
                result = adjuster.propose_adjustment(cat, dom, level)
                assert result.allowed is False

    def test_software_within_gate_ok(self, adjuster):
        for cat, dom in self.SOFTWARE_ACTIONS:
            for level in (ApprovalLevel.CONFIRM_DETAILED,
                          ApprovalLevel.CONFIRM_STANDARD,
                          ApprovalLevel.CONFIRM_QUICK):
                result = adjuster.propose_adjustment(cat, dom, level)
                assert result.allowed is True, (
                    f"SOFTWARE {cat}:{dom} should accept {level}")

    def test_passive_within_gate_ok(self, adjuster):
        for cat, dom in self.PASSIVE_ACTIONS:
            for level in (ApprovalLevel.NOTIFY_AND_PROCEED,
                          ApprovalLevel.LOG_ONLY,
                          ApprovalLevel.TRANSPARENT,
                          ApprovalLevel.SILENT):
                result = adjuster.propose_adjustment(cat, dom, level)
                assert result.allowed is True, (
                    f"PASSIVE {cat}:{dom} should accept {level}")

    def test_physical_within_gate_ok(self, adjuster):
        for cat, dom in self.PHYSICAL_ACTIONS:
            for level in (ApprovalLevel.PHYSICAL_DETAILED,
                          ApprovalLevel.PHYSICAL_STANDARD,
                          ApprovalLevel.PHYSICAL_QUICK):
                result = adjuster.propose_adjustment(cat, dom, level)
                assert result.allowed is True, (
                    f"PHYSICAL {cat}:{dom} should accept {level}")

    def test_biometric_within_gate_ok(self, adjuster):
        for cat, dom in self.BIOMETRIC_ACTIONS:
            for level in (ApprovalLevel.BIOMETRIC_DETAILED,
                          ApprovalLevel.BIOMETRIC_STANDARD,
                          ApprovalLevel.BIOMETRIC_QUICK):
                result = adjuster.propose_adjustment(cat, dom, level)
                assert result.allowed is True, (
                    f"BIOMETRIC {cat}:{dom} should accept {level}")

    def test_promotion_always_allowed(self, adjuster):
        """Promoting to a more restrictive gate always works."""
        # PASSIVE → SOFTWARE
        result = adjuster.propose_adjustment(
            ActionCategory.EXECUTE, TargetDomain.HA_LIGHT,
            ApprovalLevel.CONFIRM_STANDARD)
        assert result.allowed is True

        # SOFTWARE → BIOMETRIC
        result = adjuster.propose_adjustment(
            ActionCategory.MODIFY, TargetDomain.FS_DOC,
            ApprovalLevel.BIOMETRIC_STANDARD)
        assert result.allowed is True

        # SOFTWARE → PHYSICAL
        result = adjuster.propose_adjustment(
            ActionCategory.MODIFY, TargetDomain.FS_DOC,
            ApprovalLevel.PHYSICAL_STANDARD)
        assert result.allowed is True

        # BIOMETRIC → PHYSICAL
        result = adjuster.propose_adjustment(
            ActionCategory.MODIFY, TargetDomain.FS_DOC_SENS,
            ApprovalLevel.PHYSICAL_STANDARD)
        assert result.allowed is True


# =============================================================================
# Orchestrator Wiring Test
# =============================================================================

class TestOrchestratorWiring:
    def test_imports_work(self):
        """Verify orchestrator can import Phase 3 modules."""
        from aiohai.core.trust.matrix_adjuster import TrustMatrixAdjuster
        from aiohai.core.trust.change_request_log import ChangeRequestLog
        assert TrustMatrixAdjuster is not None
        assert ChangeRequestLog is not None

    def test_version_bumped(self):
        from aiohai.core.version import __version__
        assert __version__ == "5.4.0"


