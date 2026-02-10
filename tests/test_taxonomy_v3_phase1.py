#!/usr/bin/env python3
"""
Tests for Approval Gate Taxonomy v3 — Phase 1 Foundation

Tests the new type system (SecurityGate, ActionCategory, TargetDomain,
ApprovalLevel), the TargetClassifier, and the TierMatrix with gate
boundary enforcement.

Run: python -m pytest tests/test_taxonomy_v3_phase1.py -v
"""

import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from aiohai.core.types import (
    SecurityGate, ActionCategory, TargetDomain, ApprovalLevel,
    # Legacy types — must still work
    ActionType, ApprovalTier, SecurityLevel, ApprovalStatus, UserRole,
)
from aiohai.core.access.target_classifier import TargetClassifier
from aiohai.core.access.tier_matrix import TierMatrix, TIER_MATRIX


# =============================================================================
# SecurityGate Tests
# =============================================================================

class TestSecurityGate:
    """Tests for SecurityGate enum."""

    def test_gate_values(self):
        assert SecurityGate.DENY.value == 0
        assert SecurityGate.PHYSICAL.value == 1
        assert SecurityGate.BIOMETRIC.value == 2
        assert SecurityGate.SOFTWARE.value == 3
        assert SecurityGate.PASSIVE.value == 4

    def test_gate_ordering(self):
        """Gates must be strictly ordered: DENY < PHYSICAL < BIOMETRIC < SOFTWARE < PASSIVE."""
        assert SecurityGate.DENY < SecurityGate.PHYSICAL
        assert SecurityGate.PHYSICAL < SecurityGate.BIOMETRIC
        assert SecurityGate.BIOMETRIC < SecurityGate.SOFTWARE
        assert SecurityGate.SOFTWARE < SecurityGate.PASSIVE
        assert not (SecurityGate.PASSIVE < SecurityGate.DENY)
        assert SecurityGate.DENY <= SecurityGate.DENY
        assert SecurityGate.PASSIVE >= SecurityGate.DENY

    def test_from_level_deny(self):
        assert SecurityGate.from_level(0) == SecurityGate.DENY
        assert SecurityGate.from_level(1) == SecurityGate.DENY

    def test_from_level_physical(self):
        assert SecurityGate.from_level(2) == SecurityGate.PHYSICAL
        assert SecurityGate.from_level(3) == SecurityGate.PHYSICAL
        assert SecurityGate.from_level(4) == SecurityGate.PHYSICAL

    def test_from_level_biometric(self):
        assert SecurityGate.from_level(5) == SecurityGate.BIOMETRIC
        assert SecurityGate.from_level(6) == SecurityGate.BIOMETRIC
        assert SecurityGate.from_level(7) == SecurityGate.BIOMETRIC

    def test_from_level_software(self):
        assert SecurityGate.from_level(8) == SecurityGate.SOFTWARE
        assert SecurityGate.from_level(9) == SecurityGate.SOFTWARE
        assert SecurityGate.from_level(10) == SecurityGate.SOFTWARE

    def test_from_level_passive(self):
        assert SecurityGate.from_level(11) == SecurityGate.PASSIVE
        assert SecurityGate.from_level(12) == SecurityGate.PASSIVE
        assert SecurityGate.from_level(13) == SecurityGate.PASSIVE
        assert SecurityGate.from_level(14) == SecurityGate.PASSIVE

    def test_is_hardware(self):
        assert SecurityGate.PHYSICAL.is_hardware
        assert SecurityGate.BIOMETRIC.is_hardware
        assert not SecurityGate.DENY.is_hardware
        assert not SecurityGate.SOFTWARE.is_hardware
        assert not SecurityGate.PASSIVE.is_hardware

    def test_five_gates_total(self):
        assert len(SecurityGate) == 5


# =============================================================================
# ActionCategory Tests
# =============================================================================

class TestActionCategory:
    """Tests for ActionCategory enum."""

    def test_ten_categories(self):
        assert len(ActionCategory) == 10

    def test_category_values_are_strings(self):
        for cat in ActionCategory:
            assert isinstance(cat.value, str)

    def test_legacy_mapping_all_old_types(self):
        """All legacy action type strings must map to a valid category."""
        legacy_types = [
            'READ', 'WRITE', 'DELETE', 'LIST', 'COMMAND', 'API_QUERY',
            'FILE_READ', 'FILE_WRITE', 'FILE_DELETE', 'DIRECTORY_LIST',
            'COMMAND_EXEC', 'LOCAL_API_QUERY', 'DOCUMENT_OP', 'NETWORK_REQUEST',
        ]
        for lt in legacy_types:
            cat = ActionCategory.from_legacy_action_type(lt)
            assert isinstance(cat, ActionCategory), f"Failed for {lt}"

    def test_legacy_mapping_read(self):
        assert ActionCategory.from_legacy_action_type('READ') == ActionCategory.OBSERVE
        assert ActionCategory.from_legacy_action_type('FILE_READ') == ActionCategory.OBSERVE

    def test_legacy_mapping_write(self):
        assert ActionCategory.from_legacy_action_type('WRITE') == ActionCategory.MODIFY

    def test_legacy_mapping_delete(self):
        assert ActionCategory.from_legacy_action_type('DELETE') == ActionCategory.DELETE

    def test_legacy_mapping_command(self):
        assert ActionCategory.from_legacy_action_type('COMMAND') == ActionCategory.EXECUTE

    def test_legacy_mapping_unknown_fails_closed(self):
        """Unknown action types default to EXECUTE (fail closed)."""
        assert ActionCategory.from_legacy_action_type('UNKNOWN') == ActionCategory.EXECUTE
        assert ActionCategory.from_legacy_action_type('') == ActionCategory.EXECUTE


# =============================================================================
# TargetDomain Tests
# =============================================================================

class TestTargetDomain:
    """Tests for TargetDomain enum."""

    def test_domain_count(self):
        """42 domains total (11 FS + 8 CMD + 16 HA + 6 OFF + 1 UNKNOWN)."""
        assert len(TargetDomain) == 42

    def test_domain_families(self):
        fs = [d for d in TargetDomain if d.name.startswith('FS_')]
        cmd = [d for d in TargetDomain if d.name.startswith('CMD_')]
        ha = [d for d in TargetDomain if d.name.startswith('HA_')]
        off = [d for d in TargetDomain if d.name.startswith('OFF_')]
        assert len(fs) == 11
        assert len(cmd) == 8
        assert len(ha) == 16
        assert len(off) == 6

    def test_unknown_domain_exists(self):
        assert TargetDomain.UNKNOWN is not None


# =============================================================================
# ApprovalLevel Tests
# =============================================================================

class TestApprovalLevel:
    """Tests for the 15-level ApprovalLevel enum."""

    def test_fifteen_levels(self):
        assert len(ApprovalLevel) == 15

    def test_level_values_sequential(self):
        values = [l.value for l in ApprovalLevel]
        assert values == list(range(15))

    def test_every_level_maps_to_exactly_one_gate(self):
        for level in ApprovalLevel:
            gate = level.gate
            assert isinstance(gate, SecurityGate)

    def test_deny_gate_levels(self):
        deny = [l for l in ApprovalLevel if l.gate == SecurityGate.DENY]
        assert len(deny) == 2
        assert ApprovalLevel.HARDBLOCK in deny
        assert ApprovalLevel.SOFTBLOCK in deny

    def test_physical_gate_levels(self):
        phys = [l for l in ApprovalLevel if l.gate == SecurityGate.PHYSICAL]
        assert len(phys) == 3

    def test_biometric_gate_levels(self):
        bio = [l for l in ApprovalLevel if l.gate == SecurityGate.BIOMETRIC]
        assert len(bio) == 3

    def test_software_gate_levels(self):
        sw = [l for l in ApprovalLevel if l.gate == SecurityGate.SOFTWARE]
        assert len(sw) == 3

    def test_passive_gate_levels(self):
        passive = [l for l in ApprovalLevel if l.gate == SecurityGate.PASSIVE]
        assert len(passive) == 4

    def test_is_blocked_only_deny_gate(self):
        for level in ApprovalLevel:
            if level.gate == SecurityGate.DENY:
                assert level.is_blocked
            else:
                assert not level.is_blocked

    def test_requires_confirmation_range(self):
        for level in ApprovalLevel:
            if 2 <= level.value <= 10:
                assert level.requires_confirmation
            else:
                assert not level.requires_confirmation

    def test_is_passive_range(self):
        for level in ApprovalLevel:
            if level.value >= 11:
                assert level.is_passive
            else:
                assert not level.is_passive

    def test_timeouts(self):
        assert ApprovalLevel.BIOMETRIC_DETAILED.timeout_seconds == 120
        assert ApprovalLevel.BIOMETRIC_STANDARD.timeout_seconds == 60
        assert ApprovalLevel.BIOMETRIC_QUICK.timeout_seconds == 30
        assert ApprovalLevel.CONFIRM_DETAILED.timeout_seconds == 60
        assert ApprovalLevel.CONFIRM_STANDARD.timeout_seconds == 30
        assert ApprovalLevel.CONFIRM_QUICK.timeout_seconds == 10
        # Physical gate has no timeouts
        assert ApprovalLevel.PHYSICAL_DETAILED.timeout_seconds is None
        assert ApprovalLevel.PHYSICAL_STANDARD.timeout_seconds is None
        # Passive gate has no timeouts
        assert ApprovalLevel.NOTIFY_AND_PROCEED.timeout_seconds is None

    def test_auto_action_on_timeout(self):
        assert ApprovalLevel.CONFIRM_DETAILED.auto_action_on_timeout == 'reject'
        assert ApprovalLevel.CONFIRM_STANDARD.auto_action_on_timeout == 'reject'
        assert ApprovalLevel.CONFIRM_QUICK.auto_action_on_timeout == 'approve'
        assert ApprovalLevel.PHYSICAL_STANDARD.auto_action_on_timeout is None


# =============================================================================
# TargetClassifier Tests
# =============================================================================

class TestTargetClassifier:
    """Tests for TargetClassifier domain classification."""

    # --- Filesystem ---
    def test_fs_temp(self):
        assert TargetClassifier.classify('C:\\temp\\scratch.txt', hint='file') == TargetDomain.FS_TEMP
        assert TargetClassifier.classify('/tmp/data.log', hint='file') == TargetDomain.FS_TEMP

    def test_fs_downloads(self):
        assert TargetClassifier.classify('C:\\Users\\admin\\Downloads\\setup.exe', hint='file') == TargetDomain.FS_DL

    def test_fs_documents(self):
        assert TargetClassifier.classify('C:\\Users\\admin\\Documents\\report.docx', hint='file') == TargetDomain.FS_DOC

    def test_fs_doc_sensitive(self):
        assert TargetClassifier.classify('C:\\Users\\admin\\Documents\\TaxReturn.pdf', hint='file') == TargetDomain.FS_DOC_SENS
        assert TargetClassifier.classify('C:\\QuickBooks\\data.qbw', hint='file') == TargetDomain.FS_DOC_SENS
        assert TargetClassifier.classify('C:\\Documents\\payroll_Q3.xlsx', hint='file') == TargetDomain.FS_DOC_SENS
        assert TargetClassifier.classify('C:\\HR_department\\review.doc', hint='file') == TargetDomain.FS_DOC_SENS

    def test_fs_desktop(self):
        assert TargetClassifier.classify('C:\\Users\\admin\\Desktop\\notes.txt', hint='file') == TargetDomain.FS_DESK

    def test_fs_media(self):
        assert TargetClassifier.classify('C:\\Users\\admin\\Pictures\\photo.jpg', hint='file') == TargetDomain.FS_MEDIA
        assert TargetClassifier.classify('C:\\Users\\admin\\Music\\song.mp3', hint='file') == TargetDomain.FS_MEDIA
        assert TargetClassifier.classify('C:\\Users\\admin\\Videos\\clip.mp4', hint='file') == TargetDomain.FS_MEDIA

    def test_fs_appconf(self):
        assert TargetClassifier.classify('C:\\Users\\admin\\AppData\\Roaming\\app\\config.ini', hint='file') == TargetDomain.FS_APPCONF

    def test_fs_aiohai(self):
        assert TargetClassifier.classify('C:\\AIOHAI\\config\\config.json', hint='file') == TargetDomain.FS_AIOHAI

    def test_fs_system(self):
        assert TargetClassifier.classify('C:\\Windows\\System32\\cmd.exe', hint='file') == TargetDomain.FS_SYSTEM

    def test_fs_cred(self):
        assert TargetClassifier.classify('C:\\Users\\admin\\.ssh\\id_rsa', hint='file') == TargetDomain.FS_CRED
        assert TargetClassifier.classify('C:\\Users\\admin\\.aws\\credentials', hint='file') == TargetDomain.FS_CRED
        assert TargetClassifier.classify('C:\\vault\\wallet.dat', hint='file') == TargetDomain.FS_CRED
        assert TargetClassifier.classify('/home/user/.env', hint='file') == TargetDomain.FS_CRED

    def test_fs_net(self):
        assert TargetClassifier.classify('/etc/hosts', hint='file') == TargetDomain.FS_NET

    # --- Commands ---
    def test_cmd_info(self):
        assert TargetClassifier.classify('systeminfo', hint='command') == TargetDomain.CMD_INFO
        assert TargetClassifier.classify('ipconfig /all', hint='command') == TargetDomain.CMD_INFO
        assert TargetClassifier.classify('whoami', hint='command') == TargetDomain.CMD_INFO
        assert TargetClassifier.classify('ollama list', hint='command') == TargetDomain.CMD_INFO

    def test_cmd_fops(self):
        assert TargetClassifier.classify('copy file1.txt file2.txt', hint='command') == TargetDomain.CMD_FOPS
        assert TargetClassifier.classify('robocopy src dest', hint='command') == TargetDomain.CMD_FOPS

    def test_cmd_svc(self):
        assert TargetClassifier.classify('sc start MyService', hint='command') == TargetDomain.CMD_SVC
        assert TargetClassifier.classify('net start Spooler', hint='command') == TargetDomain.CMD_SVC

    def test_cmd_inst(self):
        assert TargetClassifier.classify('pip install requests', hint='command') == TargetDomain.CMD_INST
        assert TargetClassifier.classify('winget install git', hint='command') == TargetDomain.CMD_INST

    def test_cmd_script(self):
        assert TargetClassifier.classify('python script.py', hint='command') == TargetDomain.CMD_SCRIPT
        assert TargetClassifier.classify('node app.js', hint='command') == TargetDomain.CMD_SCRIPT

    def test_cmd_admin(self):
        assert TargetClassifier.classify('reg add HKLM\\Software', hint='command') == TargetDomain.CMD_ADMIN
        assert TargetClassifier.classify('bcdedit /set', hint='command') == TargetDomain.CMD_ADMIN

    def test_cmd_net(self):
        assert TargetClassifier.classify('netsh firewall set', hint='command') == TargetDomain.CMD_NET

    def test_cmd_disk(self):
        assert TargetClassifier.classify('diskpart', hint='command') == TargetDomain.CMD_DISK
        assert TargetClassifier.classify('format C:', hint='command') == TargetDomain.CMD_DISK

    # --- Home Assistant ---
    def test_ha_light(self):
        assert TargetClassifier.classify('light.living_room', hint='ha') == TargetDomain.HA_LIGHT

    def test_ha_lock(self):
        assert TargetClassifier.classify('lock.front_door', hint='ha') == TargetDomain.HA_LOCK

    def test_ha_alarm(self):
        assert TargetClassifier.classify('alarm_control_panel.house', hint='ha') == TargetDomain.HA_ALARM

    def test_ha_camera(self):
        assert TargetClassifier.classify('camera.front_porch', hint='ha') == TargetDomain.HA_CAM

    def test_ha_automation(self):
        assert TargetClassifier.classify('automation.night_lights', hint='ha') == TargetDomain.HA_AUTO

    def test_ha_garage(self):
        assert TargetClassifier.classify('cover.garage_door', hint='ha') == TargetDomain.HA_GARAGE

    def test_ha_cover_not_garage(self):
        assert TargetClassifier.classify('cover.living_room_blinds', hint='ha') == TargetDomain.HA_COVER

    def test_ha_sensor(self):
        assert TargetClassifier.classify('sensor.temperature', hint='ha') == TargetDomain.HA_SENS
        assert TargetClassifier.classify('binary_sensor.motion', hint='ha') == TargetDomain.HA_SENS

    def test_ha_helper(self):
        assert TargetClassifier.classify('input_boolean.vacation', hint='ha') == TargetDomain.HA_HELPER
        assert TargetClassifier.classify('counter.visitors', hint='ha') == TargetDomain.HA_HELPER

    # --- Office ---
    def test_off_doc(self):
        assert TargetClassifier.classify('report.docx', hint='office') == TargetDomain.OFF_DOC

    def test_off_macro(self):
        assert TargetClassifier.classify('budget.xlsm', hint='office') == TargetDomain.OFF_MACRO

    def test_off_email_send(self):
        assert TargetClassifier.classify(
            'https://graph.microsoft.com/v1.0/me/sendMail', hint='api'
        ) == TargetDomain.OFF_ESEND

    def test_off_email_read(self):
        assert TargetClassifier.classify(
            'https://graph.microsoft.com/v1.0/me/messages', hint='api'
        ) == TargetDomain.OFF_EREAD

    # --- Fallback ---
    def test_unknown_target(self):
        assert TargetClassifier.classify('', hint='file') == TargetDomain.UNKNOWN
        assert TargetClassifier.classify('something_random') == TargetDomain.UNKNOWN

    # --- Legacy convenience ---
    def test_classify_for_legacy(self):
        assert TargetClassifier.classify_for_legacy(
            'READ', 'C:\\Users\\admin\\Documents\\report.txt'
        ) == TargetDomain.FS_DOC
        assert TargetClassifier.classify_for_legacy(
            'COMMAND', 'whoami'
        ) == TargetDomain.CMD_INFO
        assert TargetClassifier.classify_for_legacy(
            'DELETE', 'C:\\Users\\admin\\.ssh\\id_rsa'
        ) == TargetDomain.FS_CRED


# =============================================================================
# TierMatrix Tests
# =============================================================================

class TestTierMatrix:
    """Tests for TierMatrix lookup and gate boundary enforcement."""

    def setup_method(self):
        """Fresh matrix for each test."""
        self.matrix = TierMatrix()

    # --- Lookup ---
    def test_lookup_known_entry(self):
        assert self.matrix.lookup(
            ActionCategory.OBSERVE, TargetDomain.FS_TEMP
        ) == ApprovalLevel.SILENT

    def test_lookup_unknown_defaults_to_confirm_standard(self):
        assert self.matrix.lookup(
            ActionCategory.INSTALL, TargetDomain.FS_TEMP
        ) == ApprovalLevel.CONFIRM_STANDARD

    def test_lookup_deny_entries(self):
        assert self.matrix.lookup(
            ActionCategory.OBSERVE, TargetDomain.FS_SYSTEM
        ) == ApprovalLevel.HARDBLOCK
        assert self.matrix.lookup(
            ActionCategory.ADMIN, TargetDomain.FS_DOC
        ) == ApprovalLevel.HARDBLOCK

    def test_lookup_physical_entries(self):
        assert self.matrix.lookup(
            ActionCategory.EXECUTE, TargetDomain.HA_LOCK
        ) == ApprovalLevel.PHYSICAL_STANDARD
        assert self.matrix.lookup(
            ActionCategory.EXECUTE, TargetDomain.HA_ALARM
        ) == ApprovalLevel.PHYSICAL_DETAILED

    def test_lookup_biometric_entries(self):
        assert self.matrix.lookup(
            ActionCategory.MODIFY, TargetDomain.FS_DOC_SENS
        ) == ApprovalLevel.BIOMETRIC_STANDARD
        assert self.matrix.lookup(
            ActionCategory.DELETE, TargetDomain.FS_DOC_SENS
        ) == ApprovalLevel.BIOMETRIC_DETAILED

    def test_lookup_passive_entries(self):
        assert self.matrix.lookup(
            ActionCategory.EXECUTE, TargetDomain.HA_LIGHT
        ) == ApprovalLevel.NOTIFY_AND_PROCEED
        assert self.matrix.lookup(
            ActionCategory.OBSERVE, TargetDomain.FS_TEMP
        ) == ApprovalLevel.SILENT

    # --- Gate boundary: DENY gate immutability ---
    def test_deny_gate_cannot_be_overridden(self):
        ok, _ = self.matrix.set_override(
            ActionCategory.OBSERVE, TargetDomain.FS_SYSTEM,
            ApprovalLevel.CONFIRM_STANDARD
        )
        assert not ok

    def test_deny_gate_cannot_be_promoted(self):
        """Even promotion TO DENY doesn't make sense for a DENY item."""
        ok, _ = self.matrix.set_override(
            ActionCategory.ADMIN, TargetDomain.FS_DOC,
            ApprovalLevel.PHYSICAL_DETAILED
        )
        assert not ok

    # --- Gate boundary: no demotion ---
    def test_physical_to_biometric_rejected(self):
        ok, msg = self.matrix.set_override(
            ActionCategory.EXECUTE, TargetDomain.HA_LOCK,
            ApprovalLevel.BIOMETRIC_STANDARD
        )
        assert not ok
        assert 'demotion' in msg.lower() or 'demote' in msg.lower()

    def test_physical_to_software_rejected(self):
        ok, _ = self.matrix.set_override(
            ActionCategory.EXECUTE, TargetDomain.HA_ALARM,
            ApprovalLevel.CONFIRM_STANDARD
        )
        assert not ok

    def test_physical_to_passive_rejected(self):
        ok, _ = self.matrix.set_override(
            ActionCategory.EXECUTE, TargetDomain.HA_LOCK,
            ApprovalLevel.NOTIFY_AND_PROCEED
        )
        assert not ok

    def test_biometric_to_software_rejected(self):
        ok, _ = self.matrix.set_override(
            ActionCategory.MODIFY, TargetDomain.FS_DOC_SENS,
            ApprovalLevel.CONFIRM_STANDARD
        )
        assert not ok

    def test_biometric_to_passive_rejected(self):
        ok, _ = self.matrix.set_override(
            ActionCategory.CREATE, TargetDomain.OFF_ESEND,
            ApprovalLevel.NOTIFY_AND_PROCEED
        )
        assert not ok

    # --- Within-gate adjustments allowed ---
    def test_within_biometric_gate_allowed(self):
        ok, _ = self.matrix.set_override(
            ActionCategory.MODIFY, TargetDomain.FS_DOC_SENS,
            ApprovalLevel.BIOMETRIC_QUICK
        )
        assert ok
        assert self.matrix.lookup(
            ActionCategory.MODIFY, TargetDomain.FS_DOC_SENS
        ) == ApprovalLevel.BIOMETRIC_QUICK

    def test_within_software_gate_allowed(self):
        ok, _ = self.matrix.set_override(
            ActionCategory.MODIFY, TargetDomain.FS_DOC,
            ApprovalLevel.CONFIRM_DETAILED
        )
        assert ok

    def test_within_passive_gate_allowed(self):
        ok, _ = self.matrix.set_override(
            ActionCategory.EXECUTE, TargetDomain.HA_LIGHT,
            ApprovalLevel.SILENT
        )
        assert ok

    # --- Promotion (more restrictive) allowed ---
    def test_software_to_biometric_promotion(self):
        ok, _ = self.matrix.set_override(
            ActionCategory.OBSERVE, TargetDomain.FS_DOC,
            ApprovalLevel.BIOMETRIC_STANDARD
        )
        assert ok

    def test_passive_to_software_promotion(self):
        ok, _ = self.matrix.set_override(
            ActionCategory.EXECUTE, TargetDomain.HA_LIGHT,
            ApprovalLevel.CONFIRM_STANDARD
        )
        assert ok

    def test_software_to_physical_promotion(self):
        ok, _ = self.matrix.set_override(
            ActionCategory.MODIFY, TargetDomain.FS_DOC,
            ApprovalLevel.PHYSICAL_STANDARD
        )
        assert ok

    # --- Override lifecycle ---
    def test_override_effective(self):
        self.matrix.set_override(
            ActionCategory.OBSERVE, TargetDomain.FS_DOC,
            ApprovalLevel.CONFIRM_DETAILED
        )
        assert self.matrix.lookup(
            ActionCategory.OBSERVE, TargetDomain.FS_DOC
        ) == ApprovalLevel.CONFIRM_DETAILED

    def test_remove_override_reverts(self):
        self.matrix.set_override(
            ActionCategory.OBSERVE, TargetDomain.FS_DOC,
            ApprovalLevel.CONFIRM_DETAILED
        )
        self.matrix.remove_override(ActionCategory.OBSERVE, TargetDomain.FS_DOC)
        assert self.matrix.lookup(
            ActionCategory.OBSERVE, TargetDomain.FS_DOC
        ) == ApprovalLevel.LOG_ONLY

    def test_get_default_ignores_overrides(self):
        self.matrix.set_override(
            ActionCategory.OBSERVE, TargetDomain.FS_DOC,
            ApprovalLevel.CONFIRM_DETAILED
        )
        default = self.matrix.get_default(ActionCategory.OBSERVE, TargetDomain.FS_DOC)
        assert default == ApprovalLevel.LOG_ONLY

    # --- Validate adjustment ---
    def test_validate_deny_gate_blocked(self):
        ok, _, boundary = self.matrix.validate_adjustment(
            ActionCategory.OBSERVE, TargetDomain.FS_SYSTEM,
            ApprovalLevel.CONFIRM_STANDARD
        )
        assert not ok
        assert boundary == 'DENY_GATE'

    def test_validate_demotion_blocked(self):
        ok, _, boundary = self.matrix.validate_adjustment(
            ActionCategory.EXECUTE, TargetDomain.HA_LOCK,
            ApprovalLevel.CONFIRM_STANDARD
        )
        assert not ok
        assert boundary == 'PHYSICAL_TO_SOFTWARE'

    def test_validate_within_gate_allowed(self):
        ok, _, boundary = self.matrix.validate_adjustment(
            ActionCategory.MODIFY, TargetDomain.FS_DOC,
            ApprovalLevel.CONFIRM_DETAILED
        )
        assert ok
        assert boundary is None

    # --- Static methods ---
    def test_is_deny_gate(self):
        assert TierMatrix.is_deny_gate(ActionCategory.ADMIN, TargetDomain.FS_DOC)
        assert TierMatrix.is_deny_gate(ActionCategory.OBSERVE, TargetDomain.FS_SYSTEM)
        assert not TierMatrix.is_deny_gate(ActionCategory.OBSERVE, TargetDomain.FS_DOC)

    def test_get_gate_for_pair(self):
        assert TierMatrix.get_gate_for_pair(
            ActionCategory.EXECUTE, TargetDomain.HA_LOCK
        ) == SecurityGate.PHYSICAL
        assert TierMatrix.get_gate_for_pair(
            ActionCategory.EXECUTE, TargetDomain.HA_LIGHT
        ) == SecurityGate.PASSIVE

    # --- Load overrides ---
    def test_load_overrides_valid(self):
        overrides = {
            'MODIFY:FS_DOC': {'level': 8},  # within SOFTWARE gate
        }
        errors = self.matrix.load_overrides(overrides)
        assert len(errors) == 0
        assert self.matrix.lookup(
            ActionCategory.MODIFY, TargetDomain.FS_DOC
        ) == ApprovalLevel.CONFIRM_DETAILED

    def test_load_overrides_rejects_demotion(self):
        overrides = {
            'MODIFY:FS_DOC_SENS': {'level': 9},  # BIOMETRIC → SOFTWARE
        }
        errors = self.matrix.load_overrides(overrides)
        assert len(errors) == 1

    def test_load_overrides_rejects_invalid_key(self):
        overrides = {
            'BOGUS': {'level': 9},
        }
        errors = self.matrix.load_overrides(overrides)
        assert len(errors) == 1


# =============================================================================
# Legacy Compatibility Tests
# =============================================================================

class TestLegacyCompatibility:
    """Ensure legacy types still work identically."""

    def test_approval_tier_values(self):
        assert ApprovalTier.TIER_1.value == 1
        assert ApprovalTier.TIER_2.value == 2
        assert ApprovalTier.TIER_3.value == 3
        assert ApprovalTier.TIER_4.value == 4

    def test_action_type_members(self):
        assert ActionType.FILE_READ is not None
        assert ActionType.FILE_WRITE is not None
        assert ActionType.FILE_DELETE is not None
        assert ActionType.COMMAND_EXEC is not None

    def test_security_level_members(self):
        assert SecurityLevel.BLOCKED is not None
        assert SecurityLevel.CRITICAL is not None
        assert SecurityLevel.ALLOWED is not None

    def test_approval_status_members(self):
        assert ApprovalStatus.PENDING.value == 'pending'
        assert ApprovalStatus.APPROVED.value == 'approved'

    def test_user_role_members(self):
        assert UserRole.ADMIN.value == 'admin'
        assert UserRole.RESTRICTED.value == 'restricted'


# =============================================================================
# Integration: Classifier → Matrix Pipeline Tests
# =============================================================================

class TestClassifierMatrixPipeline:
    """Test the full classify → lookup pipeline."""

    def test_read_temp_file_is_silent(self):
        domain = TargetClassifier.classify('C:\\temp\\scratch.txt', hint='file')
        level = TIER_MATRIX.lookup(ActionCategory.OBSERVE, domain)
        assert level == ApprovalLevel.SILENT

    def test_delete_sensitive_doc_requires_biometric(self):
        domain = TargetClassifier.classify(
            'C:\\Users\\admin\\Taxes\\return.pdf', hint='file')
        level = TIER_MATRIX.lookup(ActionCategory.DELETE, domain)
        assert level.gate == SecurityGate.BIOMETRIC

    def test_unlock_door_requires_physical(self):
        domain = TargetClassifier.classify('lock.front_door', hint='ha')
        level = TIER_MATRIX.lookup(ActionCategory.EXECUTE, domain)
        assert level.gate == SecurityGate.PHYSICAL

    def test_turn_on_light_is_passive(self):
        domain = TargetClassifier.classify('light.living_room', hint='ha')
        level = TIER_MATRIX.lookup(ActionCategory.EXECUTE, domain)
        assert level.is_passive

    def test_send_email_requires_biometric(self):
        domain = TargetClassifier.classify(
            'https://graph.microsoft.com/v1.0/me/sendMail', hint='api')
        level = TIER_MATRIX.lookup(ActionCategory.CREATE, domain)
        assert level.gate == SecurityGate.BIOMETRIC

    def test_admin_command_is_hardblocked(self):
        domain = TargetClassifier.classify('reg add HKLM\\Test', hint='command')
        level = TIER_MATRIX.lookup(ActionCategory.EXECUTE, domain)
        assert level == ApprovalLevel.HARDBLOCK

    def test_info_command_is_transparent(self):
        domain = TargetClassifier.classify('systeminfo', hint='command')
        level = TIER_MATRIX.lookup(ActionCategory.EXECUTE, domain)
        assert level == ApprovalLevel.TRANSPARENT

    def test_list_downloads_is_log_only(self):
        domain = TargetClassifier.classify(
            'C:\\Users\\admin\\Downloads\\', hint='file')
        level = TIER_MATRIX.lookup(ActionCategory.LIST, domain)
        assert level == ApprovalLevel.LOG_ONLY

    def test_create_automation_requires_biometric(self):
        domain = TargetClassifier.classify('automation.new_rule', hint='ha')
        level = TIER_MATRIX.lookup(ActionCategory.CREATE, domain)
        assert level.gate == SecurityGate.BIOMETRIC

    def test_disarm_alarm_requires_physical_detailed(self):
        domain = TargetClassifier.classify('alarm_control_panel.house', hint='ha')
        level = TIER_MATRIX.lookup(ActionCategory.EXECUTE, domain)
        assert level == ApprovalLevel.PHYSICAL_DETAILED


if __name__ == '__main__':
    # Run without pytest
    import traceback

    test_classes = [
        TestSecurityGate, TestActionCategory, TestTargetDomain,
        TestApprovalLevel, TestTargetClassifier, TestTierMatrix,
        TestLegacyCompatibility, TestClassifierMatrixPipeline,
    ]

    total_passed = total_failed = 0
    for cls in test_classes:
        print(f'\n--- {cls.__name__} ---')
        obj = cls()
        for name in dir(obj):
            if not name.startswith('test_'):
                continue
            if hasattr(obj, 'setup_method'):
                obj.setup_method()
            try:
                getattr(obj, name)()
                total_passed += 1
            except Exception as e:
                print(f'  FAIL: {name}: {e}')
                traceback.print_exc()
                total_failed += 1

    print(f'\n{"=" * 60}')
    print(f'Results: {total_passed} passed, {total_failed} failed')
    print(f'{"=" * 60}')
    sys.exit(1 if total_failed else 0)
