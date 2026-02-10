#!/usr/bin/env python3
"""
AIOHAI Core Access — Tier Matrix
==================================
Gate-aware lookup table mapping (ActionCategory, TargetDomain) pairs
to ApprovalLevel values.

Enforces gate boundary immutability:
- DENY gate items (levels 0-1) can NEVER be changed at runtime.
- PHYSICAL → BIOMETRIC demotion requires code change + restart.
- BIOMETRIC → SOFTWARE demotion requires code change + restart.
- Within-gate review depth is freely adjustable at runtime.
- Promotion to more restrictive gates is always allowed.

Phase 1 of Approval Gate Taxonomy v3 implementation.

Import from: aiohai.core.access.tier_matrix
"""

from typing import Dict, Optional, Tuple

from aiohai.core.types import (
    ActionCategory, TargetDomain, ApprovalLevel, SecurityGate,
)

__all__ = ['TierMatrix', 'TIER_MATRIX']

# Shorthand aliases
_L = ApprovalLevel
_C = ActionCategory
_D = TargetDomain

# =============================================================================
# THE DEFAULT MATRIX
# =============================================================================
# Key: (ActionCategory, TargetDomain) → ApprovalLevel
# Missing entries default to CONFIRM_STANDARD (level 9).

_DEFAULT_MATRIX: Dict[Tuple[ActionCategory, TargetDomain], ApprovalLevel] = {
    # ===================== FILESYSTEM =====================

    # OBSERVE
    (_C.OBSERVE, _D.FS_TEMP):      _L.SILENT,
    (_C.OBSERVE, _D.FS_DL):        _L.TRANSPARENT,
    (_C.OBSERVE, _D.FS_DOC):       _L.LOG_ONLY,
    (_C.OBSERVE, _D.FS_DOC_SENS):  _L.CONFIRM_STANDARD,
    (_C.OBSERVE, _D.FS_DESK):      _L.TRANSPARENT,
    (_C.OBSERVE, _D.FS_MEDIA):     _L.TRANSPARENT,
    (_C.OBSERVE, _D.FS_APPCONF):   _L.CONFIRM_QUICK,
    (_C.OBSERVE, _D.FS_AIOHAI):    _L.CONFIRM_DETAILED,
    (_C.OBSERVE, _D.FS_SYSTEM):    _L.HARDBLOCK,
    (_C.OBSERVE, _D.FS_CRED):      _L.HARDBLOCK,
    (_C.OBSERVE, _D.FS_NET):       _L.CONFIRM_QUICK,

    # LIST
    (_C.LIST, _D.FS_TEMP):         _L.TRANSPARENT,
    (_C.LIST, _D.FS_DL):           _L.LOG_ONLY,
    (_C.LIST, _D.FS_DOC):          _L.LOG_ONLY,
    (_C.LIST, _D.FS_DOC_SENS):     _L.CONFIRM_STANDARD,
    (_C.LIST, _D.FS_DESK):         _L.LOG_ONLY,
    (_C.LIST, _D.FS_MEDIA):        _L.LOG_ONLY,
    (_C.LIST, _D.FS_APPCONF):      _L.CONFIRM_QUICK,
    (_C.LIST, _D.FS_AIOHAI):       _L.CONFIRM_DETAILED,
    (_C.LIST, _D.FS_SYSTEM):       _L.HARDBLOCK,
    (_C.LIST, _D.FS_CRED):         _L.HARDBLOCK,
    (_C.LIST, _D.FS_NET):          _L.CONFIRM_QUICK,

    # CREATE
    (_C.CREATE, _D.FS_TEMP):       _L.LOG_ONLY,
    (_C.CREATE, _D.FS_DL):         _L.NOTIFY_AND_PROCEED,
    (_C.CREATE, _D.FS_DOC):        _L.CONFIRM_QUICK,
    (_C.CREATE, _D.FS_DOC_SENS):   _L.CONFIRM_DETAILED,
    (_C.CREATE, _D.FS_DESK):       _L.NOTIFY_AND_PROCEED,
    (_C.CREATE, _D.FS_MEDIA):      _L.NOTIFY_AND_PROCEED,
    (_C.CREATE, _D.FS_APPCONF):    _L.CONFIRM_DETAILED,
    (_C.CREATE, _D.FS_AIOHAI):     _L.SOFTBLOCK,
    (_C.CREATE, _D.FS_SYSTEM):     _L.HARDBLOCK,
    (_C.CREATE, _D.FS_CRED):       _L.HARDBLOCK,
    (_C.CREATE, _D.FS_NET):        _L.CONFIRM_STANDARD,

    # MODIFY
    (_C.MODIFY, _D.FS_TEMP):       _L.LOG_ONLY,
    (_C.MODIFY, _D.FS_DL):         _L.CONFIRM_QUICK,
    (_C.MODIFY, _D.FS_DOC):        _L.CONFIRM_STANDARD,
    (_C.MODIFY, _D.FS_DOC_SENS):   _L.BIOMETRIC_STANDARD,
    (_C.MODIFY, _D.FS_DESK):       _L.CONFIRM_QUICK,
    (_C.MODIFY, _D.FS_MEDIA):      _L.CONFIRM_QUICK,
    (_C.MODIFY, _D.FS_APPCONF):    _L.CONFIRM_DETAILED,
    (_C.MODIFY, _D.FS_AIOHAI):     _L.SOFTBLOCK,
    (_C.MODIFY, _D.FS_SYSTEM):     _L.HARDBLOCK,
    (_C.MODIFY, _D.FS_CRED):       _L.HARDBLOCK,
    (_C.MODIFY, _D.FS_NET):        _L.CONFIRM_STANDARD,

    # TRANSFER
    (_C.TRANSFER, _D.FS_TEMP):     _L.LOG_ONLY,
    (_C.TRANSFER, _D.FS_DL):       _L.CONFIRM_QUICK,
    (_C.TRANSFER, _D.FS_DOC):      _L.CONFIRM_STANDARD,
    (_C.TRANSFER, _D.FS_DOC_SENS): _L.BIOMETRIC_STANDARD,
    (_C.TRANSFER, _D.FS_DESK):     _L.CONFIRM_QUICK,
    (_C.TRANSFER, _D.FS_MEDIA):    _L.CONFIRM_QUICK,
    (_C.TRANSFER, _D.FS_APPCONF):  _L.CONFIRM_DETAILED,
    (_C.TRANSFER, _D.FS_AIOHAI):   _L.SOFTBLOCK,
    (_C.TRANSFER, _D.FS_SYSTEM):   _L.HARDBLOCK,
    (_C.TRANSFER, _D.FS_CRED):     _L.HARDBLOCK,
    (_C.TRANSFER, _D.FS_NET):      _L.CONFIRM_STANDARD,

    # DELETE
    (_C.DELETE, _D.FS_TEMP):       _L.LOG_ONLY,
    (_C.DELETE, _D.FS_DL):         _L.CONFIRM_QUICK,
    (_C.DELETE, _D.FS_DOC):        _L.CONFIRM_STANDARD,
    (_C.DELETE, _D.FS_DOC_SENS):   _L.BIOMETRIC_DETAILED,
    (_C.DELETE, _D.FS_DESK):       _L.CONFIRM_QUICK,
    (_C.DELETE, _D.FS_MEDIA):      _L.CONFIRM_STANDARD,
    (_C.DELETE, _D.FS_APPCONF):    _L.BIOMETRIC_STANDARD,
    (_C.DELETE, _D.FS_AIOHAI):     _L.HARDBLOCK,
    (_C.DELETE, _D.FS_SYSTEM):     _L.HARDBLOCK,
    (_C.DELETE, _D.FS_CRED):       _L.HARDBLOCK,
    (_C.DELETE, _D.FS_NET):        _L.CONFIRM_DETAILED,

    # CONFIGURE (filesystem — mostly nonsensical)
    (_C.CONFIGURE, _D.FS_APPCONF): _L.BIOMETRIC_DETAILED,
    (_C.CONFIGURE, _D.FS_AIOHAI):  _L.HARDBLOCK,
    (_C.CONFIGURE, _D.FS_SYSTEM):  _L.HARDBLOCK,
    (_C.CONFIGURE, _D.FS_CRED):    _L.HARDBLOCK,

    # ADMIN (filesystem — always HARDBLOCK)
    (_C.ADMIN, _D.FS_TEMP):        _L.HARDBLOCK,
    (_C.ADMIN, _D.FS_DL):          _L.HARDBLOCK,
    (_C.ADMIN, _D.FS_DOC):         _L.HARDBLOCK,
    (_C.ADMIN, _D.FS_DOC_SENS):    _L.HARDBLOCK,
    (_C.ADMIN, _D.FS_DESK):        _L.HARDBLOCK,
    (_C.ADMIN, _D.FS_MEDIA):       _L.HARDBLOCK,
    (_C.ADMIN, _D.FS_APPCONF):     _L.HARDBLOCK,
    (_C.ADMIN, _D.FS_AIOHAI):      _L.HARDBLOCK,
    (_C.ADMIN, _D.FS_SYSTEM):      _L.HARDBLOCK,
    (_C.ADMIN, _D.FS_CRED):        _L.HARDBLOCK,
    (_C.ADMIN, _D.FS_NET):         _L.HARDBLOCK,

    # ===================== COMMAND =====================

    # EXECUTE (only meaningful category for commands)
    (_C.EXECUTE, _D.CMD_INFO):     _L.TRANSPARENT,
    (_C.EXECUTE, _D.CMD_FOPS):     _L.CONFIRM_STANDARD,
    (_C.EXECUTE, _D.CMD_SVC):      _L.BIOMETRIC_STANDARD,
    (_C.EXECUTE, _D.CMD_INST):     _L.BIOMETRIC_STANDARD,
    (_C.EXECUTE, _D.CMD_SCRIPT):   _L.CONFIRM_DETAILED,
    (_C.EXECUTE, _D.CMD_NET):      _L.HARDBLOCK,
    (_C.EXECUTE, _D.CMD_ADMIN):    _L.HARDBLOCK,
    (_C.EXECUTE, _D.CMD_DISK):     _L.HARDBLOCK,

    # ===================== HOME ASSISTANT =====================

    # OBSERVE
    (_C.OBSERVE, _D.HA_SENS):      _L.SILENT,
    (_C.OBSERVE, _D.HA_PRES):      _L.LOG_ONLY,
    (_C.OBSERVE, _D.HA_LIGHT):     _L.SILENT,
    (_C.OBSERVE, _D.HA_MEDIA):     _L.SILENT,
    (_C.OBSERVE, _D.HA_CLIM):      _L.TRANSPARENT,
    (_C.OBSERVE, _D.HA_COVER):     _L.TRANSPARENT,
    (_C.OBSERVE, _D.HA_GARAGE):    _L.LOG_ONLY,
    (_C.OBSERVE, _D.HA_LOCK):      _L.CONFIRM_QUICK,
    (_C.OBSERVE, _D.HA_ALARM):     _L.CONFIRM_QUICK,
    (_C.OBSERVE, _D.HA_CAM):       _L.CONFIRM_STANDARD,
    (_C.OBSERVE, _D.HA_SCENE):     _L.TRANSPARENT,
    (_C.OBSERVE, _D.HA_AUTO):      _L.LOG_ONLY,
    (_C.OBSERVE, _D.HA_SCRIPT):    _L.LOG_ONLY,
    (_C.OBSERVE, _D.HA_HELPER):    _L.TRANSPARENT,
    (_C.OBSERVE, _D.HA_CONF):      _L.SOFTBLOCK,

    # EXECUTE
    (_C.EXECUTE, _D.HA_LIGHT):     _L.NOTIFY_AND_PROCEED,
    (_C.EXECUTE, _D.HA_MEDIA):     _L.NOTIFY_AND_PROCEED,
    (_C.EXECUTE, _D.HA_CLIM):      _L.CONFIRM_STANDARD,
    (_C.EXECUTE, _D.HA_COVER):     _L.CONFIRM_STANDARD,
    (_C.EXECUTE, _D.HA_GARAGE):    _L.CONFIRM_DETAILED,
    (_C.EXECUTE, _D.HA_LOCK):      _L.PHYSICAL_STANDARD,
    (_C.EXECUTE, _D.HA_ALARM):     _L.PHYSICAL_DETAILED,
    (_C.EXECUTE, _D.HA_CAM):       _L.CONFIRM_STANDARD,
    (_C.EXECUTE, _D.HA_NOTIFY):    _L.CONFIRM_QUICK,
    (_C.EXECUTE, _D.HA_SCENE):     _L.CONFIRM_QUICK,
    (_C.EXECUTE, _D.HA_AUTO):      _L.CONFIRM_DETAILED,
    (_C.EXECUTE, _D.HA_SCRIPT):    _L.CONFIRM_DETAILED,
    (_C.EXECUTE, _D.HA_HELPER):    _L.NOTIFY_AND_PROCEED,
    (_C.EXECUTE, _D.HA_CONF):      _L.HARDBLOCK,

    # CREATE (HA)
    (_C.CREATE, _D.HA_SCENE):      _L.CONFIRM_DETAILED,
    (_C.CREATE, _D.HA_AUTO):       _L.BIOMETRIC_DETAILED,
    (_C.CREATE, _D.HA_SCRIPT):     _L.CONFIRM_DETAILED,
    (_C.CREATE, _D.HA_HELPER):     _L.CONFIRM_QUICK,
    (_C.CREATE, _D.HA_CONF):       _L.HARDBLOCK,

    # MODIFY (HA)
    (_C.MODIFY, _D.HA_SCENE):      _L.CONFIRM_DETAILED,
    (_C.MODIFY, _D.HA_AUTO):       _L.BIOMETRIC_DETAILED,
    (_C.MODIFY, _D.HA_SCRIPT):     _L.CONFIRM_DETAILED,
    (_C.MODIFY, _D.HA_HELPER):     _L.CONFIRM_QUICK,
    (_C.MODIFY, _D.HA_CONF):       _L.HARDBLOCK,

    # DELETE (HA)
    (_C.DELETE, _D.HA_SCENE):      _L.CONFIRM_DETAILED,
    (_C.DELETE, _D.HA_AUTO):       _L.BIOMETRIC_DETAILED,
    (_C.DELETE, _D.HA_SCRIPT):     _L.CONFIRM_DETAILED,
    (_C.DELETE, _D.HA_HELPER):     _L.CONFIRM_STANDARD,
    (_C.DELETE, _D.HA_CONF):       _L.HARDBLOCK,

    # CONFIGURE (HA)
    (_C.CONFIGURE, _D.HA_AUTO):    _L.BIOMETRIC_DETAILED,
    (_C.CONFIGURE, _D.HA_CONF):    _L.HARDBLOCK,

    # ===================== OFFICE =====================

    # OBSERVE
    (_C.OBSERVE, _D.OFF_DOC):      _L.LOG_ONLY,
    (_C.OBSERVE, _D.OFF_MACRO):    _L.CONFIRM_DETAILED,
    (_C.OBSERVE, _D.OFF_EREAD):    _L.CONFIRM_STANDARD,
    (_C.OBSERVE, _D.OFF_CAL):      _L.LOG_ONLY,
    (_C.OBSERVE, _D.OFF_CONT):     _L.CONFIRM_STANDARD,

    # CREATE
    (_C.CREATE, _D.OFF_DOC):       _L.CONFIRM_QUICK,
    (_C.CREATE, _D.OFF_MACRO):     _L.SOFTBLOCK,
    (_C.CREATE, _D.OFF_ESEND):     _L.BIOMETRIC_DETAILED,
    (_C.CREATE, _D.OFF_CAL):       _L.CONFIRM_STANDARD,
    (_C.CREATE, _D.OFF_CONT):      _L.CONFIRM_DETAILED,

    # MODIFY
    (_C.MODIFY, _D.OFF_DOC):       _L.CONFIRM_STANDARD,
    (_C.MODIFY, _D.OFF_MACRO):     _L.SOFTBLOCK,
    (_C.MODIFY, _D.OFF_CAL):       _L.CONFIRM_STANDARD,
    (_C.MODIFY, _D.OFF_CONT):      _L.CONFIRM_DETAILED,

    # DELETE
    (_C.DELETE, _D.OFF_DOC):       _L.CONFIRM_STANDARD,
    (_C.DELETE, _D.OFF_MACRO):     _L.HARDBLOCK,
    (_C.DELETE, _D.OFF_EREAD):     _L.CONFIRM_DETAILED,
    (_C.DELETE, _D.OFF_CAL):       _L.CONFIRM_DETAILED,
    (_C.DELETE, _D.OFF_CONT):      _L.CONFIRM_DETAILED,
}
# fmt: on


# =============================================================================
# TIER MATRIX CLASS
# =============================================================================

class TierMatrix:
    """Gate-aware tier matrix with boundary enforcement.

    The matrix answers: "Given what this action does (category) and what
    it touches (domain), what approval level is required?"

    Gate boundary rules:
    - DENY gate items cannot be changed at runtime (levels 0-1).
    - Permanent gate demotion (PHYSICAL→BIOMETRIC, BIOMETRIC→SOFTWARE)
      requires code change + restart.
    - Within-gate review depth changes are allowed at runtime.
    - Promotion to more restrictive gates is always allowed.
    """

    # The default safe level for unknown (category, domain) pairs.
    # CONFIRM_STANDARD requires active human review — fail closed.
    DEFAULT_LEVEL = ApprovalLevel.CONFIRM_STANDARD

    def __init__(self):
        # Start with the hardcoded defaults
        self._matrix: Dict[Tuple[ActionCategory, TargetDomain], ApprovalLevel] = (
            dict(_DEFAULT_MATRIX)
        )
        # Runtime overrides (from user_overrides.json, validated on load)
        self._overrides: Dict[Tuple[ActionCategory, TargetDomain], ApprovalLevel] = {}

    def lookup(self, category: ActionCategory,
               domain: TargetDomain) -> ApprovalLevel:
        """Look up the effective approval level for a (category, domain) pair.

        Checks overrides first, then the default matrix, then falls back
        to DEFAULT_LEVEL (CONFIRM_STANDARD).
        """
        key = (category, domain)
        # Override takes precedence (already validated on set)
        if key in self._overrides:
            return self._overrides[key]
        return self._matrix.get(key, self.DEFAULT_LEVEL)

    def get_default(self, category: ActionCategory,
                    domain: TargetDomain) -> ApprovalLevel:
        """Get the hardcoded default level (ignoring overrides)."""
        return self._matrix.get((category, domain), self.DEFAULT_LEVEL)

    def set_override(self, category: ActionCategory, domain: TargetDomain,
                     level: ApprovalLevel) -> Tuple[bool, str]:
        """Set a runtime override, enforcing gate boundary rules.

        Returns (success, message).
        """
        key = (category, domain)
        default_level = self._matrix.get(key, self.DEFAULT_LEVEL)
        default_gate = default_level.gate

        # RULE 1: DENY gate items can NEVER be overridden
        if default_gate == SecurityGate.DENY:
            return False, (
                f"Cannot override {category.value}:{domain.value} — "
                f"DENY gate items are immutable. "
                f"Manual source code editing required."
            )

        # RULE 2: Cannot demote across gate boundaries
        new_gate = level.gate
        if new_gate > default_gate:
            # Higher numeric gate value = LESS restrictive
            return False, (
                f"Cannot demote {category.value}:{domain.value} from "
                f"{default_gate.name} gate to {new_gate.name} gate at runtime. "
                f"Gate demotion requires code change + restart."
            )

        # RULE 3: Promotion (more restrictive) is always allowed
        # RULE 4: Within-gate review depth changes are allowed
        self._overrides[key] = level
        return True, f"Override set: {category.value}:{domain.value} → {level.name}"

    def remove_override(self, category: ActionCategory,
                        domain: TargetDomain) -> bool:
        """Remove a runtime override, reverting to the default.

        Returns True if an override was removed.
        """
        key = (category, domain)
        if key in self._overrides:
            del self._overrides[key]
            return True
        return False

    def get_all_overrides(self) -> Dict[str, Dict]:
        """Get all current overrides as a serializable dict."""
        result = {}
        for (cat, dom), level in self._overrides.items():
            key_str = f"{cat.value}:{dom.value}"
            default = self._matrix.get((cat, dom), self.DEFAULT_LEVEL)
            result[key_str] = {
                'level': level.value,
                'level_name': level.name,
                'gate': level.gate.name,
                'default_level': default.value,
                'default_gate': default.gate.name,
            }
        return result

    def load_overrides(self, overrides: Dict[str, Dict]) -> list:
        """Load overrides from a dict (e.g., from user_overrides.json).

        Validates each override against gate boundary rules.
        Returns a list of (key_str, error_message) for rejected overrides.
        """
        errors = []
        for key_str, data in overrides.items():
            parts = key_str.split(':', 1)
            if len(parts) != 2:
                errors.append((key_str, "Invalid key format (expected CATEGORY:DOMAIN)"))
                continue

            try:
                category = ActionCategory(parts[0])
            except ValueError:
                errors.append((key_str, f"Unknown category: {parts[0]}"))
                continue

            try:
                domain = TargetDomain(parts[1])
            except ValueError:
                errors.append((key_str, f"Unknown domain: {parts[1]}"))
                continue

            try:
                level = ApprovalLevel(data.get('level', 9))
            except ValueError:
                errors.append((key_str, f"Unknown level: {data.get('level')}"))
                continue

            ok, msg = self.set_override(category, domain, level)
            if not ok:
                errors.append((key_str, msg))

        return errors

    def validate_adjustment(self, category: ActionCategory,
                            domain: TargetDomain,
                            requested_level: ApprovalLevel
                            ) -> Tuple[bool, str, Optional[str]]:
        """Validate a proposed adjustment without applying it.

        Returns:
            (allowed, explanation, boundary_violated)
            boundary_violated is None if allowed, or one of:
            'DENY_GATE', 'PHYSICAL_TO_BIOMETRIC', 'BIOMETRIC_TO_SOFTWARE',
            'SOFTWARE_TO_PASSIVE'
        """
        key = (category, domain)
        default_level = self._matrix.get(key, self.DEFAULT_LEVEL)
        default_gate = default_level.gate
        requested_gate = requested_level.gate

        if default_gate == SecurityGate.DENY:
            return False, (
                f"{category.value}:{domain.value} is in the DENY gate "
                f"(level {default_level.value}: {default_level.name}). "
                f"This cannot be changed at runtime or through the companion app. "
                f"Manual source code editing is required."
            ), 'DENY_GATE'

        if requested_gate > default_gate:
            boundary = f"{default_gate.name}_TO_{requested_gate.name}"
            return False, (
                f"Gate demotion from {default_gate.name} to {requested_gate.name} "
                f"for {category.value}:{domain.value} requires shutting down "
                f"AIOHAI and editing source code."
            ), boundary

        return True, (
            f"Within-gate adjustment: {default_level.name} → {requested_level.name} "
            f"(gate: {default_gate.name})"
        ), None

    @staticmethod
    def get_gate_for_pair(category: ActionCategory,
                          domain: TargetDomain) -> SecurityGate:
        """Get the default gate for a (category, domain) pair.

        Convenience method that doesn't require an instance.
        """
        level = _DEFAULT_MATRIX.get(
            (category, domain), ApprovalLevel.CONFIRM_STANDARD)
        return level.gate

    @staticmethod
    def is_deny_gate(category: ActionCategory,
                     domain: TargetDomain) -> bool:
        """Check if a (category, domain) pair is in the DENY gate."""
        level = _DEFAULT_MATRIX.get(
            (category, domain), ApprovalLevel.CONFIRM_STANDARD)
        return level.gate == SecurityGate.DENY


# Module-level singleton
TIER_MATRIX = TierMatrix()
