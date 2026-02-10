#!/usr/bin/env python3
"""
AIOHAI Core Trust — Trust Matrix Adjuster
============================================
Validates and applies runtime trust matrix adjustments within gate
boundary constraints.

Gate Boundary Rules (Immutable)
-------------------------------
- DENY gate items (levels 0-1) can NEVER be changed at runtime.
  No API, no companion app, no mechanism. Manual source code edit only.
- PHYSICAL → BIOMETRIC demotion: NEVER at runtime. Code change + restart.
- BIOMETRIC → SOFTWARE demotion: NEVER at runtime. Code change + restart.
- Within-gate review depth: freely adjustable at runtime.
- Promotion to more restrictive gates: always allowed.

The adjuster wraps TierMatrix.set_override() and validate_adjustment()
with higher-level logic:
- Validates proposed adjustments from user or LLM
- Applies allowed adjustments to the tier matrix
- Generates change request log entries for rejected gate demotions
- Loads/saves user_overrides.json with schema validation
- Provides the LLM-facing adjustment API (propose → validate → apply)

Phase 3 of Approval Gate Taxonomy v3 implementation.

Import from: aiohai.core.trust.matrix_adjuster
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from aiohai.core.types import (
    ActionCategory, TargetDomain, ApprovalLevel, SecurityGate,
)
from aiohai.core.access.tier_matrix import TierMatrix, TIER_MATRIX

__all__ = ['TrustMatrixAdjuster']

logger = logging.getLogger("aiohai.core.trust.matrix_adjuster")

# Default file paths relative to AIOHAI_HOME
DEFAULT_USER_OVERRIDES = "config/user_overrides.json"
OVERRIDES_SCHEMA_VERSION = "3.0"

# Maximum number of overrides allowed (prevent abuse)
MAX_OVERRIDES = 200

# Maximum number of path classifications
MAX_PATH_CLASSIFICATIONS = 100

# Maximum number of command additions
MAX_COMMAND_ADDITIONS = 50


class TrustMatrixAdjuster:
    """Validates and applies runtime trust matrix adjustments.

    Thread-safe. All public methods acquire self._lock.

    Usage:
        adjuster = TrustMatrixAdjuster(tier_matrix=TIER_MATRIX)

        # Load saved overrides
        adjuster.load_from_file()

        # Propose an adjustment (from LLM or companion app)
        result = adjuster.propose_adjustment(
            ActionCategory.EXECUTE, TargetDomain.HA_LIGHT,
            ApprovalLevel.SILENT,
            reason="User wants light control silent"
        )
        # result = AdjustmentResult with allowed/rejected + explanation

        # Apply if allowed
        if result.allowed:
            adjuster.apply_adjustment(result)
            adjuster.save_to_file()

        # For rejected gate demotions, generate change request
        if not result.allowed and result.boundary_violated:
            change_request = result.to_change_request(user="admin")
            # Pass to ChangeRequestLog
    """

    def __init__(self, *, tier_matrix: TierMatrix = None,
                 overrides_path: Optional[str] = None,
                 change_request_log=None):
        """Initialize the adjuster.

        Args:
            tier_matrix: The TierMatrix to adjust. Defaults to TIER_MATRIX.
            overrides_path: Path to user_overrides.json. Defaults to
                           $AIOHAI_HOME/config/user_overrides.json.
            change_request_log: Optional ChangeRequestLog for logging
                               rejected gate demotions.
        """
        self._lock = threading.Lock()
        self._tier_matrix = tier_matrix or TIER_MATRIX
        self._change_request_log = change_request_log

        if overrides_path is None:
            aiohai_home = os.environ.get('AIOHAI_HOME', '.')
            overrides_path = os.path.join(aiohai_home, DEFAULT_USER_OVERRIDES)
        self._overrides_path = Path(overrides_path)

        # Non-tier-matrix overrides (stored in user_overrides.json but
        # managed separately from the tier matrix)
        self._path_classifications: Dict[str, Dict] = {}
        self._command_additions: Dict[str, Dict] = {}
        self._ha_entity_overrides: Dict[str, Dict] = {}
        self._session_defaults: Dict[str, Any] = {}

    # ---- Proposal and validation ----

    def propose_adjustment(
        self, category: ActionCategory, domain: TargetDomain,
        requested_level: ApprovalLevel,
        reason: str = "",
    ) -> 'AdjustmentResult':
        """Propose a trust matrix adjustment.

        Validates the proposed change against gate boundary rules
        without applying it. Call apply_adjustment() to apply.

        Returns an AdjustmentResult with validation details.
        """
        with self._lock:
            default_level = self._tier_matrix.get_default(category, domain)
            current_level = self._tier_matrix.lookup(category, domain)

            allowed, explanation, boundary_violated = (
                self._tier_matrix.validate_adjustment(
                    category, domain, requested_level
                )
            )

            # Check override count limit
            if allowed and len(self._tier_matrix.get_all_overrides()) >= MAX_OVERRIDES:
                allowed = False
                explanation = (
                    f"Maximum number of overrides ({MAX_OVERRIDES}) reached. "
                    f"Remove unused overrides before adding new ones."
                )
                boundary_violated = None

            # Build alternatives for rejected adjustments
            alternatives = []
            if not allowed and boundary_violated:
                alternatives = self._build_alternatives(
                    category, domain, default_level, requested_level
                )

            return AdjustmentResult(
                category=category,
                domain=domain,
                current_level=current_level,
                default_level=default_level,
                requested_level=requested_level,
                allowed=allowed,
                explanation=explanation,
                boundary_violated=boundary_violated,
                alternatives=alternatives,
                reason=reason,
            )

    def apply_adjustment(self, result: 'AdjustmentResult') -> bool:
        """Apply a validated adjustment to the tier matrix.

        Only applies if result.allowed is True. Returns True on success.
        """
        if not result.allowed:
            logger.warning(
                "Cannot apply rejected adjustment: %s:%s → %s (%s)",
                result.category.value, result.domain.value,
                result.requested_level.name, result.explanation,
            )
            return False

        with self._lock:
            ok, msg = self._tier_matrix.set_override(
                result.category, result.domain, result.requested_level
            )
            if ok:
                logger.info(
                    "Applied adjustment: %s:%s → %s (reason: %s)",
                    result.category.value, result.domain.value,
                    result.requested_level.name, result.reason,
                )
            else:
                logger.error(
                    "Failed to apply validated adjustment: %s", msg
                )
            return ok

    def remove_adjustment(
        self, category: ActionCategory, domain: TargetDomain
    ) -> bool:
        """Remove an override, reverting to the default level.

        Returns True if an override was removed.
        """
        with self._lock:
            removed = self._tier_matrix.remove_override(category, domain)
            if removed:
                logger.info(
                    "Removed override: %s:%s (reverted to default)",
                    category.value, domain.value,
                )
            return removed

    def reset_all(self) -> int:
        """Remove all overrides, reverting everything to defaults.

        Returns the number of overrides removed.
        """
        with self._lock:
            overrides = self._tier_matrix.get_all_overrides()
            count = len(overrides)
            for key_str in list(overrides.keys()):
                parts = key_str.split(':', 1)
                if len(parts) == 2:
                    try:
                        cat = ActionCategory(parts[0])
                        dom = TargetDomain(parts[1])
                        self._tier_matrix.remove_override(cat, dom)
                    except (ValueError, KeyError):
                        pass
            self._path_classifications.clear()
            self._command_additions.clear()
            self._ha_entity_overrides.clear()
            self._session_defaults.clear()
            logger.info("Reset all overrides: %d removed", count)
            return count

    # ---- LLM-facing adjustment API ----

    def propose_from_natural_language(
        self, category_str: str, domain_str: str,
        requested_level_value: int,
        reason: str = "",
    ) -> 'AdjustmentResult':
        """Propose an adjustment from string values (LLM-facing API).

        Parses enum values from strings, returns AdjustmentResult.
        Invalid inputs produce a rejected result with explanation.
        """
        try:
            category = ActionCategory(category_str)
        except ValueError:
            return AdjustmentResult(
                category=None, domain=None,
                current_level=None, default_level=None,
                requested_level=None,
                allowed=False,
                explanation=f"Unknown category: {category_str!r}",
                boundary_violated=None,
                alternatives=[], reason=reason,
            )

        try:
            domain = TargetDomain(domain_str)
        except ValueError:
            return AdjustmentResult(
                category=category, domain=None,
                current_level=None, default_level=None,
                requested_level=None,
                allowed=False,
                explanation=f"Unknown domain: {domain_str!r}",
                boundary_violated=None,
                alternatives=[], reason=reason,
            )

        try:
            requested_level = ApprovalLevel(requested_level_value)
        except ValueError:
            return AdjustmentResult(
                category=category, domain=domain,
                current_level=self._tier_matrix.lookup(category, domain),
                default_level=self._tier_matrix.get_default(category, domain),
                requested_level=None,
                allowed=False,
                explanation=f"Unknown level: {requested_level_value}",
                boundary_violated=None,
                alternatives=[], reason=reason,
            )

        return self.propose_adjustment(
            category, domain, requested_level, reason=reason
        )

    # ---- Query methods ----

    def get_current_level(
        self, category: ActionCategory, domain: TargetDomain
    ) -> ApprovalLevel:
        """Get the current effective level (including overrides)."""
        with self._lock:
            return self._tier_matrix.lookup(category, domain)

    def get_default_level(
        self, category: ActionCategory, domain: TargetDomain
    ) -> ApprovalLevel:
        """Get the hardcoded default level (ignoring overrides)."""
        return self._tier_matrix.get_default(category, domain)

    def get_all_overrides(self) -> Dict[str, Dict]:
        """Get all current tier matrix overrides."""
        with self._lock:
            return self._tier_matrix.get_all_overrides()

    def has_overrides(self) -> bool:
        """Check if any overrides are active."""
        with self._lock:
            return bool(self._tier_matrix.get_all_overrides())

    # ---- Path classification management ----

    def set_path_classification(
        self, path: str, domain: str, reason: str = ""
    ) -> Tuple[bool, str]:
        """Classify a filesystem path to a specific domain.

        This tells TargetClassifier to map the given path to a
        specific TargetDomain, overriding the default pattern matching.
        """
        with self._lock:
            if len(self._path_classifications) >= MAX_PATH_CLASSIFICATIONS:
                return False, (
                    f"Maximum path classifications ({MAX_PATH_CLASSIFICATIONS}) "
                    f"reached."
                )
            try:
                TargetDomain(domain)
            except ValueError:
                return False, f"Unknown domain: {domain!r}"

            self._path_classifications[path] = {
                'domain': domain,
                'reason': reason,
            }
            return True, f"Path {path!r} classified as {domain}"

    def remove_path_classification(self, path: str) -> bool:
        """Remove a path classification override."""
        with self._lock:
            return self._path_classifications.pop(path, None) is not None

    # ---- Command addition management ----

    def add_command(
        self, command: str, domain: str, reason: str = ""
    ) -> Tuple[bool, str]:
        """Add a command to a domain classification."""
        with self._lock:
            if len(self._command_additions) >= MAX_COMMAND_ADDITIONS:
                return False, (
                    f"Maximum command additions ({MAX_COMMAND_ADDITIONS}) "
                    f"reached."
                )
            try:
                TargetDomain(domain)
            except ValueError:
                return False, f"Unknown domain: {domain!r}"

            self._command_additions[command] = {
                'domain': domain,
                'reason': reason,
            }
            return True, f"Command {command!r} classified as {domain}"

    def remove_command(self, command: str) -> bool:
        """Remove a command classification."""
        with self._lock:
            return self._command_additions.pop(command, None) is not None

    # ---- HA entity override management ----

    def set_ha_entity_override(
        self, entity_id: str, domain: str, reason: str = ""
    ) -> Tuple[bool, str]:
        """Override the domain classification for a Home Assistant entity."""
        with self._lock:
            try:
                TargetDomain(domain)
            except ValueError:
                return False, f"Unknown domain: {domain!r}"

            self._ha_entity_overrides[entity_id] = {
                'domain': domain,
                'reason': reason,
            }
            return True, f"Entity {entity_id!r} classified as {domain}"

    def remove_ha_entity_override(self, entity_id: str) -> bool:
        """Remove an HA entity domain override."""
        with self._lock:
            return self._ha_entity_overrides.pop(entity_id, None) is not None

    # ---- Session defaults ----

    def set_session_defaults(
        self, max_actions: int = None,
        max_duration_minutes: int = None,
        default_elevated_level: int = None,
    ) -> Tuple[bool, str]:
        """Update session elevation defaults.

        Only provided values are updated; None values are left unchanged.
        """
        with self._lock:
            if max_actions is not None:
                if max_actions < 1 or max_actions > 200:
                    return False, "max_actions must be between 1 and 200"
                self._session_defaults['max_actions'] = max_actions

            if max_duration_minutes is not None:
                if max_duration_minutes < 1 or max_duration_minutes > 60:
                    return False, "max_duration_minutes must be between 1 and 60"
                self._session_defaults['max_duration_minutes'] = max_duration_minutes

            if default_elevated_level is not None:
                try:
                    level = ApprovalLevel(default_elevated_level)
                except ValueError:
                    return False, f"Unknown level: {default_elevated_level}"
                if not level.is_passive:
                    return False, (
                        f"Default elevated level must be passive (11-14), "
                        f"got {level.name} ({level.value})"
                    )
                self._session_defaults['default_elevated_level'] = default_elevated_level

            return True, "Session defaults updated"

    # ---- Persistence ----

    def load_from_file(self) -> Tuple[bool, List[str]]:
        """Load overrides from user_overrides.json.

        Returns (success, list of error messages for rejected overrides).
        """
        if not self._overrides_path.exists():
            return True, []

        try:
            with open(self._overrides_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            msg = f"Cannot read {self._overrides_path}: {e}"
            logger.error(msg)
            return False, [msg]

        # Validate schema version
        schema = data.get('_schema_version', '1.0')
        if schema != OVERRIDES_SCHEMA_VERSION:
            logger.warning(
                "Override file schema %s != expected %s, loading anyway",
                schema, OVERRIDES_SCHEMA_VERSION,
            )

        errors = []

        # Load tier overrides
        tier_overrides = data.get('tier_overrides', {})
        with self._lock:
            tier_errors = self._tier_matrix.load_overrides(tier_overrides)
            for key_str, err in tier_errors:
                errors.append(f"tier_overrides[{key_str}]: {err}")

        # Load gate promotions (these are also tier overrides)
        gate_promotions = data.get('gate_promotions', {})
        with self._lock:
            promo_errors = self._tier_matrix.load_overrides(gate_promotions)
            for key_str, err in promo_errors:
                errors.append(f"gate_promotions[{key_str}]: {err}")

        # Load non-matrix overrides
        with self._lock:
            self._path_classifications = data.get('path_classifications', {})
            self._command_additions = data.get('command_additions', {})
            self._ha_entity_overrides = data.get('ha_entity_overrides', {})
            self._session_defaults = data.get('session_defaults', {})

        if errors:
            logger.warning(
                "Loaded overrides with %d rejected entries: %s",
                len(errors), errors,
            )
        else:
            logger.info(
                "Loaded overrides from %s (%d tier, %d paths, %d commands, %d HA)",
                self._overrides_path,
                len(tier_overrides) + len(gate_promotions),
                len(self._path_classifications),
                len(self._command_additions),
                len(self._ha_entity_overrides),
            )

        return len(errors) == 0, errors

    def save_to_file(self) -> bool:
        """Save current overrides to user_overrides.json.

        Creates a timestamped backup before overwriting.
        Returns True on success.
        """
        with self._lock:
            data = self._build_overrides_dict()

        # Ensure directory exists
        try:
            self._overrides_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            logger.error("Cannot create overrides directory: %s", e)
            return False

        # Create backup if file exists
        if self._overrides_path.exists():
            backup_dir = self._overrides_path.parent / "backups"
            try:
                backup_dir.mkdir(parents=True, exist_ok=True)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_name = f"user_overrides_{timestamp}.json"
                backup_path = backup_dir / backup_name
                shutil.copy2(self._overrides_path, backup_path)
            except OSError as e:
                logger.warning("Cannot create backup: %s", e)

        # Write atomically (write to temp, then rename)
        tmp_path = self._overrides_path.with_suffix('.tmp')
        try:
            with open(tmp_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
                f.write('\n')
            tmp_path.replace(self._overrides_path)
            logger.info("Saved overrides to %s", self._overrides_path)
            return True
        except OSError as e:
            logger.error("Cannot write overrides: %s", e)
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            return False

    def _build_overrides_dict(self) -> Dict:
        """Build the full user_overrides.json data structure.

        Must be called with self._lock held.
        """
        now = datetime.now().isoformat()

        # Separate overrides into tier_overrides and gate_promotions
        all_overrides = self._tier_matrix.get_all_overrides()
        tier_overrides = {}
        gate_promotions = {}

        for key_str, data in all_overrides.items():
            # A gate promotion is when the override gate is MORE restrictive
            # (lower enum value) than the default gate
            default_gate_name = data.get('default_gate', '')
            override_gate_name = data.get('gate', '')
            try:
                default_gate = SecurityGate[default_gate_name]
                override_gate = SecurityGate[override_gate_name]
                if override_gate < default_gate:
                    gate_promotions[key_str] = data
                else:
                    tier_overrides[key_str] = data
            except (KeyError, ValueError):
                tier_overrides[key_str] = data

        return {
            '_schema_version': OVERRIDES_SCHEMA_VERSION,
            '_last_modified': now,
            '_last_modified_by': 'trust_matrix_adjuster',
            '_backup_path': str(
                self._overrides_path.parent / "backups" /
                f"user_overrides_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            ),
            'tier_overrides': tier_overrides,
            'gate_promotions': gate_promotions,
            'session_defaults': self._session_defaults,
            'path_classifications': self._path_classifications,
            'command_additions': self._command_additions,
            'ha_entity_overrides': self._ha_entity_overrides,
        }

    # ---- Internal helpers ----

    def _build_alternatives(
        self, category: ActionCategory, domain: TargetDomain,
        default_level: ApprovalLevel, requested_level: ApprovalLevel
    ) -> List[Dict]:
        """Build alternative suggestions for rejected adjustments."""
        alternatives = []
        default_gate = default_level.gate

        # Suggest within-gate depth changes
        if default_gate == SecurityGate.PHYSICAL:
            for alt in (ApprovalLevel.PHYSICAL_QUICK,
                        ApprovalLevel.PHYSICAL_STANDARD,
                        ApprovalLevel.PHYSICAL_DETAILED):
                if alt != default_level:
                    alternatives.append({
                        'level': alt.value,
                        'level_name': alt.name,
                        'gate': 'PHYSICAL',
                        'description': (
                            f"Adjust review depth to {alt.name} "
                            f"(still requires NFC tap)"
                        ),
                    })

        elif default_gate == SecurityGate.BIOMETRIC:
            for alt in (ApprovalLevel.BIOMETRIC_QUICK,
                        ApprovalLevel.BIOMETRIC_STANDARD,
                        ApprovalLevel.BIOMETRIC_DETAILED):
                if alt != default_level:
                    alternatives.append({
                        'level': alt.value,
                        'level_name': alt.name,
                        'gate': 'BIOMETRIC',
                        'description': (
                            f"Adjust review depth to {alt.name} "
                            f"(still requires authenticator)"
                        ),
                    })

        elif default_gate == SecurityGate.SOFTWARE:
            for alt in (ApprovalLevel.CONFIRM_QUICK,
                        ApprovalLevel.CONFIRM_STANDARD,
                        ApprovalLevel.CONFIRM_DETAILED):
                if alt != default_level:
                    alternatives.append({
                        'level': alt.value,
                        'level_name': alt.name,
                        'gate': 'SOFTWARE',
                        'description': (
                            f"Adjust review depth to {alt.name}"
                        ),
                    })

        return alternatives

    @property
    def overrides_path(self) -> str:
        """Get the path to user_overrides.json."""
        return str(self._overrides_path)

    @property
    def path_classifications(self) -> Dict[str, Dict]:
        """Get current path classifications (read-only copy)."""
        with self._lock:
            return dict(self._path_classifications)

    @property
    def command_additions(self) -> Dict[str, Dict]:
        """Get current command additions (read-only copy)."""
        with self._lock:
            return dict(self._command_additions)

    @property
    def ha_entity_overrides(self) -> Dict[str, Dict]:
        """Get current HA entity overrides (read-only copy)."""
        with self._lock:
            return dict(self._ha_entity_overrides)

    @property
    def session_defaults(self) -> Dict[str, Any]:
        """Get current session defaults (read-only copy)."""
        with self._lock:
            return dict(self._session_defaults)


# =============================================================================
# ADJUSTMENT RESULT
# =============================================================================

class AdjustmentResult:
    """Result of a proposed trust matrix adjustment.

    Contains validation status, explanation, alternatives for rejected
    adjustments, and a method to generate change request log entries.
    """

    __slots__ = (
        'category', 'domain', 'current_level', 'default_level',
        'requested_level', 'allowed', 'explanation',
        'boundary_violated', 'alternatives', 'reason',
    )

    def __init__(self, *, category, domain, current_level, default_level,
                 requested_level, allowed, explanation,
                 boundary_violated, alternatives, reason):
        self.category = category
        self.domain = domain
        self.current_level = current_level
        self.default_level = default_level
        self.requested_level = requested_level
        self.allowed = allowed
        self.explanation = explanation
        self.boundary_violated = boundary_violated
        self.alternatives = alternatives
        self.reason = reason

    def to_dict(self) -> Dict:
        """Serialize to JSON-safe dict (for API responses / approval cards)."""
        return {
            'category': self.category.value if self.category else None,
            'domain': self.domain.value if self.domain else None,
            'current_level': self.current_level.value if self.current_level else None,
            'current_level_name': self.current_level.name if self.current_level else None,
            'current_gate': (self.current_level.gate.name
                            if self.current_level else None),
            'default_level': self.default_level.value if self.default_level else None,
            'default_gate': (self.default_level.gate.name
                            if self.default_level else None),
            'requested_level': (self.requested_level.value
                               if self.requested_level else None),
            'requested_level_name': (self.requested_level.name
                                    if self.requested_level else None),
            'requested_gate': (self.requested_level.gate.name
                              if self.requested_level else None),
            'allowed': self.allowed,
            'explanation': self.explanation,
            'boundary_violated': self.boundary_violated,
            'alternatives': self.alternatives,
            'reason': self.reason,
        }

    def to_change_request(self, user: str = "unknown") -> Dict:
        """Generate a change request log entry for rejected adjustments.

        Only meaningful when self.allowed is False and self.boundary_violated
        is not None.
        """
        now = datetime.now().isoformat()

        boundary_type = 'unknown'
        if self.boundary_violated == 'DENY_GATE':
            boundary_type = 'manual_code_edit_only'
        elif self.boundary_violated:
            boundary_type = 'code_change_required'

        return {
            'timestamp': now,
            'user': user,
            'category': self.category.value if self.category else None,
            'domain': self.domain.value if self.domain else None,
            'current_level': self.current_level.value if self.current_level else None,
            'current_gate': (self.current_level.gate.name
                            if self.current_level else None),
            'requested_level': (self.requested_level.value
                               if self.requested_level else None),
            'requested_gate': (self.requested_level.gate.name
                              if self.requested_level else None),
            'boundary_violated': self.boundary_violated,
            'boundary_type': boundary_type,
            'user_context': self.reason,
            'status': 'logged',
            'applied': None,
            'applied_by': None,
            'applied_at': None,
        }
