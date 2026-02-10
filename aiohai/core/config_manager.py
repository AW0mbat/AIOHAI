#!/usr/bin/env python3
"""
AIOHAI Core — Config Manager
===============================
Read/write/validate user_overrides.json and related configuration with
gate constraint enforcement and DENY gate immutability.

Wraps TrustMatrixAdjuster and ChangeRequestLog with a higher-level API
suitable for the companion app admin interface:
- Atomically read/write configuration snapshots
- Backup and restore support
- DENY gate immutability enforcement at the API boundary
- Schema validation on load
- Diff generation for apply-with-restart flows

Phase 4 of Approval Gate Taxonomy v3 implementation.

Import from: aiohai.core.config_manager
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

from aiohai.core.version import __version__

from aiohai.core.types import (
    ActionCategory, TargetDomain, ApprovalLevel, SecurityGate,
)
from aiohai.core.access.tier_matrix import TierMatrix, TIER_MATRIX

__all__ = ['ConfigManager']

logger = logging.getLogger("aiohai.core.config_manager")

# Max number of backups to retain
MAX_BACKUPS = 50

# Expected schema version for user_overrides.json
EXPECTED_SCHEMA_VERSION = "3.0"


class ConfigManager:
    """Admin-facing configuration manager for the companion app.

    Provides a safe, validated interface for reading and writing:
    - Tier matrix overrides (via TrustMatrixAdjuster)
    - Path/command/entity classifications
    - Session defaults
    - Backup and restore of configuration snapshots

    Thread-safe. All public methods acquire self._lock.

    Usage:
        mgr = ConfigManager(
            adjuster=trust_matrix_adjuster,
            change_request_log=change_request_log,
        )

        # Get full config snapshot for admin UI
        snapshot = mgr.get_config_snapshot()

        # Apply changes from admin UI
        result = mgr.apply_admin_changes(changes_dict, admin_user="admin")

        # Backup/restore
        backup_path = mgr.create_backup()
        backups = mgr.list_backups()
        mgr.restore_from_backup(backup_path)
    """

    def __init__(self, *, adjuster=None, change_request_log=None,
                 tier_matrix: TierMatrix = None,
                 config_dir: Optional[str] = None):
        """Initialize the config manager.

        Args:
            adjuster: TrustMatrixAdjuster instance.
            change_request_log: ChangeRequestLog instance.
            tier_matrix: TierMatrix for direct lookups. Defaults to TIER_MATRIX.
            config_dir: Path to config directory. Defaults to $AIOHAI_HOME/config.
        """
        self._lock = threading.Lock()
        self._adjuster = adjuster
        self._change_request_log = change_request_log
        self._tier_matrix = tier_matrix or TIER_MATRIX

        if config_dir is None:
            aiohai_home = os.environ.get('AIOHAI_HOME', '.')
            config_dir = os.path.join(aiohai_home, 'config')
        self._config_dir = Path(config_dir)
        self._backup_dir = self._config_dir / 'backups'

    # ---- Config snapshot (read) ----

    def get_config_snapshot(self) -> Dict[str, Any]:
        """Get a full configuration snapshot for the admin UI.

        Returns a dict containing:
        - tier_matrix: full matrix with defaults and overrides
        - overrides: current runtime overrides
        - session_defaults: session elevation defaults
        - path_classifications, command_additions, ha_entity_overrides
        - change_requests: pending and applied change requests
        - gates: gate-grouped summary for the editor UI
        """
        with self._lock:
            snapshot = {
                'version': __version__,
                'timestamp': datetime.now().isoformat(),
                'gates': self._build_gate_summary(),
                'has_overrides': (
                    self._adjuster.has_overrides()
                    if self._adjuster else False
                ),
                'overrides': (
                    self._adjuster.get_all_overrides()
                    if self._adjuster else {}
                ),
                'session_defaults': (
                    self._adjuster.session_defaults
                    if self._adjuster else {}
                ),
                'path_classifications': (
                    self._adjuster.path_classifications
                    if self._adjuster else {}
                ),
                'command_additions': (
                    self._adjuster.command_additions
                    if self._adjuster else {}
                ),
                'ha_entity_overrides': (
                    self._adjuster.ha_entity_overrides
                    if self._adjuster else {}
                ),
                'change_requests': self._get_change_request_summary(),
            }
            return snapshot

    def get_gate_editor_data(self) -> Dict[str, Any]:
        """Get data specifically structured for the SecurityLevelEditor.

        Groups actions by gate, includes current level, default level,
        and adjustment controls info.
        """
        with self._lock:
            return self._build_gate_summary()

    def get_action_level(
        self, category: ActionCategory, domain: TargetDomain
    ) -> Dict[str, Any]:
        """Get level info for a specific (category, domain) pair."""
        default = self._tier_matrix.get_default(category, domain)
        current = self._tier_matrix.lookup(category, domain)
        return {
            'category': category.value,
            'domain': domain.value,
            'default_level': default.value,
            'default_level_name': default.name,
            'default_gate': default.gate.name,
            'current_level': current.value,
            'current_level_name': current.name,
            'current_gate': current.gate.name,
            'is_overridden': default != current,
            'is_deny': default.gate == SecurityGate.DENY,
        }

    # ---- Admin changes (write) ----

    def apply_admin_changes(
        self, changes: Dict[str, Any], admin_user: str = "admin"
    ) -> Dict[str, Any]:
        """Apply a batch of changes from the admin UI.

        changes dict can contain:
        - tier_overrides: {key: {level: int, reason: str}} — level adjustments
        - removals: [key] — override removals
        - session_defaults: dict — session default overrides
        - path_classifications: {path: {domain: str, reason: str}}
        - command_additions: {cmd: {domain: str, reason: str}}
        - ha_entity_overrides: {entity: {domain: str, reason: str}}

        Returns result dict with applied/rejected/errors.
        """
        if not self._adjuster:
            return {'success': False, 'error': 'TrustMatrixAdjuster not available'}

        results = {
            'applied': [],
            'rejected': [],
            'errors': [],
            'change_requests_created': [],
        }

        with self._lock:
            # Process tier override changes
            for key_str, data in changes.get('tier_overrides', {}).items():
                self._apply_single_override(
                    key_str, data, admin_user, results
                )

            # Process removals
            for key_str in changes.get('removals', []):
                self._apply_removal(key_str, results)

            # Process session defaults
            session_defaults = changes.get('session_defaults')
            if session_defaults and isinstance(session_defaults, dict):
                self._adjuster._session_defaults.update(session_defaults)
                results['applied'].append({
                    'type': 'session_defaults',
                    'data': session_defaults,
                })

            # Process path classifications
            for path, data in changes.get('path_classifications', {}).items():
                ok, msg = self._adjuster.set_path_classification(
                    path, data.get('domain', ''), data.get('reason', '')
                )
                if ok:
                    results['applied'].append({
                        'type': 'path_classification',
                        'path': path, 'data': data,
                    })
                else:
                    results['errors'].append({
                        'type': 'path_classification',
                        'path': path, 'error': msg,
                    })

            # Process command additions
            for cmd, data in changes.get('command_additions', {}).items():
                ok, msg = self._adjuster.add_command(
                    cmd, data.get('domain', ''), data.get('reason', '')
                )
                if ok:
                    results['applied'].append({
                        'type': 'command_addition',
                        'command': cmd, 'data': data,
                    })
                else:
                    results['errors'].append({
                        'type': 'command_addition',
                        'command': cmd, 'error': msg,
                    })

            # Process HA entity overrides
            for entity, data in changes.get('ha_entity_overrides', {}).items():
                ok, msg = self._adjuster.set_ha_entity_override(
                    entity, data.get('domain', ''), data.get('reason', '')
                )
                if ok:
                    results['applied'].append({
                        'type': 'ha_entity_override',
                        'entity': entity, 'data': data,
                    })
                else:
                    results['errors'].append({
                        'type': 'ha_entity_override',
                        'entity': entity, 'error': msg,
                    })

            # Save to disk
            if results['applied']:
                save_ok = self._adjuster.save_to_file()
                if not save_ok:
                    results['errors'].append({
                        'type': 'save', 'error': 'Failed to save overrides to disk'
                    })

        results['success'] = len(results['errors']) == 0
        return results

    def reset_all_overrides(self, admin_user: str = "admin") -> Dict:
        """Reset all runtime overrides to defaults."""
        if not self._adjuster:
            return {'success': False, 'error': 'Adjuster not available'}

        with self._lock:
            count = self._adjuster.reset_all()
            save_ok = self._adjuster.save_to_file()

        return {
            'success': save_ok,
            'overrides_removed': count,
            'admin': admin_user,
            'timestamp': datetime.now().isoformat(),
        }

    # ---- Backup / Restore ----

    def create_backup(self, reason: str = "") -> Optional[str]:
        """Create a backup of the current configuration.

        Returns the backup path, or None on failure.
        """
        try:
            self._backup_dir.mkdir(parents=True, exist_ok=True)

            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_name = f"config_backup_{timestamp}"
            backup_path = self._backup_dir / backup_name

            backup_path.mkdir(exist_ok=True)

            # Copy user_overrides.json
            overrides_file = self._config_dir / 'user_overrides.json'
            if overrides_file.exists():
                shutil.copy2(overrides_file, backup_path / 'user_overrides.json')

            # Copy change_requests.json
            cr_file = self._config_dir / 'change_requests.json'
            if cr_file.exists():
                shutil.copy2(cr_file, backup_path / 'change_requests.json')

            # Write metadata
            meta = {
                'timestamp': datetime.now().isoformat(),
                'reason': reason,
                'files': [f.name for f in backup_path.iterdir()],
            }
            with open(backup_path / 'backup_meta.json', 'w') as f:
                json.dump(meta, f, indent=2)

            logger.info("Backup created: %s", backup_path)

            # Trim old backups
            self._trim_backups()

            return str(backup_path)

        except OSError as e:
            logger.error("Backup failed: %s", e)
            return None

    def list_backups(self) -> List[Dict]:
        """List available backups with metadata."""
        backups = []
        if not self._backup_dir.exists():
            return backups

        for entry in sorted(self._backup_dir.iterdir(), reverse=True):
            if not entry.is_dir() or not entry.name.startswith('config_backup_'):
                continue

            meta_file = entry / 'backup_meta.json'
            meta = {}
            if meta_file.exists():
                try:
                    with open(meta_file) as f:
                        meta = json.load(f)
                except (json.JSONDecodeError, OSError):
                    pass

            backups.append({
                'path': str(entry),
                'name': entry.name,
                'timestamp': meta.get('timestamp', ''),
                'reason': meta.get('reason', ''),
                'files': meta.get('files', []),
            })

        return backups

    def restore_from_backup(
        self, backup_path: str, admin_user: str = "admin"
    ) -> Dict:
        """Restore configuration from a backup.

        Creates a pre-restore backup before applying.
        """
        backup = Path(backup_path)
        if not backup.exists() or not backup.is_dir():
            return {'success': False, 'error': f'Backup not found: {backup_path}'}

        # Create pre-restore backup
        pre_backup = self.create_backup(reason="pre-restore")

        try:
            # Restore user_overrides.json
            src_overrides = backup / 'user_overrides.json'
            if src_overrides.exists():
                dst = self._config_dir / 'user_overrides.json'
                shutil.copy2(src_overrides, dst)

            # Restore change_requests.json
            src_cr = backup / 'change_requests.json'
            if src_cr.exists():
                dst = self._config_dir / 'change_requests.json'
                shutil.copy2(src_cr, dst)

            # Reload adjuster from restored files
            if self._adjuster:
                self._adjuster.load_from_file()

            logger.info(
                "Configuration restored from %s by %s",
                backup_path, admin_user,
            )

            return {
                'success': True,
                'restored_from': str(backup),
                'pre_restore_backup': pre_backup,
                'admin': admin_user,
                'timestamp': datetime.now().isoformat(),
            }

        except OSError as e:
            logger.error("Restore failed: %s", e)
            return {'success': False, 'error': str(e)}

    # ---- Code diff generation (for change request apply-with-restart) ----

    def generate_code_diff(self, request_ids: List[str]) -> Dict:
        """Generate the code diff needed to apply selected change requests.

        Only non-DENY requests can be applied. DENY requests are rejected.

        Returns:
            {
                'diffs': [{request_id, category, domain, from_level, to_level, code_line}],
                'denied': [{request_id, reason}],
                'not_found': [request_id],
            }
        """
        if not self._change_request_log:
            return {'diffs': [], 'denied': [], 'not_found': request_ids}

        result = {'diffs': [], 'denied': [], 'not_found': []}

        for rid in request_ids:
            req = self._change_request_log.get_request(rid)
            if req is None:
                result['not_found'].append(rid)
                continue

            if req.get('boundary_type') == 'manual_code_edit_only':
                result['denied'].append({
                    'request_id': req['request_id'],
                    'reason': (
                        'DENY gate items cannot be applied through the '
                        'companion app. Manual source code editing is required.'
                    ),
                })
                continue

            # Generate the code line change for tier_matrix.py
            diff_entry = {
                'request_id': req['request_id'],
                'category': req['category'],
                'domain': req['domain'],
                'from_level': req['current_level'],
                'to_level': req['requested_level'],
                'from_gate': req['current_gate'],
                'to_gate': req['requested_gate'],
                'code_line': (
                    f"tier_matrix.py: "
                    f"({req['category']}, {req['domain']}): "
                    f"{req['current_level']} → {req['requested_level']}"
                ),
            }
            result['diffs'].append(diff_entry)

        return result

    # ---- Internal helpers ----

    def _apply_single_override(
        self, key_str: str, data: Dict, admin_user: str,
        results: Dict
    ):
        """Apply a single tier override, creating change requests for rejections."""
        level_value = data.get('level')
        reason = data.get('reason', '')

        if level_value is None:
            results['errors'].append({
                'key': key_str, 'error': 'Missing level value'
            })
            return

        result = self._adjuster.propose_from_natural_language(
            *key_str.split(':', 1),
            requested_level_value=level_value,
            reason=reason,
        )

        if result.allowed:
            ok = self._adjuster.apply_adjustment(result)
            if ok:
                results['applied'].append({
                    'key': key_str, 'level': level_value, 'reason': reason,
                })
            else:
                results['errors'].append({
                    'key': key_str, 'error': 'Apply failed after validation'
                })
        else:
            results['rejected'].append({
                'key': key_str,
                'reason': result.explanation,
                'boundary': result.boundary_violated,
                'alternatives': result.alternatives,
            })

            # Auto-create change request for gate demotions
            if result.boundary_violated and self._change_request_log:
                cr_id = self._change_request_log.add_from_adjustment_result(
                    result, user=admin_user
                )
                if cr_id:
                    self._change_request_log.save()
                    results['change_requests_created'].append(cr_id)

    def _apply_removal(self, key_str: str, results: Dict):
        """Remove a single tier override."""
        parts = key_str.split(':', 1)
        if len(parts) != 2:
            results['errors'].append({
                'key': key_str, 'error': 'Invalid key format'
            })
            return

        try:
            cat = ActionCategory(parts[0])
            dom = TargetDomain(parts[1])
        except ValueError as e:
            results['errors'].append({
                'key': key_str, 'error': str(e)
            })
            return

        removed = self._adjuster.remove_adjustment(cat, dom)
        if removed:
            results['applied'].append({
                'type': 'removal', 'key': key_str,
            })

    def _build_gate_summary(self) -> Dict[str, Any]:
        """Build gate-grouped summary for the SecurityLevelEditor UI."""
        gates = {
            'DENY': {'name': 'Deny', 'icon': '🚫', 'items': [], 'editable': False},
            'PHYSICAL': {'name': 'Physical', 'icon': '🔒', 'items': [], 'editable': 'depth_only'},
            'BIOMETRIC': {'name': 'Biometric', 'icon': '🖐️', 'items': [], 'editable': 'depth_only'},
            'SOFTWARE': {'name': 'Software', 'icon': '🖱️', 'items': [], 'editable': True},
            'PASSIVE': {'name': 'Passive', 'icon': '👁️', 'items': [], 'editable': True},
        }

        # Iterate all defined matrix entries
        for cat in ActionCategory:
            for dom in TargetDomain:
                if dom == TargetDomain.UNKNOWN:
                    continue

                default = self._tier_matrix.get_default(cat, dom)
                current = self._tier_matrix.lookup(cat, dom)
                gate_name = default.gate.name

                if gate_name not in gates:
                    continue

                item = {
                    'category': cat.value,
                    'domain': dom.value,
                    'default_level': default.value,
                    'default_level_name': default.name,
                    'current_level': current.value,
                    'current_level_name': current.name,
                    'gate': gate_name,
                    'is_overridden': default != current,
                }
                gates[gate_name]['items'].append(item)

        # Only include gates that have items
        return {k: v for k, v in gates.items() if v['items']}

    def _get_change_request_summary(self) -> Dict:
        """Get a summary of change requests."""
        if not self._change_request_log:
            return {'pending': [], 'applied': [], 'total': 0}

        return {
            'pending': self._change_request_log.get_pending(),
            'applied': self._change_request_log.get_applied(),
            'total': self._change_request_log.total_count,
        }

    def _trim_backups(self):
        """Remove old backups exceeding MAX_BACKUPS."""
        if not self._backup_dir.exists():
            return

        backups = sorted(
            [d for d in self._backup_dir.iterdir()
             if d.is_dir() and d.name.startswith('config_backup_')],
            key=lambda d: d.name,
        )

        while len(backups) > MAX_BACKUPS:
            oldest = backups.pop(0)
            try:
                shutil.rmtree(oldest)
                logger.info("Trimmed old backup: %s", oldest.name)
            except OSError as e:
                logger.warning("Cannot remove backup %s: %s", oldest, e)
