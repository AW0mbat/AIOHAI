#!/usr/bin/env python3
"""
AIOHAI Core Audit — Security Logger
=====================================
Tamper-evident logging with:
- Chain hashing for integrity
- PII redaction (via PIIProtector when available)
- Optional HSM signing for critical entries

Previously defined inline in proxy/aiohai_proxy.py.
Extracted as Phase 1 of the monolith → layered architecture migration.

Import from: aiohai.core.audit.logger
"""

import json
import hashlib
import secrets
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict
from collections import defaultdict

from aiohai.core.types import AlertSeverity
from aiohai.core.constants import SESSION_ID_BYTES


class SecurityLogger:
    """Tamper-evident logging with PII redaction and optional HSM signing."""

    def __init__(self, config, hsm_manager=None):
        self.config = config
        self.log_dir = config.log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.main_log = self.log_dir / "security_events.log"
        self.action_log = self.log_dir / "actions.log"
        self.blocked_log = self.log_dir / "blocked.log"
        self.network_log = self.log_dir / "network.log"
        self.hsm_signed_log = self.log_dir / "hsm_signed.log"

        # HSM integration for log signing
        self.hsm_manager = hsm_manager
        self.hsm_sign_logs = config.hsm_sign_logs and hsm_manager is not None

        self.session_id = self._generate_session_id()
        self.entry_counter = 0
        self.previous_hash = "0" * 64
        self.stats = defaultdict(int)

        # PII protector for log sanitization — lazy import to avoid circular deps
        self.pii_protector = None
        try:
            from security.security_components import PIIProtector
            self.pii_protector = PIIProtector()
        except ImportError:
            pass

        logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s')
        self.logger = logging.getLogger('AIOHAI')

    def _generate_session_id(self) -> str:
        """Generate session ID using HSM if available, else software."""
        if self.hsm_manager and self.hsm_manager.is_connected():
            return self.hsm_manager.generate_token(SESSION_ID_BYTES)
        return secrets.token_hex(SESSION_ID_BYTES)

    def set_hsm_manager(self, hsm_manager) -> None:
        """Set HSM manager after initialization (for late binding)."""
        self.hsm_manager = hsm_manager
        self.hsm_sign_logs = self.config.hsm_sign_logs and hsm_manager is not None
        # Regenerate session ID with HSM
        if self.hsm_manager and self.hsm_manager.is_connected():
            self.session_id = self.hsm_manager.generate_token(SESSION_ID_BYTES)

    def _sanitize(self, text: str) -> str:
        """Sanitize text for logging (remove PII)."""
        if self.pii_protector:
            return self.pii_protector.redact_for_logging(text)
        return text

    def _chain_hash(self, entry: str) -> str:
        return hashlib.sha256(f"{self.previous_hash}:{entry}".encode()).hexdigest()

    def _write(self, log_file: Path, entry: Dict):
        self.entry_counter += 1
        entry.update({
            'timestamp': datetime.now().isoformat(),
            'session_id': self.session_id,
            'sequence': self.entry_counter
        })
        entry_str = json.dumps(entry, sort_keys=True)
        entry['chain_hash'] = self._chain_hash(entry_str)
        self.previous_hash = entry['chain_hash']

        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry) + '\n')

        # Also create HSM-signed entry for critical logs
        if self.hsm_sign_logs and entry.get('severity') in ('HIGH', 'CRITICAL'):
            self._write_hsm_signed(entry)

    def _write_hsm_signed(self, entry: Dict):
        """Write an HSM-signed log entry for tamper evidence."""
        if not self.hsm_manager or not self.hsm_manager.is_connected():
            return

        try:
            signed_entry = self.hsm_manager.sign_log_entry(entry)
            if signed_entry:
                with open(self.hsm_signed_log, 'a', encoding='utf-8') as f:
                    signed_data = {
                        'timestamp': signed_entry.timestamp,
                        'event_type': signed_entry.event_type,
                        'data': signed_entry.data,
                        'entry_hash': signed_entry.entry_hash,
                        'signature': signed_entry.signature,
                        'previous_hash': signed_entry.previous_hash,
                    }
                    f.write(json.dumps(signed_data) + '\n')
        except Exception as e:
            self.logger.warning(f"HSM log signing failed: {e}")

    def log_event(self, event: str, severity: AlertSeverity, details: Dict = None) -> None:
        # Sanitize details
        if details:
            details = {k: self._sanitize(str(v)) if isinstance(v, str) else v
                      for k, v in details.items()}

        self._write(self.main_log, {'event': event, 'severity': severity.value, 'details': details or {}})
        self.stats[f'{severity.value}_{event}'] += 1

        if severity in (AlertSeverity.HIGH, AlertSeverity.CRITICAL):
            self.logger.warning(f"[{severity.value.upper()}] {event}")

    def log_action(self, action: str, target: str, result: str, details: Dict = None) -> None:
        target = self._sanitize(target[:200])
        result = self._sanitize(result[:500]) if result else ""
        self._write(self.action_log, {'action': action, 'target': target, 'result': result,
                                       'details': details or {}})
        self.logger.info(f"ACTION: {action} | {result}")

    def log_blocked(self, action: str, target: str, reason: str) -> None:
        target = self._sanitize(target[:200])
        self._write(self.blocked_log, {'action': action, 'target': target, 'reason': reason})
        self.stats['blocked'] += 1
        self.logger.warning(f"BLOCKED: {action} | {reason}")

    def log_network(self, destination: str, action: str, details: Dict = None) -> None:
        self._write(self.network_log, {'destination': destination, 'action': action,
                                        'details': details or {}})


__all__ = ['SecurityLogger']
