#!/usr/bin/env python3
"""
AIOHAI Core Audit — Integrity Verifier
========================================
File integrity monitoring with:
- SHA-256 hashing of policy and framework files at startup
- Background re-check thread for runtime tampering detection
- Lockdown mode — proxy refuses all requests on tampering

Previously defined inline in proxy/aiohai_proxy.py.
Extracted as Phase 2a of the monolith → layered architecture migration.

Import from: aiohai.core.audit.integrity
"""

import time
import hashlib
import threading
from pathlib import Path

from aiohai.core.types import AlertSeverity
from aiohai.core.version import ALLOWED_FRAMEWORK_NAMES
from aiohai.core.constants import HASH_CHUNK_SIZE


class IntegrityVerifier:
    # Default check interval (seconds) — short enough to limit tampering window
    DEFAULT_INTERVAL = 10

    def __init__(self, config, logger, alerts):
        self.config = config
        self.logger = logger
        self.alerts = alerts
        self.policy_hash = None
        self.framework_hashes = {}  # {filename: hash} for framework files
        self.running = False
        self.thread = None
        self.lockdown = False  # Set True on tampering — blocks new requests
        self._tampering_detected_at = None

    @property
    def is_locked_down(self) -> bool:
        return self.lockdown

    def compute_hash(self, path: Path) -> str:
        sha256 = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(HASH_CHUNK_SIZE), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    def verify_policy(self) -> bool:
        if not self.config.policy_file.exists():
            self.alerts.alert(AlertSeverity.CRITICAL, "POLICY_MISSING",
                            f"Policy not found: {self.config.policy_file}")
            self._enter_lockdown("Policy file missing")
            return False

        current = self.compute_hash(self.config.policy_file)

        if self.policy_hash is None:
            self.policy_hash = current
            self.logger.log_event("POLICY_LOADED", AlertSeverity.INFO, {'hash': current[:16]})
            # Also hash framework files on first call
            self._hash_frameworks()
            return True

        if current != self.policy_hash:
            self.alerts.alert(AlertSeverity.CRITICAL, "POLICY_TAMPERING", "Policy modified!")
            self._enter_lockdown("Policy hash mismatch")
            return False

        # Also verify framework hashes on every check
        if not self._verify_frameworks():
            return False

        return True

    def _hash_frameworks(self):
        """Compute and store initial hashes for all allowed framework files."""
        policy_dir = self.config.policy_file.parent
        for fw_file in sorted(policy_dir.glob('*_framework_*.md')):
            if fw_file.name in ALLOWED_FRAMEWORK_NAMES:
                try:
                    h = self.compute_hash(fw_file)
                    self.framework_hashes[fw_file.name] = h
                    self.logger.log_event("FRAMEWORK_HASH_RECORDED", AlertSeverity.INFO,
                                          {'file': fw_file.name, 'hash': h[:16]})
                except Exception as e:
                    self.logger.log_event("FRAMEWORK_HASH_ERROR", AlertSeverity.WARNING,
                                          {'file': fw_file.name, 'error': str(e)})

    def _verify_frameworks(self) -> bool:
        """Verify framework file hashes haven't changed.

        Detects:
        - Modified framework files (hash mismatch → lockdown)
        - Deleted framework files that were present at startup (missing → lockdown)
        - New framework files are handled by _load_frameworks allowlist
        """
        policy_dir = self.config.policy_file.parent
        for fname, expected_hash in self.framework_hashes.items():
            fw_path = policy_dir / fname
            if not fw_path.exists():
                self.alerts.alert(AlertSeverity.CRITICAL, "FRAMEWORK_DELETED",
                                  f"Framework file removed: {fname}")
                self._enter_lockdown(f"Framework file deleted: {fname}")
                return False
            try:
                current = self.compute_hash(fw_path)
                if current != expected_hash:
                    self.alerts.alert(AlertSeverity.CRITICAL, "FRAMEWORK_TAMPERING",
                                      f"Framework modified: {fname}")
                    self._enter_lockdown(f"Framework hash mismatch: {fname}")
                    return False
            except Exception as e:
                self.alerts.alert(AlertSeverity.HIGH, "FRAMEWORK_VERIFY_ERROR",
                                  f"Cannot verify {fname}: {e}")
                self._enter_lockdown(f"Framework verification failed: {fname}")
                return False
        return True

    def _enter_lockdown(self, reason: str):
        """Enter lockdown mode — proxy should refuse all new requests."""
        if not self.lockdown:
            self.lockdown = True
            self._tampering_detected_at = time.time()
            self.logger.log_event("LOCKDOWN_ACTIVATED", AlertSeverity.CRITICAL, {
                'reason': reason,
            })
            print(f"\n{'='*70}")
            print(f"\U0001f6a8 LOCKDOWN: {reason}")
            print(f"   All new requests will be rejected until restart.")
            print(f"{'='*70}\n")

    def start_monitoring(self, interval: int = None) -> None:
        interval = interval or self.DEFAULT_INTERVAL
        self.running = True
        self.thread = threading.Thread(target=self._loop, args=(interval,), daemon=True)
        self.thread.start()

    def stop_monitoring(self) -> None:
        self.running = False

    def _loop(self, interval: int):
        while self.running:
            time.sleep(interval)
            self.verify_policy()


__all__ = ['IntegrityVerifier', 'ALLOWED_FRAMEWORK_NAMES']
