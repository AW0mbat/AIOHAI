#!/usr/bin/env python3
"""
AIOHAI Core Crypto — Credential Management
===========================================
Provides credential storage for WebAuthn/FIDO2:
- CredentialStore: Thread-safe persistent storage for WebAuthn credentials

Also re-exports CredentialRedactor from aiohai.core.analysis for convenience.

Previously:
- CredentialStore was defined in security/fido2_approval.py
- CredentialRedactor was defined in security/security_components.py (now in aiohai.core.analysis)

Extracted as Phase 3 of the monolith → layered architecture migration.

Import from: aiohai.core.crypto.credentials
"""

import json
import os
import logging
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional, List, Tuple

from aiohai.core.types import (
    ApprovalTier,
    UserRole,
    RegisteredCredential,
    RegisteredUser,
)

logger = logging.getLogger("aiohai.core.crypto.credentials")


class CredentialStore:
    """Thread-safe persistent storage for WebAuthn credentials."""

    def __init__(self, storage_path: Path):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.users_file = self.storage_path / "users.json"
        self.lock = threading.Lock()
        self._users: Dict[str, RegisteredUser] = {}
        self._load()

    def _load(self):
        """Load registered users from disk."""
        if self.users_file.exists():
            try:
                data = json.loads(self.users_file.read_text(encoding='utf-8'))
                for username, user_data in data.items():
                    self._users[username] = RegisteredUser.from_dict(user_data)
                logger.info(f"Loaded {len(self._users)} registered users")
            except Exception as e:
                logger.error(f"Failed to load credentials: {e}")

    def _save(self):
        """Atomically save registered users to disk."""
        try:
            data = {name: user.to_dict() for name, user in self._users.items()}
            tmp = self.users_file.with_suffix('.tmp')
            tmp.write_text(json.dumps(data, indent=2), encoding='utf-8')
            tmp.replace(self.users_file)
        except Exception as e:
            logger.error(f"Failed to save credentials: {e}")

    def add_user(self, username: str, role: UserRole,
                 allowed_paths: List[str] = None) -> RegisteredUser:
        """Create a new user with the given role."""
        with self.lock:
            if username in self._users:
                raise ValueError(f"User '{username}' already exists")
            user = RegisteredUser(
                user_id=os.urandom(32),
                username=username,
                role=role,
                created_at=datetime.now().isoformat(),
                allowed_paths=allowed_paths or [],
            )
            self._users[username] = user
            self._save()
            logger.info(f"Created user: {username} ({role.value})")
            return user

    def get_user(self, username: str) -> Optional[RegisteredUser]:
        """Get a user by username."""
        with self.lock:
            return self._users.get(username)

    def get_all_users(self) -> Dict[str, RegisteredUser]:
        """Get a copy of all registered users."""
        with self.lock:
            return self._users.copy()

    def add_credential(self, username: str,
                       credential: RegisteredCredential) -> bool:
        """Add a WebAuthn credential to an existing user."""
        with self.lock:
            user = self._users.get(username)
            if not user:
                return False
            user.credentials.append(credential)
            self._save()
            logger.info(f"Added credential to {username}: {credential.device_name}")
            return True

    def update_credential_counter(self, credential_id: bytes,
                                   new_count: int) -> bool:
        """Update the sign counter for a credential (replay protection)."""
        with self.lock:
            for user in self._users.values():
                for cred in user.credentials:
                    if cred.credential_id == credential_id:
                        cred.sign_count = new_count
                        cred.last_used = datetime.now().isoformat()
                        self._save()
                        return True
            return False

    def get_credentials_for_user(self, username: str) -> List[RegisteredCredential]:
        """Get all credentials for a user."""
        with self.lock:
            user = self._users.get(username)
            return list(user.credentials) if user else []

    def remove_user(self, username: str) -> bool:
        """Remove a user and all their credentials."""
        with self.lock:
            if username in self._users:
                del self._users[username]
                self._save()
                return True
            return False

    def user_can_approve(self, username: str, tier: ApprovalTier,
                          target: str = "") -> Tuple[bool, str]:
        """Check if a user has permission to approve at the given tier.
        
        Returns:
            Tuple of (allowed: bool, reason: str)
        """
        user = self._users.get(username)
        if not user:
            return False, "User not found"

        role_max = {
            UserRole.ADMIN: ApprovalTier.TIER_4,
            UserRole.TRUSTED_ADULT: ApprovalTier.TIER_3,
            UserRole.RESTRICTED: ApprovalTier.TIER_3,
            UserRole.GUEST: ApprovalTier.TIER_2,
        }
        max_tier = role_max.get(user.role, ApprovalTier.TIER_1)
        if tier.value > max_tier.value:
            return False, f"Role '{user.role.value}' cannot approve TIER {tier.value}"

        if user.role == UserRole.RESTRICTED and target:
            if not any(target.startswith(p) for p in user.allowed_paths):
                return False, f"Restricted user cannot approve: {target}"

        return True, "Allowed"


# Re-export CredentialRedactor from analysis layer for convenience
try:
    from aiohai.core.analysis.credentials import CredentialRedactor
except ImportError:
    # Stub if analysis layer not available
    class CredentialRedactor:
        """Stub - analysis layer not available."""
        def redact(self, text):
            return text
        def redact_for_preview(self, text, max_length=100):
            if len(text) > max_length:
                return text[:max_length] + '...'
            return text


__all__ = [
    'CredentialStore',
    'CredentialRedactor',
    'RegisteredCredential',
    'RegisteredUser',
]
