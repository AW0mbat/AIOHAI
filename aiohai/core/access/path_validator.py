#!/usr/bin/env python3
"""
AIOHAI Core Access — Path Validator
=====================================
Two-tier path validation:
1. Hard blocks: Attack infrastructure, credential stores, OS internals
2. Tier 3 gates: Sensitive personal data requiring FIDO2 approval

Also blocks: UNC paths, device paths, ADS, path traversal, symlink evasion.
Resolves Windows short filenames (8.3) to long names before checking.

Previously defined inline in proxy/aiohai_proxy.py.
Extracted as Phase 2a of the monolith → layered architecture migration.

Import from: aiohai.core.access.path_validator
"""

import os
import re
from typing import Tuple

from aiohai.core.constants import IS_WINDOWS
from aiohai.core.patterns import BLOCKED_PATH_PATTERNS, TIER3_PATH_PATTERNS

# Optional Windows imports
if IS_WINDOWS:
    try:
        import win32api
        import win32file
        _PYWIN32_AVAILABLE = True
    except ImportError:
        _PYWIN32_AVAILABLE = False
else:
    _PYWIN32_AVAILABLE = False


class PathValidator:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.blocked_patterns = [re.compile(p, re.I) for p in BLOCKED_PATH_PATTERNS]
        self.tier3_patterns = [re.compile(p, re.I) for p in TIER3_PATH_PATTERNS]

    def validate(self, path: str) -> Tuple[bool, str, str]:
        """Validate a path. Returns (allowed, resolved_path, reason).

        Three possible outcomes:
          - (False, path, "Blocked pattern")  → hard block, no approval possible
          - (True,  path, "Tier 3 required")  → allowed only with FIDO2 approval
          - (True,  path, "OK")               → normal tier classification
        """
        try:
            if path.startswith('\\\\'):
                return False, path, "UNC paths blocked"
            if path.startswith('\\\\.\\') or path.startswith('\\\\?\\'):
                return False, path, "Device paths blocked"

            # ADS check
            path_no_drive = path[2:] if len(path) >= 2 and path[1] == ':' else path
            if ':' in path_no_drive:
                return False, path, "ADS blocked"

            # Convert short names
            if IS_WINDOWS and _PYWIN32_AVAILABLE and os.path.exists(path):
                try:
                    path = win32api.GetLongPathName(path)
                except Exception:
                    pass  # Short name conversion failed, use original path

            resolved = os.path.abspath(os.path.normpath(os.path.realpath(path)))

            if '..' in path:
                return False, resolved, "Path traversal"

            if IS_WINDOWS:
                drive = os.path.splitdrive(resolved)[0].upper()
                if drive and drive not in self.config.allowed_drives:
                    return False, resolved, f"Drive {drive} not allowed"

            # Check hard blocks first
            for pattern in self.blocked_patterns:
                if pattern.search(resolved):
                    return False, resolved, "Blocked pattern"

            # Check tier-3 patterns (allowed, but requires hardware approval)
            for pattern in self.tier3_patterns:
                if pattern.search(resolved):
                    return True, resolved, "Tier 3 required"

            # Symlink check (resolve and re-check both block lists)
            if IS_WINDOWS and _PYWIN32_AVAILABLE and os.path.exists(resolved):
                try:
                    attrs = win32file.GetFileAttributes(resolved)
                    if attrs & 0x400:  # REPARSE_POINT
                        target = os.path.realpath(resolved)
                        for pattern in self.blocked_patterns:
                            if pattern.search(target):
                                return False, resolved, "Symlink target blocked"
                        for pattern in self.tier3_patterns:
                            if pattern.search(target):
                                return True, resolved, "Tier 3 required"
                except Exception:
                    pass  # Attribute check failed, allow path through

            return True, resolved, "OK"
        except Exception as e:
            return False, path, f"Error: {e}"


__all__ = [
    'PathValidator',
    'BLOCKED_PATH_PATTERNS',
    'TIER3_PATH_PATTERNS',
]
