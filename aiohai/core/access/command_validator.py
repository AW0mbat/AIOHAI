#!/usr/bin/env python3
"""
AIOHAI Core Access — Command Validator
========================================
Shell command validation with:
- Blocked patterns (encoded PowerShell, credential theft, persistence)
- UAC bypass detection
- Executable whitelist enforcement
- Obfuscation detection (string concatenation, char codes, base64)
- Docker command tier classification (standard/elevated/critical/blocked)
- Optional macro execution blocking via MacroBlocker

Previously defined inline in proxy/aiohai_proxy.py.
Extracted as Phase 2a of the monolith → layered architecture migration.

Import from: aiohai.core.access.command_validator
"""

import os
import re
import shlex
from typing import Tuple, List

from aiohai.core.patterns import BLOCKED_COMMAND_PATTERNS, UAC_BYPASS_PATTERNS
from aiohai.core.constants import WHITELISTED_EXECUTABLES, DOCKER_COMMAND_TIERS


class CommandValidator:
    def __init__(self, config, logger, macro_blocker=None):
        self.config = config
        self.logger = logger
        self.blocked_patterns = [re.compile(p, re.I) for p in BLOCKED_COMMAND_PATTERNS]
        self.uac_patterns = [re.compile(p, re.I) for p in UAC_BYPASS_PATTERNS]
        self.macro_blocker = macro_blocker

    def validate(self, command: str) -> Tuple[bool, str]:
        # Blocked patterns
        for pattern in self.blocked_patterns:
            if pattern.search(command):
                return False, f"Blocked: {pattern.pattern[:40]}"

        # UAC bypass
        for pattern in self.uac_patterns:
            if pattern.search(command):
                return False, "UAC bypass pattern"

        # OFFICE: Block macro execution commands (VBScript, CScript, Office /m switches)
        if self.macro_blocker:
            macro_ok, macro_reason = self.macro_blocker.check_command_for_macro_execution(command)
            if not macro_ok:
                return False, macro_reason

        # Parse executable
        try:
            args = shlex.split(command)
            if not args:
                return False, "Empty command"

            exe = os.path.basename(args[0]).lower()
            if exe not in self.config.whitelisted_executables:
                return False, f"Not whitelisted: {exe}"

            # Docker-specific tier validation
            if exe in ('docker', 'docker.exe', 'docker-compose', 'docker-compose.exe'):
                tier_ok, tier_reason = self._validate_docker_command(args)
                if not tier_ok:
                    return False, tier_reason
        except Exception as e:
            return False, f"Parse error: {e}"

        # Obfuscation check
        if self._is_obfuscated(command):
            return False, "Obfuscation detected"

        return True, "OK"

    def get_docker_tier(self, command: str) -> str:
        """Return the tier classification for a docker command."""
        try:
            args = shlex.split(command)
            exe = os.path.basename(args[0]).lower()
            if exe not in ('docker', 'docker.exe', 'docker-compose', 'docker-compose.exe'):
                return 'unknown'
            return self._classify_docker_subcommand(args)
        except Exception:
            return 'unknown'

    def _validate_docker_command(self, args: List[str]) -> Tuple[bool, str]:
        """Validate docker command against tier system."""
        tier = self._classify_docker_subcommand(args)
        subcommand = ' '.join(args[1:3]) if len(args) > 1 else '(none)'

        if tier == 'blocked':
            self.logger.log_blocked("DOCKER_COMMAND", subcommand, "Docker subcommand not permitted")
            return False, f"Docker '{subcommand}' is blocked (tier: blocked)"

        # standard, elevated, critical all pass validation
        # (approval UI handles the tier display)
        return True, f"Docker tier: {tier}"

    def _classify_docker_subcommand(self, args: List[str]) -> str:
        """Classify a docker command into its tier."""
        if len(args) < 2:
            return 'standard'  # Bare 'docker' with no args

        exe = os.path.basename(args[0]).lower()

        # docker-compose commands
        if exe in ('docker-compose', 'docker-compose.exe'):
            check_cmd = args[1].lower() if len(args) > 1 else ''
        else:
            # docker commands: handle 'docker compose' (new CLI) vs 'docker <cmd>'
            check_cmd = args[1].lower() if len(args) > 1 else ''

        # Check two-word commands first (e.g., 'compose up', 'network ls')
        if len(args) > 2:
            two_word = f"{args[1].lower()} {args[2].lower()}"
            for tier_name in ('blocked', 'critical', 'elevated', 'standard'):
                if two_word in DOCKER_COMMAND_TIERS[tier_name]:
                    return tier_name

        # Check single-word command
        for tier_name in ('blocked', 'critical', 'elevated', 'standard'):
            if check_cmd in DOCKER_COMMAND_TIERS[tier_name]:
                return tier_name

        return 'elevated'  # Unknown commands default to elevated

    def _is_obfuscated(self, cmd: str) -> bool:
        if len(cmd) < 20:
            return False
        indicators = 0

        special = len(re.findall(r'[`$\[\]{}()\\^]', cmd))
        if len(cmd) > 0 and special / len(cmd) > 0.15:
            indicators += 1
        if re.search(r'["\'][^"\']{1,10}["\']\s*\+\s*["\']', cmd):
            indicators += 1
        if re.search(r'\$\w+\s*=\s*["\'].*["\']\s*;', cmd):
            indicators += 1
        if re.search(r'\[char\]|\[int\].*-join', cmd, re.I):
            indicators += 1
        if cmd.count('^') > 5:
            indicators += 1
        if re.search(r'[A-Za-z0-9+/]{40,}={0,2}', cmd):
            indicators += 1

        return indicators >= 2


__all__ = [
    'CommandValidator',
    'BLOCKED_COMMAND_PATTERNS',
    'UAC_BYPASS_PATTERNS',
    'WHITELISTED_EXECUTABLES',
    'DOCKER_COMMAND_TIERS',
]
