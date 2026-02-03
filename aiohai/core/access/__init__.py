"""
Access Control — Path validation, command validation, session management.

Submodules:
- path_validator: Two-tier path validation (blocked + Tier 3 FIDO2-gated)
- command_validator: Shell command validation with obfuscation detection
- session_manager: Human-in-the-loop approval queue (generalized ApprovalManager)

Classes:
- PathValidator: Two-tier path validation (blocked + Tier 3 FIDO2-gated)
- CommandValidator: Shell command validation with obfuscation detection
- SessionManager/ApprovalManager: Human-in-the-loop approval queue
"""

from aiohai.core.access.path_validator import (
    PathValidator,
    BLOCKED_PATH_PATTERNS,
    TIER3_PATH_PATTERNS,
)

from aiohai.core.access.command_validator import (
    CommandValidator,
    BLOCKED_COMMAND_PATTERNS,
    UAC_BYPASS_PATTERNS,
    WHITELISTED_EXECUTABLES,
    DOCKER_COMMAND_TIERS,
)

from aiohai.core.access.session_manager import (
    ApprovalManager,
    SessionManager,
)

__all__ = [
    # Path validation
    'PathValidator',
    'BLOCKED_PATH_PATTERNS',
    'TIER3_PATH_PATTERNS',
    
    # Command validation
    'CommandValidator',
    'BLOCKED_COMMAND_PATTERNS',
    'UAC_BYPASS_PATTERNS',
    'WHITELISTED_EXECUTABLES',
    'DOCKER_COMMAND_TIERS',
    
    # Session management
    'ApprovalManager',
    'SessionManager',
]
