"""
AIOHAI Constants — Numeric Values, Limits, and Configuration
=============================================================
Non-pattern constants used across the proxy. Token sizes, intervals,
executable whitelists, Docker command tiers.

Import from: aiohai.core.constants
"""

import sys

# =============================================================================
# PLATFORM DETECTION
# =============================================================================

IS_WINDOWS = sys.platform == 'win32'

# =============================================================================
# TOKEN / CRYPTO SIZES (bytes of randomness)
# =============================================================================

SESSION_ID_BYTES = 8            # 16 hex chars for session IDs
APPROVAL_ID_BYTES = 8           # 16 hex chars for approval IDs
API_SECRET_BYTES = 32           # 64 hex chars for API secrets
CHALLENGE_TOKEN_BYTES = 16      # 32 hex chars for FIDO2 challenge sessions
REQUEST_ID_URL_BYTES = 16       # ~22 URL-safe chars for approval request IDs

# =============================================================================
# FILE I/O
# =============================================================================

HASH_CHUNK_SIZE = 8192          # Bytes per read when hashing files

# =============================================================================
# MONITORING INTERVALS (seconds)
# =============================================================================

HSM_HEALTH_CHECK_INTERVAL = 30
APPROVAL_CLEANUP_AGE_MINUTES = 30

# =============================================================================
# HTTP / NETWORK
# =============================================================================

FIDO2_CLIENT_MAX_RETRIES = 3
FIDO2_CLIENT_RETRY_BACKOFF = 0.5    # Doubles each retry

# =============================================================================
# ENVIRONMENT
# =============================================================================

# Safe environment variables (reduced — USERNAME removed for privacy)
SAFE_ENV_VARS = {
    'PATH', 'SYSTEMROOT', 'SYSTEMDRIVE', 'WINDIR',
    'NUMBER_OF_PROCESSORS', 'PROCESSOR_ARCHITECTURE', 'OS', 'PATHEXT', 'COMSPEC',
}

# =============================================================================
# EXECUTABLE WHITELIST
# =============================================================================

# SECURITY-CRITICAL: This is in code, not config.json, intentionally.
# An attacker with config write access cannot weaken the whitelist.
WHITELISTED_EXECUTABLES = {
    'cmd.exe',
    # SECURITY FIX (F-007/F-008): powershell.exe, pwsh.exe, and explorer.exe removed.
    # powershell.exe can bypass command pattern blocking with creative encoding.
    # explorer.exe can open URLs (bypassing network interceptor) and launch arbitrary files.
    'python.exe', 'python3.exe', 'pip.exe',
    'git.exe', 'node.exe', 'npm.cmd', 'code.cmd',
    'notepad.exe',
    'docker', 'docker.exe', 'docker-compose', 'docker-compose.exe',
    'dir', 'echo', 'type', 'cd', 'cls', 'copy', 'move', 'del',
    'mkdir', 'rmdir', 'ren', 'find', 'findstr', 'sort', 'more', 'tree',
    'ipconfig', 'ping', 'netstat', 'hostname', 'whoami',
    'systeminfo', 'tasklist', 'date', 'time', 'ver', 'set', 'where',
}

# =============================================================================
# DOCKER COMMAND TIERS
# =============================================================================

DOCKER_COMMAND_TIERS = {
    'standard': {
        'ps', 'images', 'inspect', 'logs', 'stats', 'top', 'port',
        'version', 'info', 'network ls', 'network inspect',
        'volume ls', 'volume inspect', 'compose ps', 'compose logs',
        'compose config', 'compose ls',
    },
    'elevated': {
        'start', 'stop', 'restart', 'pause', 'unpause',
        'pull', 'create', 'run', 'exec',
        'compose up', 'compose down', 'compose start', 'compose stop',
        'compose restart', 'compose pull', 'compose build',
        'compose exec', 'compose run', 'compose create',
        'network create', 'network connect', 'network disconnect',
        'volume create',
    },
    'critical': {
        'rm', 'rmi', 'system prune', 'volume rm', 'volume prune',
        'network rm', 'network prune', 'image prune', 'container prune',
        'compose rm', 'builder prune',
    },
    'blocked': {
        'save', 'load', 'export', 'import', 'commit', 'push',
        'login', 'logout', 'trust', 'manifest', 'buildx',
        'swarm', 'service', 'stack', 'secret', 'config create',
    },
}
