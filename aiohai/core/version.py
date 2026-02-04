"""
AIOHAI Core — Version Constants

Single source of truth for all version-related values.
Import from here instead of hardcoding versions elsewhere.

Usage:
    from aiohai.core.version import __version__, POLICY_FILENAME
    from aiohai.core.version import ALLOWED_FRAMEWORK_NAMES
"""

# =============================================================================
# PACKAGE VERSION
# =============================================================================

# The official AIOHAI package version
# Update this when releasing new versions
__version__ = "4.0.0"


# =============================================================================
# POLICY FILE
# =============================================================================

# Policy filename - change here when policy version changes
# This is the ONLY place this filename should be defined
POLICY_FILENAME = "aiohai_security_policy_v3.0.md"


# =============================================================================
# CONFIG SCHEMA
# =============================================================================

# Config schema version (separate from package version)
# This tracks the config.json structure, not the code
# Only increment when config.json structure changes
CONFIG_SCHEMA_VERSION = "3.0"


# =============================================================================
# FRAMEWORK ALLOWLIST
# =============================================================================

# Security-critical allowlist of framework files that can be loaded
# Add new framework versions here when created
# This MUST remain in code (not config) to prevent config tampering
# from loading malicious framework files
ALLOWED_FRAMEWORK_NAMES = frozenset({
    'ha_framework_v3.md',
    'office_framework_v3.md',
    'ha_framework_v4.md',
    'office_framework_v4.md',
})


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    '__version__',
    'POLICY_FILENAME',
    'CONFIG_SCHEMA_VERSION',
    'ALLOWED_FRAMEWORK_NAMES',
]
