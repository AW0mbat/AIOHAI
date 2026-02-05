"""
AIOHAI Configuration — UnifiedConfig
======================================
Central configuration dataclass with defaults for all proxy settings.

Previously defined inline in proxy/aiohai_proxy.py.
Extracted as Phase 1 of the monolith → layered architecture migration.

Import from: aiohai.core.config
"""

import os
from pathlib import Path
from typing import Set, List
from dataclasses import dataclass, field

from aiohai.core.version import POLICY_FILENAME
from aiohai.core.constants import WHITELISTED_EXECUTABLES


@dataclass
class UnifiedConfig:
    listen_host: str = "127.0.0.1"
    listen_port: int = 11435
    ollama_host: str = "127.0.0.1"
    ollama_port: int = 11434

    base_dir: Path = field(default_factory=lambda: Path(os.environ.get('AIOHAI_HOME', r'C:\AIOHAI')))
    policy_file: Path = None
    policy_signature_file: Path = None  # HSM signature
    log_dir: Path = None
    secure_temp_dir: Path = None

    refuse_admin: bool = True
    verify_dll_integrity: bool = True
    inject_system_prompt: bool = True
    scan_for_injection: bool = True
    enforce_network_allowlist: bool = True
    scan_file_content: bool = True
    enable_dual_llm: bool = False
    allow_degraded_security: bool = False  # If True, allow startup without security components

    # HSM Configuration
    hsm_enabled: bool = True
    hsm_required: bool = True
    hsm_use_mock: bool = False
    hsm_pin: str = ""
    hsm_sign_logs: bool = True

    # FIDO2/WebAuthn Configuration
    fido2_enabled: bool = True
    fido2_server_port: int = 8443
    fido2_server_host: str = "0.0.0.0"
    fido2_config_path: str = ""
    fido2_auto_start_server: bool = True
    fido2_poll_timeout: int = 300
    fido2_poll_interval: float = 1.0

    command_timeout: int = 30
    max_file_size_mb: int = 100
    max_output_length: int = 50000
    rate_limit_per_minute: int = 60
    max_concurrent_actions: int = 5
    approval_expiry_minutes: int = 5

    allowed_drives: Set[str] = field(default_factory=lambda: {'C:', 'D:', 'E:'})
    whitelisted_executables: Set[str] = field(default_factory=lambda: WHITELISTED_EXECUTABLES.copy())
    network_allowlist: List[str] = field(default_factory=lambda: [
        'localhost', '127.0.0.1',
        'github.com', 'api.github.com',
        'pypi.org', 'files.pythonhosted.org',
    ])

    max_dns_query_length: int = 100
    max_dns_entropy: float = 4.5
    enable_desktop_alerts: bool = True

    def __post_init__(self):
        if self.policy_file is None:
            self.policy_file = self.base_dir / "policy" / POLICY_FILENAME
        if self.policy_signature_file is None:
            self.policy_signature_file = self.base_dir / "policy" / "policy.sig"
        if self.log_dir is None:
            self.log_dir = self.base_dir / "logs"
        if self.secure_temp_dir is None:
            self.secure_temp_dir = self.base_dir / "temp"
        if not self.fido2_config_path:
            self.fido2_config_path = str(self.base_dir / "config" / "fido2_config.json")


__all__ = ['UnifiedConfig']
