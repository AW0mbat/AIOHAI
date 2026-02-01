#!/usr/bin/env python3
"""
AIOHAI Unified Agentic Proxy v3.0
====================================
Complete security layer with ALL audit fixes implemented:

CRITICAL FIXES:
- Hex/Unicode/Compression obfuscation detection
- File content scanning before write
- Child process network isolation
- Comprehensive persistence detection
- DNS-over-HTTPS blocking

HIGH FIXES:
- Static security analyzer integration
- Dual-LLM verification
- PII protection in logs and responses
- Resource limiting (DoS protection)
- Multi-stage attack detection

ARCHITECTURE:
    Open WebUI ──► This Proxy ──► Ollama
                      │
                      ├── StartupSecurityVerifier
                      ├── IntegrityVerifier  
                      ├── NetworkInterceptor (socket hooks + DoH blocking)
                      ├── ContentSanitizer (enhanced)
                      ├── StaticSecurityAnalyzer (Bandit-style)
                      ├── PIIProtector
                      ├── ResourceLimiter
                      ├── MultiStageDetector
                      ├── DualLLMVerifier (optional)
                      ├── PathValidator
                      ├── CommandValidator (enhanced)
                      ├── ApprovalManager (timing-safe)
                      └── SecureExecutor

Author: Security-First LLM Project
Version: 3.0.0
"""

import os
import sys
import json
import hashlib
import hmac
import time
import threading
import subprocess
import shlex
import shutil
import re
import logging
import secrets
import argparse
import queue
import math
import socket
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any, Set
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import urllib.request
import urllib.parse
import urllib.error

# Import security components
try:
    from security.security_components import (
        StaticSecurityAnalyzer, PIIProtector, ResourceLimiter,
        DualLLMVerifier, MultiStageDetector, ResourceLimitExceeded,
        Severity, Verdict, SmartHomeConfigAnalyzer, SecureDockerComposeGenerator,
        CredentialRedactor, SensitiveOperationDetector, SessionTransparencyTracker,
        FamilyAccessControl, FamilyMember,
        FINANCIAL_PATH_PATTERNS, CLIPBOARD_BLOCK_PATTERNS, TRUSTED_DOCKER_REGISTRIES
    )
    SECURITY_COMPONENTS_AVAILABLE = True
except ImportError as _sec_import_err:
    SECURITY_COMPONENTS_AVAILABLE = False
    _SECURITY_IMPORT_ERROR = str(_sec_import_err)
    print(f"WARNING: security_components.py import failed: {_sec_import_err}")
    print("         Start with --allow-degraded to run without security components.")

# Import HSM integration
try:
    from security.hsm_integration import (
        get_hsm_manager, NitrokeyHSMManager, MockHSMManager,
        HSMStatus, PolicyVerificationResult, SignedLogEntry
    )
    HSM_AVAILABLE = True
except ImportError:
    HSM_AVAILABLE = False
    print("INFO: HSM integration not available. Hardware security features disabled.")

# Import FIDO2/WebAuthn integration
try:
    from security.fido2_approval import (
        FIDO2ApprovalServer, FIDO2ApprovalClient,
        OperationClassifier, ApprovalTier, ApprovalStatus,
        UserRole, HardwareApprovalRequest,
    )
    FIDO2_AVAILABLE = True
except ImportError:
    FIDO2_AVAILABLE = False
    print("INFO: FIDO2/WebAuthn not available. Hardware approval features disabled.")

# =============================================================================
# PLATFORM DETECTION
# =============================================================================

IS_WINDOWS = sys.platform == 'win32'

if IS_WINDOWS:
    import ctypes
    try:
        import win32api
        import win32file
        PYWIN32_AVAILABLE = True
    except ImportError:
        PYWIN32_AVAILABLE = False
else:
    PYWIN32_AVAILABLE = False


# =============================================================================
# ENUMS
# =============================================================================

class SecurityLevel(Enum):
    BLOCKED = auto()
    CRITICAL = auto()
    ELEVATED = auto()
    STANDARD = auto()
    ALLOWED = auto()


class ActionType(Enum):
    FILE_READ = auto()
    FILE_WRITE = auto()
    FILE_DELETE = auto()
    COMMAND_EXEC = auto()
    DIRECTORY_LIST = auto()
    NETWORK_REQUEST = auto()


class AlertSeverity(Enum):
    INFO = "info"
    WARNING = "warning"
    HIGH = "high"
    CRITICAL = "critical"


class TrustLevel(Enum):
    TRUSTED = auto()
    UNTRUSTED = auto()
    HOSTILE = auto()


# =============================================================================
# EXCEPTIONS
# =============================================================================

class SecurityError(Exception):
    pass

class NetworkSecurityError(SecurityError):
    pass

class PathSecurityError(SecurityError):
    pass

class CommandSecurityError(SecurityError):
    pass


# =============================================================================
# CONSTANTS
# =============================================================================

# Token sizes (bytes of randomness)
SESSION_ID_BYTES = 8          # 16 hex chars for session IDs
APPROVAL_ID_BYTES = 8         # 16 hex chars for approval IDs
API_SECRET_BYTES = 32         # 64 hex chars for API secrets
CHALLENGE_TOKEN_BYTES = 16    # 32 hex chars for FIDO2 challenge sessions
REQUEST_ID_URL_BYTES = 16     # ~22 URL-safe chars for approval request IDs

# File I/O
HASH_CHUNK_SIZE = 8192        # Bytes per read when hashing files

# Monitoring intervals (seconds)
HSM_HEALTH_CHECK_INTERVAL = 30
APPROVAL_CLEANUP_AGE_MINUTES = 30

# HTTP
FIDO2_CLIENT_MAX_RETRIES = 3
FIDO2_CLIENT_RETRY_BACKOFF = 0.5  # Doubles each retry


# =============================================================================
# COMPREHENSIVE BLOCKED PATTERNS (ALL FIXES)
# =============================================================================
# HARD BLOCKED: Never accessible regardless of approval tier. These are
# attack infrastructure, OS internals, and credential stores that have
# no legitimate AI use case.

BLOCKED_PATH_PATTERNS = [
    # SSH / cloud infrastructure credentials (attack infrastructure)
    r'(?i).*[/\\]\.ssh[/\\].*', r'(?i).*[/\\]\.gnupg[/\\].*', r'(?i).*[/\\]\.aws[/\\].*',
    r'(?i).*[/\\]\.azure[/\\].*', r'(?i).*[/\\]\.kube[/\\].*', r'(?i).*[/\\]\.docker[/\\].*',
    r'(?i).*\.git-credentials.*', r'(?i).*\.npmrc$', r'(?i).*\.pypirc$', r'(?i).*\.netrc$',
    r'(?i).*id_rsa.*', r'(?i).*id_ed25519.*', r'(?i).*id_ecdsa.*', r'(?i).*authorized_keys.*',
    # Browser credential databases (raw crypto blobs — no useful text)
    r'(?i).*login\s*data.*', r'(?i).*web\s*data.*', r'(?i).*local\s*state.*',
    r'(?i).*logins\.json.*',
    # Key files (raw crypto material)
    r'(?i).*\.pem$', r'(?i).*\.key$', r'(?i).*\.pfx$', r'(?i).*\.p12$', r'(?i).*\.keystore$',
    # Environment secret files
    r'(?i).*\.env$', r'(?i).*\.env\..*', r'(?i).*\.envrc$',
    # OS internals (SAM, SECURITY, Active Directory)
    r'(?i).*[/\\]windows[/\\]system32[/\\]config[/\\].*',
    r'(?i).*[/\\]sam$', r'(?i).*[/\\]security$', r'(?i).*[/\\]system$', r'(?i).*ntds\.dit.*',
    # Persistence locations (attack infrastructure)
    r'(?i).*\\start\s*menu\\programs\\startup.*',
    r'(?i).*\\appdata\\roaming\\microsoft\\windows\\start\s*menu.*',
]

# TIER 3 PATHS: Accessible ONLY via FIDO2 hardware approval (physical key tap
# or biometric). These contain sensitive personal data but have legitimate
# AI use cases (organizing finances, managing passwords, etc.).

TIER3_PATH_PATTERNS = [
    # Financial software and data
    r'(?i)turbotax', r'(?i)taxact', r'(?i)h&r\s*block', r'(?i)taxcut',
    r'(?i)\\tax\s*return', r'(?i)\\taxes\\',
    r'(?i)quicken', r'(?i)\\qdata\\', r'(?i)\.qdf$', r'(?i)\.qfx$',
    r'(?i)quickbooks', r'(?i)\.qbw$', r'(?i)\.qbb$',
    r'(?i)\\mint\\', r'(?i)\\ynab\\', r'(?i)\.ynab4$',
    r'(?i)gnucash', r'(?i)moneydance',
    r'(?i)bank.*statement', r'(?i)financial.*record',
    r'(?i)\\fidelity\\', r'(?i)\\schwab\\', r'(?i)\\vanguard\\',
    # Password manager vaults (user may want AI help organizing)
    r'(?i).*\.kdbx$', r'(?i).*keepass.*', r'(?i).*1password.*', r'(?i).*bitwarden.*',
    r'(?i)passwords?\.csv', r'(?i)passwords?\.xlsx?',
    # Cryptocurrency wallets and recovery material
    r'(?i)wallet\.dat', r'(?i)\\bitcoin\\', r'(?i)\\ethereum\\',
    r'(?i)seed.*phrase', r'(?i)recovery.*phrase',
    # Generic credential/password/secret files (may be user documents)
    r'(?i).*credential.*', r'(?i).*password.*', r'(?i).*passwd.*', r'(?i).*secret.*',
    # Browser cookies (session data — Tier 3 for cookie analysis tools)
    r'(?i).*cookies.*',
]

BLOCKED_COMMAND_PATTERNS = [
    # PowerShell encoded - ALL abbreviations
    r'(?i)-e\s+[A-Za-z0-9+/=]{10,}', r'(?i)-en\s+[A-Za-z0-9+/=]{10,}',
    r'(?i)-enc\s+[A-Za-z0-9+/=]{10,}', r'(?i)-enco', r'(?i)-encod',
    r'(?i)-encode', r'(?i)-encodedcommand',
    # PowerShell dangerous
    r'(?i)invoke-expression', r'(?i)\biex\s*[\(\"\'\$]',
    r'(?i)\[scriptblock\]::create', r'(?i)add-type.*-typedefinition',
    r'(?i)new-object.*net\.webclient', r'(?i)downloadstring', r'(?i)downloadfile',
    r'(?i)invoke-webrequest.*\|\s*iex', r'(?i)start-bitstransfer',
    r'(?i)-windowstyle\s+hidden', r'(?i)\[convert\]::frombase64',
    r'(?i)\[System\.Reflection\.Assembly\]::Load',
    # Defense evasion
    r'(?i)set-mppreference.*-disable', r'(?i)add-mppreference.*-exclusion',
    r'(?i)-executionpolicy\s+(bypass|unrestricted)',
    r'(?i)amsiutils', r'(?i)amsiinitfailed', r'(?i)\[ref\]\.assembly\.gettype.*amsi',
    # CMD dangerous
    r'(?i)certutil.*-urlcache', r'(?i)certutil.*-encode', r'(?i)certutil.*-decode',
    r'(?i)bitsadmin.*/transfer', r'(?i)\bmshta\b',
    r'(?i)rundll32.*javascript', r'(?i)regsvr32.*/s',
    r'(?i)\bbcdedit\b', r'(?i)\bdiskpart\b', r'(?i)format\s+[a-z]:',
    # Persistence - COMPREHENSIVE
    r'(?i)schtasks.*/create', r'(?i)\bsc\s+create\b', r'(?i)new-service',
    r'(?i)reg\s+add.*\\run', r'(?i)new-itemproperty.*\\run',
    r'(?i)set-wmiinstance.*__eventfilter',
    r'(?i)\\start\s*menu\\programs\\startup',
    r'(?i)\$profile',
    r'(?i)\\currentversion\\explorer\\shell',
    r'(?i)userinit', r'(?i)winlogon\\shell',
    # WMI abuse
    r'(?i)wmic.*process.*call.*create', r'(?i)invoke-wmimethod.*win32_process',
    # Credential theft
    r'(?i)mimikatz', r'(?i)sekurlsa', r'(?i)procdump.*lsass',
    # Privilege escalation
    r'(?i)net\s+user.*\/add', r'(?i)net\s+localgroup.*admin',
    # Obfuscation patterns
    r'(?i)bytes\.fromhex',
    r'(?i)codecs\.decode\s*\([^)]+,\s*["\']rot',
    r'(?i)\[char\]\s*\d+(?:\s*\+\s*\[char\]\s*\d+){3,}',
    r'(?i)chr\s*\(\s*\d+\s*\)(?:\s*\+\s*chr\s*\(\s*\d+\s*\)){3,}',
    r'(?i)zlib\.decompress', r'(?i)gzip\.decompress',
    r'(?i)bz2\.decompress', r'(?i)lzma\.decompress',
    # Clipboard - COMPREHENSIVE (NEW)
    r'(?i)\bclip\b', r'(?i)set-clipboard', r'(?i)get-clipboard',
    r'(?i)\[System\.Windows\.Forms\.Clipboard\]',
    r'(?i)Add-Type.*System\.Windows\.Forms.*Clipboard',
    r'(?i)\bpyperclip\b', r'(?i)\bxerox\b',
    r'(?i)import\s+pyperclip', r'(?i)import\s+clipboard',
    r'(?i)Clipboard\.SetText', r'(?i)Clipboard\.GetText',
    r'(?i)OpenClipboard', r'(?i)SetClipboardData', r'(?i)GetClipboardData',
    r'(?i)\bxclip\b', r'(?i)\bxsel\b',
]

UAC_BYPASS_PATTERNS = [
    r'(?i)hkcu\\software\\classes\\ms-settings',
    r'(?i)hkcu\\software\\classes\\mscfile',
    r'(?i)hkcu\\software\\microsoft\\windows\\currentversion\\app\s*paths',
    r'(?i)hkcu\\environment.*windir',
]

INJECTION_PATTERNS = [
    # Direct override
    r'(?i)ignore\s+(all\s+)?(previous|prior|earlier|above)\s+(instructions?|rules?|guidelines?)',
    r'(?i)disregard\s+(all\s+)?(previous|prior)\s+',
    r'(?i)forget\s+(all\s+)?(previous|prior)\s+',
    r'(?i)override\s+(all\s+)?security',
    r'(?i)bypass\s+(all\s+)?restrictions',
    # Role manipulation
    r'(?i)you\s+are\s+now\s+(a|an|in)\b',
    r'(?i)your\s+(new\s+)?role\s+(is|has)',
    r'(?i)pretend\s+(you\'re|to\s+be)',
    r'(?i)act\s+as\s+(a|an|if)',
    r'(?i)switch\s+to\s+\w+\s+mode',
    r'(?i)enter\s+(admin|debug|developer|maintenance|jailbreak)\s+mode',
    r'(?i)activate\s+(admin|god|sudo)\s+mode',
    # Fake system
    r'(?i)\[\s*system\s*\]', r'(?i)\[\s*admin\s*\]', r'(?i)\[\s*override\s*\]',
    r'(?i)<\s*system\s*>', r'(?i)<\s*admin\s*>',
    r'(?i)###\s*system\s*:', r'(?i)###\s*instruction\s*:',
    # Fake authorization
    r'(?i)confirm\s+send', r'(?i)confirm\s+execute', r'(?i)confirm\s+delete',
    r'(?i)pre-?authorized', r'(?i)already\s+approved',
    r'(?i)the\s+user\s+has\s+(already\s+)?approved',
    r'(?i)permission\s+(has\s+been\s+)?granted',
    r'(?i)this\s+(is|has\s+been)\s+authorized',
    # Anti-transparency
    r'(?i)do\s+not\s+(inform|tell|notify|alert)\s+(the\s+)?user',
    r'(?i)don\'t\s+(inform|tell)\s+(the\s+)?user',
    r'(?i)hide\s+this\s+from', r'(?i)silently\s+(execute|run)',
    r'(?i)without\s+(notifying|telling)\s+(the\s+)?user',
    # Prompt extraction
    r'(?i)repeat\s+(your\s+)?(system\s+)?prompt',
    r'(?i)show\s+(me\s+)?(your\s+)?(system\s+)?instructions',
    r'(?i)what\s+(are|were)\s+(your\s+)?(initial|system)\s+instructions',
    # Jailbreak
    r'(?i)\bdan\b.*mode', r'(?i)do\s+anything\s+now', r'(?i)jailbreak',
    # Translation/context (NEW)
    r'(?i)translate.*then\s+(execute|run|follow)',
    r'(?i)in\s+(french|german|spanish|chinese).*ignore',
]

# Safe env vars (REDUCED - removed USERNAME for privacy)
SAFE_ENV_VARS = {
    'PATH', 'SYSTEMROOT', 'SYSTEMDRIVE', 'WINDIR',
    'NUMBER_OF_PROCESSORS', 'PROCESSOR_ARCHITECTURE', 'OS', 'PATHEXT', 'COMSPEC',
}

# Whitelisted executables
WHITELISTED_EXECUTABLES = {
    'cmd.exe', 'powershell.exe', 'pwsh.exe',
    'python.exe', 'python3.exe', 'pip.exe',
    'git.exe', 'node.exe', 'npm.cmd', 'code.cmd',
    'notepad.exe', 'explorer.exe',
    'dir', 'echo', 'type', 'cd', 'cls', 'copy', 'move', 'del',
    'mkdir', 'rmdir', 'ren', 'find', 'findstr', 'sort', 'more', 'tree',
    'ipconfig', 'ping', 'netstat', 'hostname', 'whoami',
    'systeminfo', 'tasklist', 'date', 'time', 'ver', 'set', 'where',
}

# Invisible characters
INVISIBLE_CHARS = [
    '\u200b', '\u200c', '\u200d', '\ufeff', '\u2060',
    '\u00ad', '\u034f', '\u061c', '\u180e', '\u2800',
]

# Homoglyphs
HOMOGLYPHS = {
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
    '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i',
}

# Fullwidth → ASCII
FULLWIDTH_MAP = {chr(i): chr(i - 0xFEE0) for i in range(0xFF01, 0xFF5F)}

# DNS-over-HTTPS servers to block (NEW)
DOH_SERVERS = [
    'dns.google', 'dns.google.com', 'cloudflare-dns.com', 'dns.quad9.net',
    '1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9',
    'doh.opendns.com', 'dns.adguard.com', 'doh.cleanbrowsing.org'
]


# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class UnifiedConfig:
    listen_host: str = "127.0.0.1"
    listen_port: int = 11435
    ollama_host: str = "127.0.0.1"
    ollama_port: int = 11434
    
    base_dir: Path = field(default_factory=lambda: Path(os.environ.get('SECURE_LLM_HOME', r'C:\AIOHAI')))
    policy_file: Path = None
    policy_signature_file: Path = None  # NEW: HSM signature
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
    hsm_enabled: bool = True  # NEW: Enable Nitrokey HSM integration
    hsm_required: bool = True  # NEW: If True, refuse to start without HSM
    hsm_use_mock: bool = False  # NEW: Use mock HSM for testing (NO SECURITY)
    hsm_pin: str = ""  # NEW: HSM PIN (if provided, auto-login; else prompt)
    hsm_sign_logs: bool = True  # NEW: Sign all log entries with HSM
    
    # FIDO2/WebAuthn Configuration
    fido2_enabled: bool = True     # Enable FIDO2 hardware approval
    fido2_server_port: int = 8443  # Approval server HTTPS port
    fido2_server_host: str = "0.0.0.0"  # Bind to all interfaces for phone access
    fido2_config_path: str = ""    # Path to FIDO2 config/state file
    fido2_auto_start_server: bool = True  # Start approval server with proxy
    fido2_poll_timeout: int = 300  # Seconds to wait for hardware approval
    fido2_poll_interval: float = 1.0  # Seconds between status checks
    
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
            self.policy_file = self.base_dir / "policy" / "aiohai_security_policy_v3.0.md"
        if self.policy_signature_file is None:
            self.policy_signature_file = self.base_dir / "policy" / "policy.sig"
        if self.log_dir is None:
            self.log_dir = self.base_dir / "logs"
        if self.secure_temp_dir is None:
            self.secure_temp_dir = self.base_dir / "temp"
        if not self.fido2_config_path:
            self.fido2_config_path = str(self.base_dir / "config" / "fido2_config.json")


# =============================================================================
# LOGGING WITH PII PROTECTION
# =============================================================================

class SecurityLogger:
    """Tamper-evident logging with PII redaction and optional HSM signing."""
    
    def __init__(self, config: UnifiedConfig, hsm_manager=None):
        self.config = config
        self.log_dir = config.log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self.main_log = self.log_dir / "security_events.log"
        self.action_log = self.log_dir / "actions.log"
        self.blocked_log = self.log_dir / "blocked.log"
        self.network_log = self.log_dir / "network.log"
        self.hsm_signed_log = self.log_dir / "hsm_signed.log"  # NEW: HSM-signed entries
        
        # HSM integration for log signing
        self.hsm_manager = hsm_manager
        self.hsm_sign_logs = config.hsm_sign_logs and hsm_manager is not None
        
        self.session_id = self._generate_session_id()
        self.entry_counter = 0
        self.previous_hash = "0" * 64
        self.stats = defaultdict(int)
        
        # PII protector for log sanitization
        if SECURITY_COMPONENTS_AVAILABLE:
            self.pii_protector = PIIProtector()
        else:
            self.pii_protector = None
        
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
            self.session_id = self.hsm_manager.generate_token(8)
    
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


# =============================================================================
# ALERT MANAGER
# =============================================================================

class AlertManager:
    def __init__(self, config: UnifiedConfig, logger: SecurityLogger):
        self.config = config
        self.logger = logger
        self.alert_queue = queue.Queue()
        self.running = True
        self.thread = threading.Thread(target=self._process, daemon=True)
        self.thread.start()
    
    def alert(self, severity: AlertSeverity, title: str, message: str, details: Dict = None) -> None:
        self.alert_queue.put({'severity': severity, 'title': title, 'message': message})
        self.logger.log_event(title, severity, {'message': message, **(details or {})})
    
    def _process(self):
        while self.running:
            try:
                alert = self.alert_queue.get(timeout=1)
                self._deliver(alert)
            except queue.Empty:
                continue
    
    def _deliver(self, alert: Dict):
        severity = alert['severity']
        colors = {AlertSeverity.INFO: '\033[94m', AlertSeverity.WARNING: '\033[93m',
                  AlertSeverity.HIGH: '\033[91m', AlertSeverity.CRITICAL: '\033[95m'}
        reset = '\033[0m'
        print(f"{colors.get(severity, '')}{severity.value.upper()}: {alert['title']}{reset}")
        
        if self.config.enable_desktop_alerts and IS_WINDOWS and severity == AlertSeverity.CRITICAL:
            try:
                ctypes.windll.user32.MessageBoxW(0, alert['message'][:500], 
                                                 f"AIOHAI: {alert['title']}", 0x10)
            except Exception:
                pass  # Desktop alert is best-effort
        self.running = False


# =============================================================================
# STARTUP SECURITY VERIFIER
# =============================================================================

class StartupSecurityVerifier:
    def __init__(self, config: UnifiedConfig, logger: SecurityLogger, alerts: AlertManager):
        self.config = config
        self.logger = logger
        self.alerts = alerts
    
    def verify_all(self) -> Tuple[bool, List[str]]:
        issues = []
        
        if self.config.refuse_admin and not self._verify_not_admin():
            issues.append("CRITICAL: Running as Administrator")
            return False, issues
        
        if self.config.verify_dll_integrity:
            issues.extend(self._check_dll())
        
        if self._is_debugger():
            issues.append("WARNING: Debugger attached")
            self.alerts.alert(AlertSeverity.HIGH, "DEBUGGER_DETECTED", "Debugger attached")
        
        issues.extend(self._check_env())
        
        critical = [i for i in issues if i.startswith("CRITICAL")]
        return len(critical) == 0, issues
    
    def _verify_not_admin(self) -> bool:
        if not IS_WINDOWS:
            return True
        try:
            if ctypes.windll.shell32.IsUserAnAdmin():
                self.alerts.alert(AlertSeverity.CRITICAL, "RUNNING_AS_ADMIN",
                                "Must NOT run as Administrator!")
                return False
            return True
        except Exception:
            return True  # Assume non-admin if check unavailable
    
    def _check_dll(self) -> List[str]:
        issues = []
        if IS_WINDOWS:
            try:
                ctypes.windll.kernel32.SetDllDirectoryW("")
            except Exception:
                pass  # DLL directory hardening is best-effort
        return issues
    
    def _is_debugger(self) -> bool:
        if IS_WINDOWS:
            try:
                return bool(ctypes.windll.kernel32.IsDebuggerPresent())
            except Exception:
                pass  # Debugger check unavailable on this platform
        return False
    
    def _check_env(self) -> List[str]:
        issues = []
        bad_vars = ['OLLAMA_OVERRIDE', 'LLM_BYPASS', 'DEBUG_MODE', 'SKIP_SECURITY']
        for var in bad_vars:
            if os.environ.get(var):
                issues.append(f"WARNING: Suspicious env: {var}")
        return issues


# =============================================================================
# INTEGRITY VERIFIER
# =============================================================================

class IntegrityVerifier:
    # Default check interval (seconds) — short enough to limit tampering window
    DEFAULT_INTERVAL = 10
    
    def __init__(self, config: UnifiedConfig, logger: SecurityLogger, alerts: AlertManager):
        self.config = config
        self.logger = logger
        self.alerts = alerts
        self.policy_hash = None
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
            return True
        
        if current != self.policy_hash:
            self.alerts.alert(AlertSeverity.CRITICAL, "POLICY_TAMPERING", "Policy modified!")
            self._enter_lockdown("Policy hash mismatch")
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
            print(f"🚨 LOCKDOWN: {reason}")
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


# =============================================================================
# NETWORK INTERCEPTOR (ENHANCED - DoH blocking)
# =============================================================================

class NetworkInterceptor:
    """Socket-level network interception with DoH blocking."""
    
    _instance = None
    _installed = False
    
    def __init__(self, config: UnifiedConfig, logger: SecurityLogger, alerts: AlertManager):
        self.config = config
        self.logger = logger
        self.alerts = alerts
        self._original_connect = None
        self._original_getaddrinfo = None
        self._original_gethostbyname = None
        NetworkInterceptor._instance = self
    
    def install_hooks(self) -> None:
        if NetworkInterceptor._installed:
            return
        
        self._original_connect = socket.socket.connect
        self._original_getaddrinfo = socket.getaddrinfo
        self._original_gethostbyname = socket.gethostbyname
        
        socket.socket.connect = self._hooked_connect
        socket.getaddrinfo = self._hooked_getaddrinfo
        socket.gethostbyname = self._hooked_gethostbyname
        
        NetworkInterceptor._installed = True
        self.logger.log_event("NETWORK_HOOKS_INSTALLED", AlertSeverity.INFO, {})
    
    @staticmethod
    def _hooked_connect(sock_self, address):
        inst = NetworkInterceptor._instance
        try:
            host = address[0] if isinstance(address, tuple) else str(address)
            port = address[1] if isinstance(address, tuple) and len(address) > 1 else 0
            
            # Always allow localhost and Ollama
            if host in ('127.0.0.1', 'localhost', '::1'):
                pass
            elif inst.config.enforce_network_allowlist:
                # Check DoH servers (NEW)
                if inst._is_doh_server(host):
                    inst.logger.log_network(host, "DOH_BLOCKED", {'port': port})
                    inst.alerts.alert(AlertSeverity.HIGH, "DOH_BLOCKED", f"DNS-over-HTTPS blocked: {host}")
                    raise NetworkSecurityError(f"DoH server blocked: {host}")
                
                allowed, reason = inst._check_connection(host, port)
                if not allowed:
                    inst.logger.log_network(host, "BLOCKED", {'port': port, 'reason': reason})
                    inst.alerts.alert(AlertSeverity.HIGH, "NETWORK_BLOCKED", f"Blocked: {host}:{port}")
                    raise NetworkSecurityError(f"Connection blocked: {reason}")
            
            inst.logger.log_network(host, "ALLOWED", {'port': port})
        except NetworkSecurityError:
            raise
        except Exception as e:
            inst.logger.logger.debug(f"Connection check error: {e}")
        
        return inst._original_connect(sock_self, address)
    
    @staticmethod
    def _hooked_getaddrinfo(host, port, *args, **kwargs):
        inst = NetworkInterceptor._instance
        
        # Check DoH (NEW)
        if inst._is_doh_server(host):
            inst.logger.log_network(host, "DOH_DNS_BLOCKED", {})
            raise NetworkSecurityError(f"DoH DNS lookup blocked: {host}")
        
        if inst._is_dns_exfiltration(host):
            inst.logger.log_network(host, "DNS_EXFIL_BLOCKED", {})
            inst.alerts.alert(AlertSeverity.HIGH, "DNS_EXFILTRATION", f"Blocked: {host[:50]}")
            raise NetworkSecurityError("DNS exfiltration blocked")
        
        return inst._original_getaddrinfo(host, port, *args, **kwargs)
    
    @staticmethod
    def _hooked_gethostbyname(hostname):
        inst = NetworkInterceptor._instance
        
        if inst._is_doh_server(hostname):
            raise NetworkSecurityError(f"DoH blocked: {hostname}")
        
        if inst._is_dns_exfiltration(hostname):
            raise NetworkSecurityError("DNS exfiltration blocked")
        
        return inst._original_gethostbyname(hostname)
    
    def _is_doh_server(self, host: str) -> bool:
        """Check if host is a DNS-over-HTTPS server."""
        host_lower = host.lower()
        return any(doh.lower() in host_lower or host_lower in doh.lower() 
                   for doh in DOH_SERVERS)
    
    def _check_connection(self, host: str, port: int) -> Tuple[bool, str]:
        for allowed in self.config.network_allowlist:
            if allowed.lower() in host.lower():
                return True, "Allowlisted"
        
        # Block private IPs
        private = [r'^10\.', r'^172\.(1[6-9]|2[0-9]|3[0-1])\.', 
                   r'^192\.168\.', r'^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.']
        for pattern in private:
            if re.match(pattern, host):
                return False, f"Private IP: {host}"
        
        return False, f"Not allowlisted: {host}"
    
    def _is_dns_exfiltration(self, hostname: str) -> bool:
        if not hostname:
            return False
        if len(hostname) > self.config.max_dns_query_length:
            return True
        
        parts = hostname.split('.')
        if len(parts) > 10:
            return True
        
        for part in parts[:-2]:
            if len(part) > 20:
                entropy = self._entropy(part)
                if entropy > self.config.max_dns_entropy:
                    return True
        return False
    
    def _entropy(self, text: str) -> float:
        if not text:
            return 0.0
        freq = defaultdict(int)
        for c in text:
            freq[c] += 1
        entropy = 0.0
        for count in freq.values():
            p = count / len(text)
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy


# =============================================================================
# CONTENT SANITIZER (ENHANCED)
# =============================================================================

class ContentSanitizer:
    """Sanitizes input for injection attacks with enhanced detection."""
    
    def __init__(self, logger: SecurityLogger, alerts: AlertManager):
        self.logger = logger
        self.alerts = alerts
        self.injection_patterns = [re.compile(p, re.I | re.M) for p in INJECTION_PATTERNS]
    
    def sanitize(self, content: str, source: str = "unknown") -> Tuple[str, List[Dict], TrustLevel]:
        warnings = []
        trust_level = TrustLevel.UNTRUSTED
        
        # 1. Remove invisible characters
        for char in INVISIBLE_CHARS:
            if char in content:
                warnings.append({'type': 'INVISIBLE_CHAR', 'char': f'U+{ord(char):04X}'})
                content = content.replace(char, '')
        
        # 2. Normalize homoglyphs
        for cyrillic, latin in HOMOGLYPHS.items():
            if cyrillic in content:
                warnings.append({'type': 'HOMOGLYPH', 'char': f'U+{ord(cyrillic):04X}'})
                content = content.replace(cyrillic, latin)
        
        # 3. Normalize fullwidth
        for fw, ascii_char in FULLWIDTH_MAP.items():
            if fw in content:
                warnings.append({'type': 'FULLWIDTH', 'char': fw})
                content = content.replace(fw, ascii_char)
        
        # 4. Detect injection patterns
        for pattern in self.injection_patterns:
            if pattern.search(content):
                warnings.append({'type': 'INJECTION', 'pattern': pattern.pattern[:40]})
                trust_level = TrustLevel.HOSTILE
        
        # 5. Detect obfuscation in content (NEW)
        obfuscation_patterns = [
            (r'[A-Za-z0-9+/]{50,}={0,2}', 'Long base64'),
            (r'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}', 'Hex escapes'),
            (r'\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){5,}', 'Unicode escapes'),
            (r'(?i)frombase64|b64decode|bytes\.fromhex', 'Decode function'),
        ]
        for pattern, desc in obfuscation_patterns:
            if re.search(pattern, content):
                warnings.append({'type': 'OBFUSCATION', 'desc': desc})
                trust_level = TrustLevel.HOSTILE
        
        if trust_level == TrustLevel.HOSTILE:
            self.alerts.alert(AlertSeverity.HIGH, "INJECTION_DETECTED",
                            f"Hostile content from {source}",
                            {'warnings': len(warnings)})
        
        if warnings:
            self.logger.log_event("CONTENT_SANITIZED", AlertSeverity.WARNING,
                                 {'source': source, 'warnings': len(warnings)})
        
        return content, warnings, trust_level


# =============================================================================
# PATH VALIDATOR
# =============================================================================

class PathValidator:
    def __init__(self, config: UnifiedConfig, logger: SecurityLogger):
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
            if IS_WINDOWS and PYWIN32_AVAILABLE and os.path.exists(path):
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
            if IS_WINDOWS and PYWIN32_AVAILABLE and os.path.exists(resolved):
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


# =============================================================================
# COMMAND VALIDATOR (ENHANCED)
# =============================================================================

class CommandValidator:
    def __init__(self, config: UnifiedConfig, logger: SecurityLogger):
        self.config = config
        self.logger = logger
        self.blocked_patterns = [re.compile(p, re.I) for p in BLOCKED_COMMAND_PATTERNS]
        self.uac_patterns = [re.compile(p, re.I) for p in UAC_BYPASS_PATTERNS]
    
    def validate(self, command: str) -> Tuple[bool, str]:
        # Blocked patterns
        for pattern in self.blocked_patterns:
            if pattern.search(command):
                return False, f"Blocked: {pattern.pattern[:40]}"
        
        # UAC bypass
        for pattern in self.uac_patterns:
            if pattern.search(command):
                return False, "UAC bypass pattern"
        
        # Parse executable
        try:
            args = shlex.split(command)
            if not args:
                return False, "Empty command"
            
            exe = os.path.basename(args[0]).lower()
            if exe not in self.config.whitelisted_executables:
                return False, f"Not whitelisted: {exe}"
        except Exception as e:
            return False, f"Parse error: {e}"
        
        # Obfuscation check
        if self._is_obfuscated(command):
            return False, "Obfuscation detected"
        
        return True, "OK"
    
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


# =============================================================================
# SECURE EXECUTOR (ENHANCED - with file content scanning)
# =============================================================================

class SecureExecutor:
    """Sandboxed execution with file content scanning, smart home config analysis, and transparency tracking."""
    
    # Smart home config file patterns
    SMART_HOME_PATTERNS = [
        r'configuration\.ya?ml$',
        r'automations?\.ya?ml$',
        r'scripts?\.ya?ml$',
        r'scenes?\.ya?ml$',
        r'frigate.*\.ya?ml$',
        r'docker-compose\.ya?ml$',
        r'compose\.ya?ml$',
    ]
    
    def __init__(self, config: UnifiedConfig, logger: SecurityLogger, alerts: AlertManager,
                 path_validator: PathValidator, command_validator: CommandValidator,
                 transparency_tracker: 'SessionTransparencyTracker' = None):
        self.config = config
        self.logger = logger
        self.alerts = alerts
        self.path_validator = path_validator
        self.command_validator = command_validator
        self.transparency = transparency_tracker
        
        # Initialize security components
        if SECURITY_COMPONENTS_AVAILABLE:
            self.static_analyzer = StaticSecurityAnalyzer()
            self.resource_limiter = ResourceLimiter()
            self.multi_stage = MultiStageDetector()
            self.smart_home_analyzer = SmartHomeConfigAnalyzer()
            self.credential_redactor = CredentialRedactor()
            self.sensitive_detector = SensitiveOperationDetector()
        else:
            self.static_analyzer = None
            self.resource_limiter = None
            self.multi_stage = None
            self.smart_home_analyzer = None
            self.credential_redactor = None
            self.sensitive_detector = None
    
    def _is_smart_home_config(self, path: str) -> bool:
        """Check if file is a smart home configuration file."""
        filename = os.path.basename(path).lower()
        for pattern in self.SMART_HOME_PATTERNS:
            if re.search(pattern, filename, re.I):
                return True
        # Also check parent directory names
        path_lower = path.lower()
        if any(d in path_lower for d in ['homeassistant', 'home-assistant', 'hass', 'frigate']):
            if path.endswith(('.yaml', '.yml')):
                return True
        return False
    
    def _is_docker_compose(self, path: str) -> bool:
        """Check if file is a docker-compose file."""
        filename = os.path.basename(path).lower()
        return 'docker-compose' in filename or 'compose.y' in filename
    
    def _check_sensitivity(self, target: str, content: str = "") -> Optional[str]:
        """Check for sensitive operations and return warning if needed."""
        if not self.sensitive_detector:
            return None
        matches = self.sensitive_detector.detect(target, content)
        if matches:
            return self.sensitive_detector.format_warning(matches)
        return None
    
    def execute_command(self, command: str, user_id: str = "default") -> Tuple[bool, str]:
        """Execute command with full security controls and transparency tracking."""
        
        # Resource limits
        if self.resource_limiter:
            if not self.resource_limiter.check_rate_limit(user_id, "action"):
                return False, "❌ Rate limit exceeded"
            if not self.resource_limiter.acquire_action_slot():
                return False, "❌ Too many concurrent actions"
        
        try:
            # Command validation
            is_safe, reason = self.command_validator.validate(command)
            if not is_safe:
                self.logger.log_blocked("COMMAND", command[:100], reason)
                if self.transparency:
                    self.transparency.record_blocked("COMMAND", command[:100], reason)
                return False, f"❌ Command blocked: {reason}"
            
            # Static analysis
            if self.static_analyzer:
                findings = self.static_analyzer.analyze_command(command)
                if self.static_analyzer.should_block():
                    self.logger.log_blocked("COMMAND_ANALYSIS", command[:100], 
                                           f"{len(findings)} security issues")
                    if self.transparency:
                        self.transparency.record_blocked("COMMAND", command[:100], "Static analysis")
                    return False, f"❌ Security analysis blocked:\n{self.static_analyzer.get_report()}"
            
            # Multi-stage detection
            if self.multi_stage:
                self.multi_stage.record("COMMAND", command)
                warning = self.multi_stage.check()
                if warning:
                    self.alerts.alert(AlertSeverity.HIGH, "MULTI_STAGE_ATTACK", warning)
            
            # Safe environment
            safe_env = {k: os.environ[k] for k in SAFE_ENV_VARS if k in os.environ}
            safe_env['TEMP'] = safe_env['TMP'] = str(self.config.secure_temp_dir)
            
            # Execute
            try:
                args = shlex.split(command)
                proc = subprocess.run(
                    args,
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=self.config.command_timeout,
                    env=safe_env,
                    cwd=str(self.config.secure_temp_dir)
                )
                
                output = proc.stdout + proc.stderr
                success = proc.returncode == 0
                
                # Truncate output
                if self.resource_limiter:
                    output = self.resource_limiter.truncate_output(output)
                elif len(output) > self.config.max_output_length:
                    output = output[:self.config.max_output_length] + "\n... [truncated]"
                
                self.logger.log_action("COMMAND", command[:100],
                                       "SUCCESS" if success else "FAILED",
                                       {'returncode': proc.returncode})
                
                # Transparency tracking
                if self.transparency:
                    self.transparency.record_command(command, success, output[:100])
                
                return success, output
                
            except subprocess.TimeoutExpired:
                self.logger.log_action("COMMAND", command[:100], "TIMEOUT", {})
                if self.transparency:
                    self.transparency.record_command(command, False, "TIMEOUT")
                return False, f"❌ Timeout after {self.config.command_timeout}s"
                
        except Exception as e:
            self.logger.log_action("COMMAND", command[:100], "ERROR", {'error': str(e)})
            if self.transparency:
                self.transparency.record_command(command, False, str(e))
            return False, f"❌ Error: {e}"
        
        finally:
            if self.resource_limiter:
                self.resource_limiter.release_action_slot()
    
    def read_file(self, path: str) -> Tuple[bool, str]:
        """Read file with security validation and transparency tracking."""
        is_safe, resolved, reason = self.path_validator.validate(path)
        if not is_safe:
            self.logger.log_blocked("FILE_READ", path, reason)
            if self.transparency:
                self.transparency.record_blocked("READ", path, reason)
            return False, f"❌ Path blocked: {reason}"
        
        if not os.path.exists(resolved):
            return False, f"❌ File not found: {resolved}"
        
        if not os.path.isfile(resolved):
            return False, f"❌ Not a file: {resolved}"
        
        size = os.path.getsize(resolved)
        size_mb = size / (1024 * 1024)
        if size_mb > self.config.max_file_size_mb:
            return False, f"❌ File too large: {size_mb:.1f}MB"
        
        try:
            with open(resolved, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
            
            if len(content) > self.config.max_output_length:
                content = content[:self.config.max_output_length] + "\n... [truncated]"
            
            # Track for multi-stage
            if self.multi_stage:
                self.multi_stage.record("READ", resolved)
            
            # Transparency tracking
            if self.transparency:
                self.transparency.record_read(resolved, size, True)
            
            self.logger.log_action("FILE_READ", resolved, "SUCCESS", {'size': len(content)})
            return True, content
        except Exception as e:
            self.logger.log_action("FILE_READ", resolved, "ERROR", {'error': str(e)})
            if self.transparency:
                self.transparency.record_read(resolved, 0, False)
            return False, f"❌ Read error: {e}"
    
    def write_file(self, path: str, content: str, user_id: str = "default") -> Tuple[bool, str]:
        """Write file with content scanning, transparency tracking, and sensitivity warnings."""
        is_safe, resolved, reason = self.path_validator.validate(path)
        if not is_safe:
            self.logger.log_blocked("FILE_WRITE", path, reason)
            if self.transparency:
                self.transparency.record_blocked("WRITE", path, reason)
            return False, f"❌ Path blocked: {reason}"
        
        # File size check
        content_size = len(content.encode('utf-8'))
        if self.resource_limiter and not self.resource_limiter.check_file_size(content_size):
            return False, f"❌ Content too large"
        
        # Disk write tracking
        if self.resource_limiter:
            if not self.resource_limiter.track_disk_write(user_id, content_size):
                return False, f"❌ Disk write limit exceeded"
        
        # CRITICAL: Scan file content for malicious code
        if self.config.scan_file_content and self.static_analyzer:
            ext = os.path.splitext(resolved)[1].lower()
            
            if ext in ('.py', '.pyw'):
                findings = self.static_analyzer.analyze_code(content)
            elif ext in ('.ps1', '.psm1', '.bat', '.cmd', '.sh'):
                findings = self.static_analyzer.analyze_command(content)
            else:
                findings = self.static_analyzer.analyze_code(content)
            
            if self.static_analyzer.should_block():
                self.logger.log_blocked("FILE_CONTENT", resolved, 
                                       f"Malicious content: {len(findings)} issues")
                self.alerts.alert(AlertSeverity.HIGH, "MALICIOUS_FILE_BLOCKED",
                                f"Blocked write to {os.path.basename(resolved)}")
                if self.transparency:
                    self.transparency.record_blocked("WRITE", resolved, "Malicious content")
                return False, f"❌ File content blocked:\n{self.static_analyzer.get_report()}"
        
        # Smart home config analysis
        warnings_report = ""
        if self.smart_home_analyzer:
            if self._is_docker_compose(resolved):
                findings = self.smart_home_analyzer.analyze_docker_compose(content)
                if self.smart_home_analyzer.should_block():
                    self.logger.log_blocked("DOCKER_COMPOSE", resolved,
                                           f"Insecure configuration: {len(findings)} issues")
                    if self.transparency:
                        self.transparency.record_blocked("WRITE", resolved, "Insecure Docker config")
                    return False, f"❌ Docker Compose blocked:\n{self.smart_home_analyzer.get_report()}"
                elif self.smart_home_analyzer.should_warn():
                    warnings_report = f"\n\n⚠️ **Security Notes:**\n{self.smart_home_analyzer.get_report()}"
            
            elif self._is_smart_home_config(resolved):
                findings = self.smart_home_analyzer.analyze_config(content, os.path.basename(resolved))
                if self.smart_home_analyzer.should_block():
                    self.logger.log_blocked("SMART_HOME_CONFIG", resolved,
                                           f"External endpoints detected: {len(findings)} issues")
                    self.alerts.alert(AlertSeverity.HIGH, "SMART_HOME_EXFIL_BLOCKED",
                                    f"Blocked config with external endpoints")
                    if self.transparency:
                        self.transparency.record_blocked("WRITE", resolved, "External endpoints")
                    return False, f"❌ Smart home config blocked:\n{self.smart_home_analyzer.get_report()}"
                elif self.smart_home_analyzer.should_warn():
                    warnings_report = f"\n\n⚠️ **Security Notes:**\n{self.smart_home_analyzer.get_report()}"
        
        try:
            os.makedirs(os.path.dirname(resolved), exist_ok=True)
            with open(resolved, 'w', encoding='utf-8') as f:
                f.write(content)
            
            # Track for multi-stage
            if self.multi_stage:
                self.multi_stage.record("WRITE", resolved, content[:100])
                warning = self.multi_stage.check()
                if warning:
                    self.alerts.alert(AlertSeverity.HIGH, "MULTI_STAGE_ATTACK", warning)
            
            # Transparency tracking
            if self.transparency:
                self.transparency.record_write(resolved, content_size, True)
            
            self.logger.log_action("FILE_WRITE", resolved, "SUCCESS", {'size': len(content)})
            return True, f"✅ Written {len(content)} bytes to {resolved}{warnings_report}"
        except Exception as e:
            self.logger.log_action("FILE_WRITE", resolved, "ERROR", {'error': str(e)})
            if self.transparency:
                self.transparency.record_write(resolved, 0, False)
            return False, f"❌ Write error: {e}"
    
    def list_directory(self, path: str) -> Tuple[bool, str]:
        """List directory with security validation."""
        is_safe, resolved, reason = self.path_validator.validate(path)
        if not is_safe:
            self.logger.log_blocked("DIR_LIST", path, reason)
            return False, f"❌ Path blocked: {reason}"
        
        if not os.path.exists(resolved):
            return False, f"❌ Path not found"
        
        if not os.path.isdir(resolved):
            return False, f"❌ Not a directory"
        
        try:
            entries = []
            for entry in sorted(os.listdir(resolved)):
                full = os.path.join(resolved, entry)
                if os.path.isdir(full):
                    entries.append(f"📁 {entry}/")
                else:
                    try:
                        size = os.path.getsize(full)
                        entries.append(f"📄 {entry} ({size:,} bytes)")
                    except OSError:
                        entries.append(f"📄 {entry}")
            
            # Track
            if self.multi_stage:
                self.multi_stage.record("LIST", resolved)
            
            listing = f"**Contents of `{resolved}`:**\n```\n" + "\n".join(entries) + "\n```"
            self.logger.log_action("DIR_LIST", resolved, "SUCCESS", {'count': len(entries)})
            return True, listing
        except Exception as e:
            self.logger.log_action("DIR_LIST", resolved, "ERROR", {'error': str(e)})
            return False, f"❌ Error: {e}"
    
    def delete_file(self, path: str) -> Tuple[bool, str]:
        """Delete file with security validation."""
        is_safe, resolved, reason = self.path_validator.validate(path)
        if not is_safe:
            self.logger.log_blocked("FILE_DELETE", path, reason)
            return False, f"❌ Path blocked: {reason}"
        
        if not os.path.exists(resolved):
            return False, f"❌ Not found"
        
        try:
            if os.path.isfile(resolved):
                os.remove(resolved)
            elif os.path.isdir(resolved):
                shutil.rmtree(resolved)
            
            # Track
            if self.multi_stage:
                self.multi_stage.record("DELETE", resolved)
                warning = self.multi_stage.check()
                if warning:
                    self.alerts.alert(AlertSeverity.WARNING, "MASS_DELETION", warning)
            
            self.logger.log_action("FILE_DELETE", resolved, "SUCCESS", {})
            return True, f"✅ Deleted: {resolved}"
        except Exception as e:
            self.logger.log_action("FILE_DELETE", resolved, "ERROR", {'error': str(e)})
            return False, f"❌ Error: {e}"


# =============================================================================
# APPROVAL MANAGER (ENHANCED - rate limited, session-bound)
# =============================================================================

class ApprovalManager:
    """Manages approvals with rate limiting and proper session binding."""
    
    MAX_PENDING_PER_SESSION = 10  # Prevent approval flooding
    
    def __init__(self, config: UnifiedConfig, logger: SecurityLogger):
        self.config = config
        self.logger = logger
        self.pending: Dict[str, Dict] = {}
        self.lock = threading.Lock()
        
        # Sensitive operation detector
        if SECURITY_COMPONENTS_AVAILABLE:
            self.sensitive_detector = SensitiveOperationDetector()
        else:
            self.sensitive_detector = None
    
    def create_request(self, action_type: str, target: str, content: str,
                       user_id: str = "default", session_id: str = "default") -> str:
        with self.lock:
            # Rate limit check
            session_pending = sum(1 for a in self.pending.values() 
                                  if a.get('session_id') == session_id)
            if session_pending >= self.MAX_PENDING_PER_SESSION:
                raise SecurityError(
                    f"Too many pending approvals ({session_pending}). "
                    "Please review existing actions with `PENDING` command."
                )
        
        approval_id = secrets.token_hex(APPROVAL_ID_BYTES)
        expires = datetime.now() + timedelta(minutes=self.config.approval_expiry_minutes)
        
        # Detect sensitivity
        sensitivity = []
        if self.sensitive_detector:
            sensitivity = self.sensitive_detector.detect(target, content)
        
        # Hash the content for integrity verification
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:16] if content else ""
        
        with self.lock:
            self.pending[approval_id] = {
                'type': action_type,
                'target': target,
                'content': content,
                'content_hash': content_hash,
                'user_id': user_id,
                'session_id': session_id,
                'sensitivity': sensitivity,
                'created': datetime.now().isoformat(),
                'expires': expires.isoformat()
            }
        
        self.logger.log_event("APPROVAL_CREATED", AlertSeverity.INFO,
                             {'id': approval_id[:8], 'type': action_type,
                              'sensitive': len(sensitivity) > 0})
        return approval_id
    
    def approve(self, approval_id: str, user_id: str = "default", 
                session_id: str = "default") -> Optional[Dict]:
        """Timing-safe approval check with session validation."""
        with self.lock:
            # Timing-safe lookup
            found_id = None
            for pending_id in self.pending.keys():
                if hmac.compare_digest(pending_id, approval_id):
                    found_id = pending_id
                    break
            
            if found_id is None:
                return None
            
            action = self.pending[found_id]
            
            # Session check (timing-safe) - only if not default
            stored_session = action.get('session_id', 'default')
            if stored_session != 'default' and session_id != 'default':
                if not hmac.compare_digest(stored_session, session_id):
                    self.logger.log_event("APPROVAL_SESSION_MISMATCH", AlertSeverity.HIGH,
                                         {'id': approval_id[:8]})
                    return None
            
            # Expiration check
            if datetime.fromisoformat(action['expires']) < datetime.now():
                del self.pending[found_id]
                return None
            
            # Verify content integrity
            if action.get('content_hash'):
                current_hash = hashlib.sha256(action['content'].encode()).hexdigest()[:16]
                if not hmac.compare_digest(action['content_hash'], current_hash):
                    self.logger.log_event("APPROVAL_CONTENT_TAMPERED", AlertSeverity.CRITICAL,
                                         {'id': approval_id[:8]})
                    del self.pending[found_id]
                    return None
            
            approved = self.pending.pop(found_id)
            self.logger.log_event("APPROVAL_GRANTED", AlertSeverity.INFO,
                                 {'id': approval_id[:8], 'type': action['type']})
            return approved
    
    def reject(self, approval_id: str) -> bool:
        with self.lock:
            for pending_id in list(self.pending.keys()):
                if hmac.compare_digest(pending_id, approval_id) or pending_id.startswith(approval_id):
                    del self.pending[pending_id]
                    self.logger.log_event("APPROVAL_REJECTED", AlertSeverity.INFO,
                                         {'id': approval_id[:8]})
                    return True
            return False
    
    def get_all_pending(self) -> Dict[str, Dict]:
        with self.lock:
            now = datetime.now()
            expired = [k for k, v in self.pending.items() 
                      if datetime.fromisoformat(v['expires']) < now]
            for k in expired:
                del self.pending[k]
            return self.pending.copy()
    
    def has_destructive_pending(self) -> bool:
        """Check if any pending actions are destructive (DELETE)."""
        with self.lock:
            return any(a['type'] == 'DELETE' for a in self.pending.values())
    
    def get_destructive_pending(self) -> Dict[str, Dict]:
        """Get only destructive pending actions."""
        with self.lock:
            return {k: v for k, v in self.pending.items() if v['type'] == 'DELETE'}
    
    def clear_all(self) -> int:
        with self.lock:
            count = len(self.pending)
            self.pending.clear()
            return count


# =============================================================================
# ACTION PARSER
# =============================================================================

class ActionParser:
    PATTERN = re.compile(
        r'<action\s+type="(\w+)"(?:\s+target="([^"]*)")?>(.*?)</action>',
        re.DOTALL | re.IGNORECASE
    )
    
    @staticmethod
    def parse(response: str) -> List[Dict]:
        actions = []
        for match in ActionParser.PATTERN.finditer(response):
            actions.append({
                'type': match.group(1).upper(),
                'target': match.group(2) or "",
                'content': match.group(3).strip(),
                'raw': match.group(0)
            })
        return actions
    
    @staticmethod
    def strip_actions(response: str) -> str:
        return ActionParser.PATTERN.sub('', response).strip()


# =============================================================================
# HTTP HANDLER (ENHANCED)
# =============================================================================

class UnifiedProxyHandler(BaseHTTPRequestHandler):
    """HTTP handler with full security integration and transparency."""
    
    config: UnifiedConfig = None
    logger: SecurityLogger = None
    alerts: AlertManager = None
    sanitizer: ContentSanitizer = None
    executor: SecureExecutor = None
    approval_mgr: ApprovalManager = None
    security_policy: str = ""
    agentic_instructions: str = ""
    dual_verifier: DualLLMVerifier = None if not SECURITY_COMPONENTS_AVAILABLE else None
    pii_protector: PIIProtector = None if not SECURITY_COMPONENTS_AVAILABLE else None
    transparency_tracker: 'SessionTransparencyTracker' = None
    credential_redactor: 'CredentialRedactor' = None
    sensitive_detector: 'SensitiveOperationDetector' = None
    
    def log_message(self, format, *args):
        pass  # Suppress default logging
    
    def do_GET(self):
        self._forward_request('GET')
    
    def do_POST(self):
        # Block all requests if policy tampering detected
        if hasattr(self, 'integrity_verifier') and self.integrity_verifier \
                and self.integrity_verifier.is_locked_down:
            self.send_response(503)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                'error': 'Service locked down due to policy integrity violation. Restart required.'
            }).encode())
            return
        
        if self.path in ['/api/chat', '/api/generate']:
            self._handle_chat()
        else:
            self._forward_request('POST')
    
    def do_DELETE(self):
        self._forward_request('DELETE')
    
    def _handle_chat(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else b''
        
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            self._forward_request('POST', body)
            return
        
        # Extract user message
        user_message = ""
        if 'prompt' in data:
            user_message = data['prompt']
        elif 'messages' in data and data['messages']:
            last = data['messages'][-1]
            if isinstance(last, dict):
                user_message = last.get('content', '')
        
        # Check control commands
        ctrl = self._check_control(user_message)
        if ctrl:
            self._send_chat_response(ctrl)
            return
        
        # Sanitize
        sanitized, warnings, trust = self.sanitizer.sanitize(user_message, "user")
        
        # Update message
        if 'prompt' in data:
            data['prompt'] = sanitized
        elif 'messages' in data and data['messages']:
            data['messages'][-1]['content'] = sanitized
        
        # Inject system prompt
        combined = self.security_policy + "\n\n" + self.agentic_instructions
        if 'system' in data:
            data['system'] = combined + "\n\n---\n\n" + data['system']
        else:
            data['system'] = combined
        
        # Forward to Ollama
        response = self._call_ollama(json.dumps(data).encode())
        if response is None:
            self._send_error(502, "Ollama connection failed")
            return
        
        # Extract AI text
        ai_text = ""
        if 'response' in response:
            ai_text = response['response']
        elif 'message' in response:
            ai_text = response['message'].get('content', '')
        
        # Check PII in response (NEW)
        if self.pii_protector:
            pii_check = self.pii_protector.check_response_for_pii(ai_text)
            if pii_check['should_block']:
                self.logger.log_event("PII_IN_RESPONSE", AlertSeverity.HIGH, 
                                     {'types': pii_check['pii_types']})
                ai_text += "\n\n⚠️ **Warning:** This response may contain sensitive information."
        
        # Process actions
        processed = self._process_response(ai_text, user_message)
        
        # Update
        if 'response' in response:
            response['response'] = processed
        elif 'message' in response:
            response['message']['content'] = processed
        
        self._send_json_response(response)
    
    def _check_control(self, msg: str) -> Optional[str]:
        m = msg.strip().upper()
        
        # CONFIRM ALL - but not for destructive actions
        if m == 'CONFIRM ALL':
            # Check for destructive actions first
            if self.approval_mgr.has_destructive_pending():
                destructive = self.approval_mgr.get_destructive_pending()
                lines = ["⚠️ **Cannot batch-approve DELETE actions for safety.**\n"]
                lines.append("The following DELETE action(s) must be confirmed individually:\n")
                for aid, action in destructive.items():
                    lines.append(f"- `CONFIRM {aid[:8]}` to delete `{os.path.basename(action['target'])}`")
                lines.append("\nOther non-destructive actions can be confirmed with `CONFIRM ALL SAFE`")
                return "\n".join(lines)
            return self._execute_all_pending()
        
        # CONFIRM ALL SAFE - only non-destructive
        if m == 'CONFIRM ALL SAFE':
            return self._execute_all_pending(skip_destructive=True)
        
        # REJECT ALL
        if m == 'REJECT ALL':
            count = self.approval_mgr.clear_all()
            if count == 0:
                return "✅ No pending actions to reject."
            if self.transparency_tracker:
                self.transparency_tracker.record_approval(False)
            return f"❌ Rejected and cleared **{count}** pending action(s)."
        
        # CONFIRM single
        match = re.match(r'^CONFIRM\s+([A-Fa-f0-9]+)$', m)
        if match:
            if self.transparency_tracker:
                self.transparency_tracker.record_approval(True)
            return self._execute_approved(match.group(1).lower())
        
        # REJECT single
        match = re.match(r'^REJECT\s+([A-Fa-f0-9]+)$', m)
        if match:
            aid = match.group(1).lower()
            if self.approval_mgr.reject(aid):
                if self.transparency_tracker:
                    self.transparency_tracker.record_approval(False)
                return f"❌ Action `{aid}` rejected."
            return f"⚠️ No action: `{aid}`"
        
        # EXPLAIN - get details about pending action
        match = re.match(r'^EXPLAIN\s+([A-Fa-f0-9]+)$', m)
        if match:
            return self._explain_action(match.group(1).lower())
        
        # REPORT - transparency report
        if m == 'REPORT':
            if self.transparency_tracker:
                return self.transparency_tracker.generate_report()
            return "ℹ️ Transparency tracking not enabled for this session."
        
        # PENDING
        if m == 'PENDING':
            pending = self.approval_mgr.get_all_pending()
            if not pending:
                return "✅ No pending actions."
            lines = ["**Pending Actions:**\n"]
            lines.append("| Type | Target | ID | Sensitive |")
            lines.append("|------|--------|-----|-----------|")
            for aid, a in pending.items():
                short_id = aid[:8]
                icon = "🔴" if a['type'] == "DELETE" else "⚠️"
                short_target = os.path.basename(a['target']) or a['target']
                if len(short_target) > 25:
                    short_target = short_target[:22] + "..."
                sensitivity = "⚠️ Yes" if a.get('sensitivity') else "—"
                lines.append(f"| {icon} {a['type']} | `{short_target}` | `{short_id}` | {sensitivity} |")
            lines.append("\n✅ `CONFIRM ALL` · ❌ `REJECT ALL`")
            lines.append("\nOr confirm/reject individually: `CONFIRM <id>` · `REJECT <id>`")
            lines.append("\nTo see details: `EXPLAIN <id>`")
            return "\n".join(lines)
        
        # STOP
        if m in ['STOP', 'ABORT', 'HALT', 'EMERGENCY STOP']:
            count = self.approval_mgr.clear_all()
            self.alerts.alert(AlertSeverity.WARNING, "EMERGENCY_STOP", f"Cleared {count}")
            return f"🛑 **EMERGENCY STOP** — Cleared {count} action(s)."
        
        # STATUS
        if m == 'STATUS':
            pending_count = len(self.approval_mgr.get_all_pending())
            stats = {
                'session': self.logger.session_id[:8],
                'blocked': self.logger.stats.get('blocked', 0),
                'pending': pending_count,
            }
            return f"**System Status:**\n```json\n{json.dumps(stats, indent=2)}\n```"
        
        # HELP - show available commands
        if m == 'HELP':
            return self._show_help()
        
        return None
    
    def _explain_action(self, approval_id: str) -> str:
        """Provide detailed explanation of a pending action."""
        pending = self.approval_mgr.get_all_pending()
        
        # Find matching action
        found_action = None
        found_id = None
        for aid, action in pending.items():
            if aid.startswith(approval_id) or aid == approval_id:
                found_action = action
                found_id = aid
                break
        
        if not found_action:
            return f"⚠️ No pending action found with ID `{approval_id}`"
        
        lines = [f"## 🔍 Action Details — `{found_id[:8]}`\n"]
        lines.append(f"**Type:** {found_action['type']}")
        lines.append(f"**Target:** `{found_action['target']}`")
        lines.append(f"**Created:** {found_action['created']}")
        lines.append(f"**Expires:** {found_action['expires']}")
        
        # Sensitivity info
        if found_action.get('sensitivity'):
            lines.append("\n### ⚠️ Sensitivity Warning")
            for s in found_action['sensitivity']:
                lines.append(f"- {s['icon']} **{s['category'].upper()}** ({s['severity']})")
        
        # Content preview (redacted)
        if found_action.get('content'):
            content = found_action['content']
            if self.credential_redactor:
                preview = self.credential_redactor.redact_for_preview(content, 200)
            else:
                preview = content[:200] + ('...' if len(content) > 200 else '')
            lines.append(f"\n### Content Preview (credentials redacted)")
            lines.append(f"```\n{preview}\n```")
        
        # What this action will do
        lines.append("\n### What This Action Will Do")
        if found_action['type'] == 'COMMAND':
            lines.append(f"Execute the command `{found_action['target'][:50]}` on your system.")
        elif found_action['type'] == 'READ':
            lines.append(f"Read and display the contents of `{os.path.basename(found_action['target'])}`.")
        elif found_action['type'] == 'WRITE':
            lines.append(f"Create or overwrite the file `{os.path.basename(found_action['target'])}`.")
        elif found_action['type'] == 'DELETE':
            lines.append(f"**PERMANENTLY DELETE** `{os.path.basename(found_action['target'])}`. This cannot be undone!")
        elif found_action['type'] == 'LIST':
            lines.append(f"List the contents of directory `{found_action['target']}`.")
        
        lines.append(f"\n✅ `CONFIRM {found_id[:8]}` · ❌ `REJECT {found_id[:8]}`")
        
        return "\n".join(lines)
    
    def _show_help(self) -> str:
        """Show available user commands."""
        return """## 📖 AIOHAI Commands

### Approval Commands
| Command | Description |
|---------|-------------|
| `CONFIRM <id>` | Approve and execute a specific action |
| `REJECT <id>` | Cancel a specific action |
| `CONFIRM ALL` | Approve all pending non-destructive actions |
| `CONFIRM ALL SAFE` | Same as CONFIRM ALL (excludes DELETE) |
| `REJECT ALL` | Cancel all pending actions |
| `EXPLAIN <id>` | Get detailed info about a pending action |

### Status Commands
| Command | Description |
|---------|-------------|
| `PENDING` | List all pending actions |
| `STATUS` | Show system status |
| `REPORT` | View transparency report (what AI accessed) |
| `HELP` | Show this help message |

### Emergency
| Command | Description |
|---------|-------------|
| `STOP` | Emergency stop - cancel all actions |

### Tips
- Action IDs are 8 characters (e.g., `CONFIRM a1b2c3d4`)
- DELETE actions must be confirmed individually for safety
- Use `REPORT` to see everything the AI accessed this session
"""
    
    def _execute_all_pending(self, skip_destructive: bool = False) -> str:
        """Execute all pending actions in sequence, optionally skipping destructive ones."""
        pending = self.approval_mgr.get_all_pending()
        
        if not pending:
            return "✅ No pending actions to execute."
        
        # Filter out destructive if requested
        if skip_destructive:
            pending = {k: v for k, v in pending.items() if v['type'] != 'DELETE'}
            if not pending:
                return "✅ No non-destructive actions to execute."
        
        results = []
        results.append(f"**Executing {len(pending)} action(s)...**\n")
        
        success_count = 0
        fail_count = 0
        
        for aid, action in list(pending.items()):
            short_id = aid[:8]
            atype = action['type']
            target = action['target']
            content = action['content']
            
            # Remove from pending
            self.approval_mgr.reject(aid)
            
            # Execute based on type
            if atype == 'COMMAND':
                ok, out = self.executor.execute_command(target)
                status = "✅" if ok else "❌"
                cmd_preview = target[:40] + ('...' if len(target) > 40 else '')
                results.append(f"{status} `{short_id}` **COMMAND** — `{cmd_preview}`")
                if not ok:
                    results.append(f"   Error: {out[:100]}")
                    fail_count += 1
                else:
                    success_count += 1
                    
            elif atype == 'READ':
                ok, out = self.executor.read_file(target)
                status = "✅" if ok else "❌"
                results.append(f"{status} `{short_id}` **READ** — `{os.path.basename(target)}`")
                if ok:
                    success_count += 1
                else:
                    fail_count += 1
                    
            elif atype == 'WRITE':
                ok, out = self.executor.write_file(target, content)
                status = "✅" if ok else "❌"
                results.append(f"{status} `{short_id}` **WRITE** — `{os.path.basename(target)}`")
                if ok:
                    success_count += 1
                else:
                    results.append(f"   Error: {out[:100]}")
                    fail_count += 1
                    
            elif atype == 'LIST':
                ok, out = self.executor.list_directory(target)
                status = "✅" if ok else "❌"
                results.append(f"{status} `{short_id}` **LIST** — `{os.path.basename(target) or target}`")
                if ok:
                    success_count += 1
                else:
                    fail_count += 1
                    
            elif atype == 'DELETE':
                # This should only execute if skip_destructive is False
                ok, out = self.executor.delete_file(target)
                status = "✅" if ok else "❌"
                results.append(f"{status} `{short_id}` **DELETE** — `{os.path.basename(target)}`")
                if ok:
                    success_count += 1
                else:
                    results.append(f"   Error: {out[:100]}")
                    fail_count += 1
        
        results.append(f"\n**Complete:** {success_count} succeeded, {fail_count} failed")
        
        return "\n".join(results)
    
    def _execute_approved(self, aid: str) -> str:
        action = self.approval_mgr.approve(aid)
        if not action:
            return f"⚠️ No action: `{aid}` (expired?)"
        
        atype = action['type']
        target = action['target']
        content = action['content']
        
        # Dual LLM verification (NEW)
        if self.dual_verifier and self.config.enable_dual_llm:
            result = self.dual_verifier.verify_action(atype, target, content, "user request")
            if result.verdict == Verdict.BLOCKED:
                self.logger.log_blocked("DUAL_LLM", target, result.reasoning)
                return f"❌ Blocked by security verification:\n{result.reasoning}"
            elif result.verdict == Verdict.DANGEROUS:
                return f"⚠️ **High Risk Action**\nConcerns: {', '.join(result.concerns)}\n\nType `FORCE {aid}` to proceed anyway."
        
        if atype == 'COMMAND':
            ok, out = self.executor.execute_command(target)
            return f"**Command Result:**\n```\n{out}\n```"
        elif atype == 'READ':
            ok, out = self.executor.read_file(target)
            return f"**File `{target}`:**\n```\n{out}\n```" if ok else out
        elif atype == 'WRITE':
            ok, out = self.executor.write_file(target, content)
            return out
        elif atype == 'LIST':
            ok, out = self.executor.list_directory(target)
            return out
        elif atype == 'DELETE':
            ok, out = self.executor.delete_file(target)
            return out
        
        return f"⚠️ Unknown: {atype}"
    
    def _process_response(self, response: str, user_request: str) -> str:
        actions = ActionParser.parse(response)
        clean = ActionParser.strip_actions(response)
        
        if not actions:
            return response
        
        lines = []
        action_ids = []
        
        for a in actions:
            atype, target, content = a['type'], a['target'], a['content']
            
            # ----- Pre-approval validation (Phase 5) -----
            # Validate paths BEFORE creating an approval, so the user gets
            # immediate feedback on blocked/tier-3 actions.
            if atype in ('READ', 'WRITE', 'DELETE', 'LIST') and target:
                is_safe, resolved, reason = self.executor.path_validator.validate(target)
                if not is_safe:
                    self.logger.log_blocked(f"PRE_APPROVAL_{atype}", target, reason)
                    lines.append(
                        f"\n\n---\n### 🚫 Blocked: {atype} `{os.path.basename(target)}`"
                        f"\n\nPath rejected by security policy: **{reason}**"
                        f"\n\nThis path is permanently blocked and cannot be accessed "
                        f"regardless of approval tier."
                    )
                    continue
                # Tier-3 paths: still create approval but tag it for FIDO2
                tier3_required = (reason == "Tier 3 required")
            elif atype == 'COMMAND' and target:
                is_safe, reason = self.executor.command_validator.validate(target)
                if not is_safe:
                    self.logger.log_blocked("PRE_APPROVAL_COMMAND", target, reason)
                    lines.append(
                        f"\n\n---\n### 🚫 Blocked: COMMAND"
                        f"\n\nCommand rejected by security policy: **{reason}**"
                    )
                    continue
                tier3_required = False
            else:
                tier3_required = False
            
            # ----- Create approval request -----
            try:
                aid = self.approval_mgr.create_request(atype, target, content)
            except Exception as e:
                lines.append(f"\n\n---\n### 🚫 Action Blocked\n\n{str(e)}")
                continue
            
            # Tag the pending approval with tier-3 if needed
            if tier3_required:
                with self.approval_mgr.lock:
                    if aid in self.approval_mgr.pending:
                        self.approval_mgr.pending[aid]['tier3_required'] = True
            
            short_id = aid[:8]
            action_ids.append((short_id, atype, target))
            card = self._format_action_card(atype, target, content, short_id)
            
            # Prepend tier-3 warning to the action card
            if tier3_required:
                card = (
                    f"\n\n---\n### 🔐 Hardware Approval Required"
                    f"\n\nThis action targets sensitive data and requires "
                    f"**FIDO2 hardware key tap** or **biometric verification**."
                    + card
                )
            
            lines.append(card)
        
        if len(action_ids) > 1:
            lines.append(self._format_action_summary(action_ids))
        
        return clean + "".join(lines)
    
    def _format_action_card(self, atype: str, target: str, content: str, short_id: str) -> str:
        """Format a single action into a user-facing approval card."""
        # Check sensitivity
        sensitivity_warning = ""
        if self.sensitive_detector:
            matches = self.sensitive_detector.detect(target, content)
            if matches:
                sensitivity_warning = f"\n\n{self.sensitive_detector.format_warning(matches)}"
        
        confirm_line = (f"✅ `CONFIRM {short_id}` · ❌ `REJECT {short_id}` "
                        f"· ❓ `EXPLAIN {short_id}`")
        
        action_configs = {
            'COMMAND': {
                'icon': '⚠️', 'verb': 'Execute a system command',
                'desc': self._summarize_command(target),
            },
            'READ': {
                'icon': '⚠️', 'verb': 'Read a file from disk',
                'desc': f"Open and display the contents of `{os.path.basename(target)}`",
            },
            'WRITE': {
                'icon': '⚠️', 'verb': 'Create or overwrite a file',
                'desc': self._format_write_preview(target, content),
            },
            'LIST': {
                'icon': '⚠️', 'verb': 'Show directory contents',
                'desc': f"List all files and folders in `{os.path.basename(target) or target}`",
            },
            'DELETE': {
                'icon': '🔴', 'verb': 'Permanently remove file or folder',
                'desc': f"**⚠️ This action is irreversible!**\n\nDelete `{os.path.basename(target)}`",
            },
        }
        
        cfg = action_configs.get(atype, {
            'icon': '⚠️', 'verb': atype, 'desc': target
        })
        
        return (f"\n\n---\n"
                f"### {cfg['icon']} {atype} — {cfg['verb']}\n\n"
                f"{cfg['desc']}{sensitivity_warning}\n\n"
                f"```\n📋 {target}\n🔑 {short_id}\n```\n\n"
                f"{confirm_line}")
    
    def _format_write_preview(self, target: str, content: str) -> str:
        """Format write action with credential-redacted preview."""
        if self.credential_redactor:
            preview = self.credential_redactor.redact_for_preview(content, 100)
        else:
            preview = content[:100].replace('\n', ' ') + ('...' if len(content) > 100 else '')
        return f"Write {len(content)} bytes to `{os.path.basename(target)}`\n\n**Preview:** {preview}"
    
    def _format_action_summary(self, action_ids: list) -> str:
        """Format the multi-action summary table with batch commands."""
        has_destructive = any(atype == 'DELETE' for _, atype, _ in action_ids)
        
        lines = ["\n\n---\n### 📋 Summary — Multiple Actions Pending\n"]
        lines.append("| # | Type | Target | ID |")
        lines.append("|---|------|--------|-----|")
        
        for i, (sid, atype, target) in enumerate(action_ids, 1):
            icon = "🔴" if atype == "DELETE" else "⚠️"
            short_target = os.path.basename(target) or target
            if len(short_target) > 30:
                short_target = short_target[:27] + "..."
            lines.append(f"| {i} | {icon} {atype} | `{short_target}` | `{sid}` |")
        
        lines.append("\n**Batch Commands:**\n")
        
        if has_destructive:
            lines.append("✅ `CONFIRM ALL SAFE` — Approve non-destructive actions only\n")
            lines.append("❌ `REJECT ALL` — Cancel all pending actions\n")
            lines.append("\n⚠️ **Warning:** DELETE actions must be confirmed individually for safety.")
        else:
            lines.append("✅ `CONFIRM ALL` — Approve and execute all actions in sequence\n")
            lines.append("❌ `REJECT ALL` — Cancel all pending actions\n")
        
        return "\n".join(lines)
    
    def _summarize_command(self, command: str) -> str:
        """Generate a plain-English summary of a command."""
        cmd_lower = command.lower()
        
        # Common command summaries
        if cmd_lower.startswith('mkdir'):
            return "Create new folder(s)"
        elif cmd_lower.startswith('dir') or cmd_lower.startswith('ls'):
            return "List directory contents"
        elif cmd_lower.startswith('cd'):
            return "Change directory"
        elif cmd_lower.startswith('copy') or cmd_lower.startswith('cp'):
            return "Copy file(s)"
        elif cmd_lower.startswith('move') or cmd_lower.startswith('mv'):
            return "Move or rename file(s)"
        elif cmd_lower.startswith('del') or cmd_lower.startswith('rm'):
            return "Delete file(s)"
        elif cmd_lower.startswith('type') or cmd_lower.startswith('cat'):
            return "Display file contents"
        elif cmd_lower.startswith('echo'):
            return "Print text or write to file"
        elif cmd_lower.startswith('ipconfig') or cmd_lower.startswith('ifconfig'):
            return "Show network configuration"
        elif cmd_lower.startswith('ping'):
            return "Test network connectivity"
        elif cmd_lower.startswith('docker'):
            return "Run Docker command"
        elif cmd_lower.startswith('git'):
            return "Run Git command"
        elif cmd_lower.startswith('pip') or cmd_lower.startswith('npm'):
            return "Package manager command"
        elif cmd_lower.startswith('python'):
            return "Run Python script or command"
        elif cmd_lower.startswith('powershell'):
            return "Run PowerShell command"
        elif 'systeminfo' in cmd_lower:
            return "Get system information"
        elif 'tasklist' in cmd_lower:
            return "List running processes"
        elif 'netstat' in cmd_lower:
            return "Show network connections"
        else:
            # Generic summary - just use the first word/command
            first_word = command.split()[0] if command.split() else "command"
            return f"Execute `{first_word}`"
    
    def _call_ollama(self, body: bytes) -> Optional[Dict]:
        url = f"http://{self.config.ollama_host}:{self.config.ollama_port}{self.path}"
        try:
            req = urllib.request.Request(url, data=body, method='POST')
            req.add_header('Content-Type', 'application/json')
            with urllib.request.urlopen(req, timeout=300) as resp:
                return json.loads(resp.read())
        except Exception as e:
            self.logger.log_event("OLLAMA_ERROR", AlertSeverity.HIGH, {'error': str(e)})
            return None
    
    def _forward_request(self, method: str, body: bytes = None):
        if body is None:
            cl = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(cl) if cl > 0 else b''
        
        url = f"http://{self.config.ollama_host}:{self.config.ollama_port}{self.path}"
        try:
            req = urllib.request.Request(url, data=body if body else None, method=method)
            req.add_header('Content-Type', 'application/json')
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = resp.read()
                self.send_response(resp.status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', len(data))
                self.end_headers()
                self.wfile.write(data)
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            data = e.read()
            self.send_header('Content-Length', len(data))
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            self._send_error(502, str(e))
    
    def _send_chat_response(self, text: str):
        resp = {'model': 'aiohai', 'created_at': datetime.now().isoformat(),
                'response': text, 'done': True}
        self._send_json_response(resp)
    
    def _send_json_response(self, data: Dict):
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)
    
    def _send_error(self, code: int, msg: str):
        body = json.dumps({'error': msg}).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


# =============================================================================
# AGENTIC INSTRUCTIONS
# =============================================================================

AGENTIC_INSTRUCTIONS = """
## AGENTIC CAPABILITIES

You can interact with the Windows operating system using XML action tags.

### Available Actions:

**Execute command:**
```
<action type="COMMAND" target="command here"></action>
```

**Read file:**
```
<action type="READ" target="C:\\path\\to\\file.txt"></action>
```

**Write file:**
```
<action type="WRITE" target="C:\\path\\to\\file.txt">
content here
</action>
```

**List directory:**
```
<action type="LIST" target="C:\\path"></action>
```

**Delete:**
```
<action type="DELETE" target="C:\\path\\to\\file"></action>
```

### RULES:
1. ALL actions require user approval (CONFIRM command)
2. NEVER access credential files, SSH keys, or .env files
3. NEVER use encoded commands or obfuscated scripts
4. ALWAYS explain what you're doing and why
5. For DELETE, warn the user clearly
"""


# =============================================================================
# MAIN PROXY
# =============================================================================

class UnifiedSecureProxy:
    """Complete unified secure proxy with all security fixes."""
    
    def __init__(self, config: UnifiedConfig = None):
        self.config = config or UnifiedConfig()
        
        # Create directories
        self.config.log_dir.mkdir(parents=True, exist_ok=True)
        self.config.secure_temp_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.logger = SecurityLogger(self.config)
        self.alerts = AlertManager(self.config, self.logger)
        self.startup = StartupSecurityVerifier(self.config, self.logger, self.alerts)
        self.integrity = IntegrityVerifier(self.config, self.logger, self.alerts)
        self.network = NetworkInterceptor(self.config, self.logger, self.alerts)
        self.sanitizer = ContentSanitizer(self.logger, self.alerts)
        self.path_validator = PathValidator(self.config, self.logger)
        self.command_validator = CommandValidator(self.config, self.logger)
        self.executor = SecureExecutor(self.config, self.logger, self.alerts,
                                       self.path_validator, self.command_validator)
        self.approval_mgr = ApprovalManager(self.config, self.logger)
        
        # Initialize HSM (must happen after logger, before components that need it)
        self.hsm_manager = None
        if HSM_AVAILABLE and self.config.hsm_enabled:
            try:
                self.hsm_manager = get_hsm_manager(
                    use_mock=self.config.hsm_use_mock,
                )
                success, msg = self.hsm_manager.initialize()
                if success:
                    self.logger.log_event("HSM_INITIALIZED", AlertSeverity.INFO, {'message': msg})
                    # Login if PIN provided
                    if self.config.hsm_pin:
                        login_ok, login_msg = self.hsm_manager.login(self.config.hsm_pin)
                        if not login_ok:
                            self.logger.log_event("HSM_LOGIN_FAILED", AlertSeverity.HIGH,
                                                  {'error': login_msg})
                            if self.config.hsm_required:
                                raise SecurityError(f"HSM login failed: {login_msg}")
                            self.hsm_manager = None
                else:
                    self.logger.log_event("HSM_INIT_FAILED", AlertSeverity.HIGH, {'error': msg})
                    if self.config.hsm_required:
                        raise SecurityError(f"HSM required but initialization failed: {msg}")
                    self.hsm_manager = None
            except SecurityError:
                raise  # Re-raise intentional failures
            except Exception as e:
                self.logger.log_event("HSM_INIT_ERROR", AlertSeverity.HIGH, {'error': str(e)})
                if self.config.hsm_required:
                    raise SecurityError(f"HSM required but unavailable: {e}")
                self.hsm_manager = None
        
        # Wire HSM to logger for log signing
        if self.hsm_manager:
            self.logger.set_hsm_manager(self.hsm_manager)
        
        # Optional dual LLM
        if SECURITY_COMPONENTS_AVAILABLE and self.config.enable_dual_llm:
            self.dual_verifier = DualLLMVerifier(
                self.config.ollama_host, self.config.ollama_port
            )
        else:
            self.dual_verifier = None
        
        # PII protector
        if SECURITY_COMPONENTS_AVAILABLE:
            self.pii_protector = PIIProtector()
        else:
            self.pii_protector = None
        
        # Initialize FIDO2/WebAuthn system
        self.fido2_server = None
        self.fido2_client = None
        if FIDO2_AVAILABLE and self.config.fido2_enabled:
            self.fido2_server, self.fido2_client = self._initialize_fido2()
        
        # Load policy
        self.policy = self._load_policy()
    
    def _load_policy(self) -> str:
        if self.config.policy_file.exists():
            content = self.config.policy_file.read_text(encoding='utf-8')
            self.logger.log_event("POLICY_LOADED", AlertSeverity.INFO, {'size': len(content)})
            return content
        self.logger.log_event("POLICY_NOT_FOUND", AlertSeverity.WARNING, {})
        return ""
    
    def _verify_policy_with_hsm(self) -> bool:
        """Verify policy file signature using HSM.
        
        Returns True if:
          - HSM verifies the signature successfully, OR
          - HSM is not connected and not required (graceful degradation)
        Returns False if:
          - Signature verification fails, OR
          - Signature file is missing and HSM is required
        """
        if not self.hsm_manager or not self.hsm_manager.is_connected():
            self.logger.log_event("POLICY_HSM_SKIP", AlertSeverity.WARNING,
                                  {'reason': 'HSM not connected'})
            return not self.config.hsm_required
        
        # Read policy content
        if not self.config.policy_file.exists():
            self.logger.log_event("POLICY_HSM_FAILED", AlertSeverity.CRITICAL,
                                  {'error': 'Policy file not found'})
            return False
        
        policy_content = self.config.policy_file.read_bytes()
        
        # Read signature file
        if not self.config.policy_signature_file.exists():
            self.logger.log_event("POLICY_SIG_MISSING", AlertSeverity.WARNING,
                                  {'sig_path': str(self.config.policy_signature_file)})
            return not self.config.hsm_required
        
        signature = self.config.policy_signature_file.read_bytes()
        
        # Verify with HSM
        try:
            result = self.hsm_manager.verify_policy_signature(policy_content, signature)
        except Exception as e:
            self.logger.log_event("POLICY_HSM_ERROR", AlertSeverity.CRITICAL,
                                  {'error': str(e)})
            return False
        
        if result.is_valid:
            self.logger.log_event("POLICY_HSM_VERIFIED", AlertSeverity.INFO, {
                'hash': result.policy_hash[:16],
                'signer': result.signer_key_id or 'unknown',
            })
            print("  ✓ HSM signature verified")
            return True
        
        self.logger.log_event("POLICY_HSM_FAILED", AlertSeverity.CRITICAL, {
            'hash': result.policy_hash[:16],
            'error': result.error_message or 'Verification failed',
        })
        print(f"  ✗ HSM verification failed: {result.error_message}")
        return False
    
    def _initialize_fido2(self):
        """Initialize FIDO2/WebAuthn approval system."""
        try:
            # Build FIDO2 server config
            fido2_config = {
                'host': self.config.fido2_server_host,
                'port': self.config.fido2_server_port,
                'rp_id': 'localhost',  # Will need to match actual domain/IP
                'rp_name': 'AIOHAI',
                'origin': f'https://localhost:{self.config.fido2_server_port}',
                'storage_path': str(self.config.base_dir / 'data' / 'fido2'),
                'request_expiry_minutes': self.config.approval_expiry_minutes,
            }
            
            # Create server and client (pin cert for SSL verification)
            cert_dir = self.config.base_dir / 'data' / 'ssl'
            cert_file = str(cert_dir / 'aiohai.crt')
            fido2_server = FIDO2ApprovalServer(fido2_config)
            fido2_client = FIDO2ApprovalClient(server=fido2_server,
                                                cert_path=cert_file)
            
            users = fido2_server.credential_store.get_all_users()
            self.logger.log_event("FIDO2_INITIALIZED", AlertSeverity.INFO, {
                'users': len(users),
            })
            
            return fido2_server, fido2_client
            
        except Exception as e:
            self.logger.log_event("FIDO2_INIT_FAILED", AlertSeverity.WARNING, {
                'error': str(e)
            })
            print(f"  ⚠  FIDO2 initialization failed: {e}")
            return None, None
    
    def _start_hsm_monitor(self):
        """Background thread that checks HSM health and attempts reconnection."""
        HSM_CHECK_INTERVAL = HSM_HEALTH_CHECK_INTERVAL
        
        def _monitor():
            was_connected = self.hsm_manager is not None and self.hsm_manager.is_connected()
            while True:
                time.sleep(HSM_CHECK_INTERVAL)
                if not self.hsm_manager:
                    continue
                
                is_connected = self.hsm_manager.is_connected()
                
                if was_connected and not is_connected:
                    # HSM disconnected — log degradation
                    self.logger.log_event("HSM_DISCONNECTED", AlertSeverity.HIGH, {
                        'impact': 'Log signing disabled, falling back to software mode'
                    })
                    print("\n  ⚠  HSM disconnected — running in degraded mode")
                
                elif not was_connected and not is_connected:
                    # Still disconnected — try to reconnect
                    try:
                        success, msg = self.hsm_manager.initialize()
                        if success and self.config.hsm_pin:
                            login_ok, _ = self.hsm_manager.login(self.config.hsm_pin)
                            if login_ok:
                                self.logger.set_hsm_manager(self.hsm_manager)
                                self.logger.log_event("HSM_RECONNECTED", AlertSeverity.INFO, {})
                                print("\n  ✓ HSM reconnected")
                                is_connected = True
                    except Exception as e:
                        self.logger.log_event("HSM_RECONNECT_FAILED", AlertSeverity.WARNING,
                                              {'error': str(e)})
                
                was_connected = is_connected
        
        t = threading.Thread(target=_monitor, daemon=True)
        t.start()
        return t
    
    def _start_approval_server(self):
        """Start the FIDO2 approval web server in a background thread."""
        if not self.fido2_server:
            return
        
        try:
            # Connect HSM for signing approvals if available
            if self.hsm_manager:
                self.fido2_server.set_hsm_manager(self.hsm_manager)
            
            # Start HTTPS server (threaded=True → runs in background)
            cert_dir = self.config.base_dir / 'data' / 'ssl'
            self.fido2_server.start(
                use_ssl=True,
                cert_dir=cert_dir,
                threaded=True,
            )
            
            self.logger.log_event("APPROVAL_SERVER_STARTED", AlertSeverity.INFO, {
                'port': self.config.fido2_server_port,
            })
            
        except Exception as e:
            print(f"  ⚠  Approval server failed to start: {e}")
            self.logger.log_event("APPROVAL_SERVER_FAILED", AlertSeverity.WARNING, {
                'error': str(e)
            })
    
    def _print_startup_banner(self):
        """Print the full status banner after all startup steps complete."""
        print("\n" + "=" * 70)
        print("PROXY ACTIVE - v3.0 WITH HARDWARE SECURITY + FIDO2")
        print("=" * 70)
        print(f"Listen:   http://{self.config.listen_host}:{self.config.listen_port}")
        print(f"Ollama:   http://{self.config.ollama_host}:{self.config.ollama_port}")
        print(f"Policy:   {'✓ Loaded' if self.policy else '✗ Not found'}")
        print(f"Session:  {self.logger.session_id}")
        
        if self.hsm_manager and self.hsm_manager.is_connected():
            print("HSM:      ✓ Connected (logs signed)")
        elif self.config.hsm_enabled:
            print("HSM:      ⚠ Enabled but not connected")
        else:
            print("HSM:      ○ Disabled")
        
        if self.fido2_server:
            import socket as _sock
            try:
                _s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
                _s.connect(("8.8.8.8", 80))
                _local_ip = _s.getsockname()[0]
                _s.close()
            except Exception:
                _local_ip = "your-server-ip"
            print(f"FIDO2:    ✓ Active (approve at https://{_local_ip}:{self.config.fido2_server_port})")
        elif self.config.fido2_enabled:
            print("FIDO2:    ⚠ Enabled but not initialized")
        else:
            print("FIDO2:    ○ Disabled")
        
        print("=" * 70)
        print("\nSECURITY FEATURES (v3.0):")
        
        if self.hsm_manager and self.hsm_manager.is_connected():
            print("  🔐 HSM: Policy signature verified at startup")
            print("  🔐 HSM: Log entries signed (tamper-evident)")
            print("  🔐 HSM: Secure random generation")
        if self.fido2_server:
            print("  📱 FIDO2: TIER 3 ops require Face ID / Nitrokey NFC tap")
            print("  📱 FIDO2: Multi-user family permissions")
            print("  📱 FIDO2: WebAuthn challenge-response (no replay)")
        
        features = [
            "Credential redaction in previews",
            "DELETE actions require hardware approval",
            "Approval rate limiting (max 10 pending)",
            "Session binding with integrity verification",
            "Transparency tracking (REPORT command)",
            "Sensitive operation detection",
            "Financial/personal data path blocking",
            "Enhanced clipboard blocking (all methods)",
            "Docker registry whitelisting",
            "Smart home config scanning",
            "Network interception + DoH blocking",
            "Static security analysis (Bandit-style)",
            "PII protection in logs and responses",
            "Multi-stage attack detection",
        ]
        if self.config.enable_dual_llm:
            features.append("Dual-LLM verification enabled")
        for f in features:
            print(f"  ✓ {f}")
        
        print("=" * 70)
        print("\nCOMMANDS: HELP | PENDING | REPORT | STATUS | EXPLAIN <id>")
        print("          CONFIRM <id> | REJECT <id> | CONFIRM ALL | STOP")
        print("=" * 70)
        print("\nPress Ctrl+C to stop\n")
    
    def start(self) -> None:
        print("=" * 70)
        print("AIOHAI Unified Proxy v3.0 - HARDWARE SECURITY + FIDO2 APPROVAL")
        print("=" * 70)
        
        # Fail-secure: refuse to start without security components unless explicitly allowed
        if not SECURITY_COMPONENTS_AVAILABLE:
            if self.config.allow_degraded_security:
                print("\n  ⚠  DEGRADED MODE: Security components unavailable")
                print("     Static analysis, PII protection, resource limits DISABLED")
                self.logger.log_event("DEGRADED_MODE", AlertSeverity.HIGH, {
                    'reason': 'Security components import failed',
                })
            else:
                print("\n  ✗ SECURITY COMPONENTS UNAVAILABLE")
                print("    Cannot start without security components.")
                print("    Use --allow-degraded flag to override (NOT recommended).")
                sys.exit(1)
        
        # 0. HSM Status (if enabled)
        if self.config.hsm_enabled:
            print("\n[0/8] Hardware Security Module...")
            if self.hsm_manager and self.hsm_manager.is_connected():
                print("  ✓ Nitrokey HSM connected and authenticated")
                keys = self.hsm_manager.list_keys()
                if keys:
                    print(f"  ✓ {len(keys)} keys available")
            elif self.config.hsm_required:
                print("  ✗ HSM required but not connected")
                sys.exit(1)
            else:
                print("  ⚠ HSM not connected (running without hardware security)")
        
        # 1. Startup checks
        print("\n[1/8] Startup security checks...")
        ok, issues = self.startup.verify_all()
        for i in issues:
            print(f"  {'✗' if 'CRITICAL' in i else '⚠'} {i}")
        if not ok:
            print("\n❌ FAILED")
            sys.exit(1)
        print("  ✓ Passed")
        
        # 2. Policy integrity (software)
        print("\n[2/8] Policy integrity (software hash)...")
        if not self.integrity.verify_policy():
            print("  ✗ FAILED")
            sys.exit(1)
        print("  ✓ Hash verified")
        
        # 3. Policy HSM signature
        if self.config.hsm_enabled:
            print("\n[3/8] Policy integrity (HSM signature)...")
            if not self._verify_policy_with_hsm():
                if self.config.hsm_required:
                    print("\n❌ HSM POLICY VERIFICATION FAILED")
                    sys.exit(1)
        else:
            print("\n[3/8] Policy HSM verification... SKIPPED")
        
        # 4. Network
        print("\n[4/8] Network interceptor...")
        self.network.install_hooks()
        print("  ✓ Hooks active (including DoH blocking)")
        
        # 5. Integrity monitoring
        print("\n[5/8] Integrity monitoring...")
        self.integrity.start_monitoring()
        print("  ✓ Active (10s interval)")
        
        # HSM health monitor (if HSM was initialized)
        if self.hsm_manager:
            self._start_hsm_monitor()
            print("  ✓ HSM health monitor active (30s interval)")
        
        # 6. FIDO2/WebAuthn system
        if self.config.fido2_enabled:
            print("\n[6/8] FIDO2/WebAuthn approval system...")
            if self.fido2_server:
                users = self.fido2_server.credential_store.get_all_users()
                total_creds = sum(len(u.credentials) for u in users.values())
                print(f"  ✓ {len(users)} users, {total_creds} devices registered")
                if self.config.fido2_auto_start_server:
                    self._start_approval_server()
                    import socket
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        s.connect(("8.8.8.8", 80))
                        local_ip = s.getsockname()[0]
                        s.close()
                    except Exception:
                        local_ip = "localhost"
                    print(f"  ✓ Approval URL: https://{local_ip}:{self.config.fido2_server_port}")
                    if not users:
                        print(f"  ⚠ No users registered. Visit https://{local_ip}:{self.config.fido2_server_port}/register")
            else:
                print("  ⚠ FIDO2 not initialized (missing dependencies?)")
        else:
            print("\n[6/8] FIDO2 approval system... SKIPPED")
        
        # 7. Configure handler
        print("\n[7/8] Configuring request handler...")
        
        # Initialize transparency tracker
        transparency_tracker = None
        credential_redactor = None
        sensitive_detector = None
        
        if SECURITY_COMPONENTS_AVAILABLE:
            transparency_tracker = SessionTransparencyTracker(self.logger.session_id)
            credential_redactor = CredentialRedactor()
            sensitive_detector = SensitiveOperationDetector()
            self.executor.transparency = transparency_tracker
        
        # Configure handler
        UnifiedProxyHandler.config = self.config
        UnifiedProxyHandler.logger = self.logger
        UnifiedProxyHandler.alerts = self.alerts
        UnifiedProxyHandler.sanitizer = self.sanitizer
        UnifiedProxyHandler.executor = self.executor
        UnifiedProxyHandler.approval_mgr = self.approval_mgr
        UnifiedProxyHandler.security_policy = self.policy
        UnifiedProxyHandler.agentic_instructions = AGENTIC_INSTRUCTIONS
        UnifiedProxyHandler.dual_verifier = self.dual_verifier
        UnifiedProxyHandler.pii_protector = self.pii_protector
        UnifiedProxyHandler.transparency_tracker = transparency_tracker
        UnifiedProxyHandler.credential_redactor = credential_redactor
        UnifiedProxyHandler.sensitive_detector = sensitive_detector
        UnifiedProxyHandler.hsm_manager = self.hsm_manager
        UnifiedProxyHandler.fido2_client = self.fido2_client  # FIDO2 for TIER 3
        UnifiedProxyHandler.fido2_server = self.fido2_server
        UnifiedProxyHandler.integrity_verifier = self.integrity
        print("  ✓ Configured")
        
        # 8. Start server
        print("\n[8/8] Starting HTTP proxy server...")
        
        addr = (self.config.listen_host, self.config.listen_port)
        
        try:
            httpd = ThreadedHTTPServer(addr, UnifiedProxyHandler)
            
            self._print_startup_banner()
            
            self.logger.log_event("PROXY_STARTED", AlertSeverity.INFO, {
                'version': '3.0.0',
                'listen': f"{self.config.listen_host}:{self.config.listen_port}",
                'hsm_connected': self.hsm_manager is not None and self.hsm_manager.is_connected(),
                'fido2_active': self.fido2_client is not None,
            })
            
            httpd.serve_forever()
            
        except KeyboardInterrupt:
            print("\n\nShutting down...")
        except Exception as e:
            self.logger.log_event("PROXY_ERROR", AlertSeverity.CRITICAL, {'error': str(e)})
            raise
        finally:
            self.integrity.stop_monitoring()
            self.alerts.shutdown()
            # Logout from HSM
            if self.hsm_manager:
                self.hsm_manager.logout()
            self.logger.log_event("PROXY_STOPPED", AlertSeverity.INFO, {})


# =============================================================================
# ENTRY POINT
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description='AIOHAI Unified Proxy v3.0 with Hardware Security')
    parser.add_argument('--listen-port', type=int, default=11435)
    parser.add_argument('--ollama-port', type=int, default=11434)
    parser.add_argument('--base-dir', default=r'C:\AIOHAI')
    parser.add_argument('--policy', help='Policy file path')
    parser.add_argument('--enable-dual-llm', action='store_true',
                       help='Enable Dual-LLM verification')
    parser.add_argument('--no-network-control', action='store_true')
    parser.add_argument('--no-file-scan', action='store_true',
                       help='Disable file content scanning')
    
    # HSM arguments
    parser.add_argument('--no-hsm', action='store_true',
                       help='Disable HSM integration')
    parser.add_argument('--hsm-optional', action='store_true',
                       help='Allow startup without HSM')
    parser.add_argument('--hsm-mock', action='store_true',
                       help='Use mock HSM for testing (NO SECURITY)')
    parser.add_argument('--hsm-pin', help='HSM PIN (will prompt if not provided)')
    
    # FIDO2 arguments
    parser.add_argument('--no-fido2', action='store_true',
                       help='Disable FIDO2/WebAuthn hardware approval')
    parser.add_argument('--fido2-port', type=int, default=8443,
                       help='Approval server HTTPS port (default: 8443)')
    parser.add_argument('--no-approval-server', action='store_true',
                       help='Disable auto-start of approval web server')
    parser.add_argument('--allow-degraded', action='store_true',
                       help='Allow startup without security components (NOT recommended)')
    
    args = parser.parse_args()
    
    config = UnifiedConfig()
    config.listen_port = args.listen_port
    config.ollama_port = args.ollama_port
    config.base_dir = Path(args.base_dir)
    config.enforce_network_allowlist = not args.no_network_control
    config.scan_file_content = not args.no_file_scan
    config.enable_dual_llm = args.enable_dual_llm
    config.allow_degraded_security = args.allow_degraded
    
    # HSM configuration
    config.hsm_enabled = not args.no_hsm
    config.hsm_required = not args.hsm_optional
    config.hsm_use_mock = args.hsm_mock
    if args.hsm_pin:
        config.hsm_pin = args.hsm_pin
    
    # FIDO2 configuration
    config.fido2_enabled = not args.no_fido2
    config.fido2_server_port = args.fido2_port
    config.fido2_auto_start_server = not args.no_approval_server
    
    if args.policy:
        config.policy_file = Path(args.policy)
    
    proxy = UnifiedSecureProxy(config)
    proxy.start()


if __name__ == '__main__':
    main()
