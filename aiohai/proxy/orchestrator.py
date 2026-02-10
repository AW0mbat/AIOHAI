#!/usr/bin/env python3
"""
Proxy Orchestrator — Main startup and component wiring.

UnifiedSecureProxy is the top-level class that initializes all security
components, wires them together, runs startup checks, and starts the
HTTP proxy server.

Phase 5 extraction from proxy/aiohai_proxy.py.
"""

import argparse
import json
import os
import sys
import time
import threading
import socket
from pathlib import Path
from typing import Optional

from aiohai.core.types import SecurityError, AlertSeverity
from aiohai.core.constants import HSM_HEALTH_CHECK_INTERVAL
from aiohai.core.version import ALLOWED_FRAMEWORK_NAMES
from aiohai.core.templates import AGENTIC_INSTRUCTIONS
from aiohai.core.config import UnifiedConfig
from aiohai.core.audit.logger import SecurityLogger
from aiohai.core.audit.alerts import AlertManager
from aiohai.core.audit.startup import StartupSecurityVerifier
from aiohai.core.audit.integrity import IntegrityVerifier
from aiohai.core.network.interceptor import NetworkInterceptor
from aiohai.core.analysis.sanitizer import ContentSanitizer
from aiohai.core.access.path_validator import PathValidator
from aiohai.core.access.command_validator import CommandValidator

from aiohai.proxy.executor import SecureExecutor
from aiohai.proxy.approval import ApprovalManager
from aiohai.proxy.handler import UnifiedProxyHandler, HandlerContext
from aiohai.proxy.server import ThreadedHTTPServer
from aiohai.proxy.circuit_breaker import OllamaCircuitBreaker

__all__ = ['UnifiedSecureProxy', 'main']


# Optional imports — degrade gracefully
_SECURITY_COMPONENTS_AVAILABLE = False
try:
    from aiohai.core.analysis.pii_protector import PIIProtector
    from aiohai.core.analysis.credentials import CredentialRedactor
    from aiohai.core.analysis.sensitive_ops import SensitiveOperationDetector
    from aiohai.core.audit.transparency import SessionTransparencyTracker
    from aiohai.proxy.dual_llm import DualLLMVerifier
    _SECURITY_COMPONENTS_AVAILABLE = True
except ImportError:
    pass

_HSM_AVAILABLE = False
try:
    from aiohai.core.crypto.hsm_bridge import get_hsm_manager
    _HSM_AVAILABLE = True
except ImportError:
    pass

_FIDO2_AVAILABLE = False
try:
    from aiohai.core.crypto.fido_gate import FIDO2ApprovalServer, FIDO2ApprovalClient
    _FIDO2_AVAILABLE = True
except ImportError:
    pass

# Integration imports (optional)
_SMART_HOME_AVAILABLE = False
try:
    from aiohai.integrations.smart_home.service_registry import LocalServiceRegistry
    from aiohai.integrations.smart_home.query_executor import LocalAPIQueryExecutor
    from aiohai.integrations.smart_home.stack_detector import SmartHomeStackDetector
    from aiohai.integrations.smart_home.notification import HomeAssistantNotificationBridge
    _SMART_HOME_AVAILABLE = True
except ImportError:
    pass

_OFFICE_AVAILABLE = False
try:
    from aiohai.integrations.office.document_scanner import DocumentContentScanner
    from aiohai.integrations.office.macro_blocker import MacroBlocker
    from aiohai.integrations.office.metadata_sanitizer import MetadataSanitizer
    from aiohai.integrations.office.graph_registry import GraphAPIRegistry
    from aiohai.integrations.office.stack_detector import OfficeStackDetector
    from aiohai.integrations.office.audit_logger import DocumentAuditLogger
    _OFFICE_AVAILABLE = True
except ImportError:
    pass


class UnifiedSecureProxy:
    """Complete unified secure proxy with all security fixes."""

    def __init__(self, config: UnifiedConfig = None):
        self.config = config or UnifiedConfig()

        # Create directories
        self.config.log_dir.mkdir(parents=True, exist_ok=True)
        self.config.secure_temp_dir.mkdir(parents=True, exist_ok=True)

        # Load raw config.json once for all init helpers
        config_path = self.config.base_dir / 'config' / 'config.json'
        self._raw_config = {}
        if config_path.exists():
            try:
                with open(config_path, encoding='utf-8') as f:
                    self._raw_config = json.load(f)
            except Exception:
                pass  # UnifiedConfig handles defaults

        # Initialize core components
        self.logger = SecurityLogger(self.config)
        self.alerts = AlertManager(self.config, self.logger)
        self.startup = StartupSecurityVerifier(self.config, self.logger, self.alerts)
        self.integrity = IntegrityVerifier(self.config, self.logger, self.alerts)
        self.network = NetworkInterceptor(self.config, self.logger, self.alerts)
        self.sanitizer = ContentSanitizer(self.logger, self.alerts)

        # Pre-initialize Office document security components
        self.doc_scanner = None
        self.macro_blocker = None
        self.metadata_sanitizer = None
        self.graph_api_registry = None
        self.office_detector = None
        self.doc_audit_logger = None

        # PII protector (needed by doc_scanner and others)
        self.pii_protector = None
        if _SECURITY_COMPONENTS_AVAILABLE:
            self.pii_protector = PIIProtector()

        if _OFFICE_AVAILABLE and _SECURITY_COMPONENTS_AVAILABLE:
            self._init_office_components()

        self.path_validator = PathValidator(self.config, self.logger)
        self.command_validator = CommandValidator(
            self.config, self.logger, macro_blocker=self.macro_blocker)
        self.executor = SecureExecutor(
            self.config, self.logger, self.alerts,
            self.path_validator, self.command_validator,
            doc_scanner=self.doc_scanner,
            macro_blocker=self.macro_blocker,
            metadata_sanitizer=self.metadata_sanitizer,
            doc_audit_logger=self.doc_audit_logger)
        self.approval_mgr = ApprovalManager(self.config, self.logger)

        # Phase 2: Session elevation manager
        self.session_manager = None
        try:
            from aiohai.core.trust.session import SessionManager
            from aiohai.core.trust.session_store import SessionStore
            session_store = SessionStore()
            self.session_manager = SessionManager(store=session_store)
            self.approval_mgr.session_manager = self.session_manager
        except ImportError:
            pass

        # Phase 3: Trust matrix adjuster + change request log
        self.matrix_adjuster = None
        self.change_request_log = None
        try:
            from aiohai.core.trust.matrix_adjuster import TrustMatrixAdjuster
            from aiohai.core.trust.change_request_log import ChangeRequestLog
            self.change_request_log = ChangeRequestLog()
            self.matrix_adjuster = TrustMatrixAdjuster(
                change_request_log=self.change_request_log,
            )
            # Load saved overrides
            ok, errors = self.matrix_adjuster.load_from_file()
            if errors:
                for err in errors:
                    self.logger.log_event(
                        "OVERRIDE_LOAD_ERROR", AlertSeverity.WARNING,
                        {'error': err})
        except ImportError:
            pass

        # Phase 4: Config manager + Admin API server
        self.config_manager = None
        self.admin_api = None
        try:
            from aiohai.core.config_manager import ConfigManager
            from aiohai.proxy.admin_api import AdminAPIServer
            self.config_manager = ConfigManager(
                matrix_adjuster=self.matrix_adjuster,
                change_request_log=self.change_request_log,
            )
            self.admin_api = AdminAPIServer(
                config_manager=self.config_manager,
                session_manager=self.session_manager,
                change_request_log=self.change_request_log,
                matrix_adjuster=self.matrix_adjuster,
            )
        except ImportError:
            pass

        # Initialize HSM
        self.hsm_manager = None
        if _HSM_AVAILABLE and self.config.hsm_enabled:
            self._init_hsm()

        # Wire HSM to logger for log signing
        if self.hsm_manager:
            self.logger.set_hsm_manager(self.hsm_manager)

        # Optional dual LLM
        self.dual_verifier = None
        if _SECURITY_COMPONENTS_AVAILABLE and self.config.enable_dual_llm:
            self.dual_verifier = DualLLMVerifier(
                self.config.ollama_host, self.config.ollama_port)

        # Initialize FIDO2/WebAuthn system
        self.fido2_server = None
        self.fido2_client = None
        if _FIDO2_AVAILABLE and self.config.fido2_enabled:
            self.fido2_server, self.fido2_client = self._initialize_fido2()

        # Load policy
        self.policy = self._load_policy()

        # Initialize smart home components
        self.notification_bridge = None
        self.service_registry = None
        self.api_query_executor = None
        self.stack_detector = None

        if _SMART_HOME_AVAILABLE and _SECURITY_COMPONENTS_AVAILABLE:
            self._init_smart_home()

    # ----- Initialization helpers -----

    def _init_office_components(self):
        """Initialize Office document security components."""
        try:
            office_config = self._raw_config.get('office', {})

            if office_config.get('enabled', False):
                self.doc_scanner = DocumentContentScanner(
                    self.logger,
                    pii_protector=self.pii_protector,
                    credential_redactor=(CredentialRedactor()
                                         if _SECURITY_COMPONENTS_AVAILABLE else None),
                )
                self.macro_blocker = MacroBlocker(self.logger)
                self.metadata_sanitizer = MetadataSanitizer(self.logger)

                graph_config = office_config.get('graph_api', {})
                if graph_config.get('enabled', False):
                    self.graph_api_registry = GraphAPIRegistry(
                        self.logger, config=graph_config)

                self.office_detector = OfficeStackDetector(
                    base_dir=str(self.config.base_dir))
                status = self.office_detector.detect()
                self.logger.log_event("OFFICE_DETECTED", AlertSeverity.INFO,
                                      {'state': status['detection_state']})

                audit_config = office_config.get('audit', {})
                if audit_config.get('enabled', True):
                    self.doc_audit_logger = DocumentAuditLogger(
                        log_dir=self.config.log_dir / 'document_audit',
                        retention_days=audit_config.get('retention_days', 30),
                        log_content_hashes=audit_config.get('log_content_hashes', True),
                    )
        except Exception as e:
            self.logger.log_event("OFFICE_INIT_ERROR", AlertSeverity.WARNING,
                                  {'error': str(e)})

    def _init_hsm(self):
        """Initialize Hardware Security Module."""
        try:
            self.hsm_manager = get_hsm_manager(use_mock=self.config.hsm_use_mock)
            success, msg = self.hsm_manager.initialize()
            if success:
                self.logger.log_event("HSM_INITIALIZED", AlertSeverity.INFO,
                                      {'message': msg})
                if self.config.hsm_pin:
                    login_ok, login_msg = self.hsm_manager.login(self.config.hsm_pin)
                    if not login_ok:
                        self.logger.log_event("HSM_LOGIN_FAILED", AlertSeverity.HIGH,
                                              {'error': login_msg})
                        if self.config.hsm_required:
                            raise SecurityError(f"HSM login failed: {login_msg}")
                        self.hsm_manager = None
            else:
                self.logger.log_event("HSM_INIT_FAILED", AlertSeverity.HIGH,
                                      {'error': msg})
                if self.config.hsm_required:
                    raise SecurityError(
                        f"HSM required but initialization failed: {msg}")
                self.hsm_manager = None
        except SecurityError:
            raise
        except Exception as e:
            self.logger.log_event("HSM_INIT_ERROR", AlertSeverity.HIGH,
                                  {'error': str(e)})
            if self.config.hsm_required:
                raise SecurityError(f"HSM required but unavailable: {e}")
            self.hsm_manager = None

    def _init_smart_home(self):
        """Initialize smart home integration components."""
        try:
            sh_config = self._raw_config.get('smart_home', {})

            if sh_config.get('enabled', True):
                self.service_registry = LocalServiceRegistry(self.logger)

                # Register default services
                self.service_registry.register(
                    'frigate', '127.0.0.1', 5000,
                    ['/api/events', '/api/stats', '/api/version',
                     '/api/config', '/api/*'],
                    max_response_bytes=1048576,
                    description='Frigate NVR')
                self.service_registry.register(
                    'homeassistant', '127.0.0.1', 8123,
                    ['/api/states', '/api/states/*', '/api/history/period*',
                     '/api/config', '/api/events'],
                    max_response_bytes=1048576,
                    description='Home Assistant')

                # Load custom services from config
                if self._raw_config:
                    self.service_registry.load_from_config(self._raw_config)

                self.api_query_executor = LocalAPIQueryExecutor(
                    self.service_registry, self.logger, self.pii_protector)

                # Notification bridge
                nb_config = sh_config.get('notification_bridge', {})
                if nb_config.get('enabled', True):
                    self.notification_bridge = HomeAssistantNotificationBridge(
                        alert_manager=self.alerts,
                        port=nb_config.get('port', 11436),
                        frigate_host=nb_config.get('frigate_host', '127.0.0.1'),
                        frigate_port=nb_config.get('frigate_port', 5000))
                    self.notification_bridge.start()

                    self.service_registry.register(
                        'aiohai_bridge', '127.0.0.1',
                        nb_config.get('port', 11436),
                        ['/notifications', '/health'],
                        max_response_bytes=524288,
                        description='AIOHAI Notification Bridge')

                # Stack detector
                sd_config = sh_config.get('stack_detection', {})
                if sd_config.get('enabled', True):
                    self.stack_detector = SmartHomeStackDetector(
                        base_dir=str(self.config.base_dir))
                    status = self.stack_detector.detect()
                    self.logger.log_event("SMART_HOME_DETECTED", AlertSeverity.INFO,
                                          {'state': status['deployment_state']})

        except Exception as e:
            self.logger.log_event("SMART_HOME_INIT_ERROR", AlertSeverity.WARNING,
                                  {'error': str(e)})

    # ----- Policy loading -----

    def _load_policy(self) -> str:
        if self.config.policy_file.exists():
            content = self.config.policy_file.read_text(encoding='utf-8')
            self.logger.log_event("POLICY_LOADED", AlertSeverity.INFO,
                                  {'size': len(content)})
            content = self._load_frameworks(content)
            return content
        self.logger.log_event("POLICY_NOT_FOUND", AlertSeverity.WARNING, {})
        return ""

    def _load_frameworks(self, policy_content: str) -> str:
        """Load framework prompt files from the policy directory.

        M-6 FIX: Only load from an explicit allowlist of known framework filenames.
        """
        policy_dir = self.config.policy_file.parent
        framework_files = sorted(policy_dir.glob('*_framework_*.md'))

        if not framework_files:
            return policy_content

        combined = policy_content
        for fw_file in framework_files:
            if fw_file.name not in ALLOWED_FRAMEWORK_NAMES:
                self.logger.log_event("FRAMEWORK_REJECTED", AlertSeverity.HIGH, {
                    'file': fw_file.name,
                    'reason': 'Not in allowed framework list'})
                continue

            try:
                fw_content = fw_file.read_text(encoding='utf-8')
                combined += f"\n\n{'='*80}\n"
                combined += f"FRAMEWORK: {fw_file.stem}\n"
                combined += f"{'='*80}\n\n"
                combined += fw_content
                self.logger.log_event("FRAMEWORK_LOADED", AlertSeverity.INFO,
                                      {'file': fw_file.name, 'size': len(fw_content)})
            except Exception as e:
                self.logger.log_event("FRAMEWORK_LOAD_ERROR", AlertSeverity.WARNING,
                                      {'file': fw_file.name, 'error': str(e)})

        return combined

    # ----- HSM and FIDO2 helpers -----

    def _verify_policy_with_hsm(self) -> bool:
        """Verify policy file signature using HSM."""
        if not self.hsm_manager or not self.hsm_manager.is_connected():
            self.logger.log_event("POLICY_HSM_SKIP", AlertSeverity.WARNING,
                                  {'reason': 'HSM not connected'})
            return not self.config.hsm_required

        if not self.config.policy_file.exists():
            self.logger.log_event("POLICY_HSM_FAILED", AlertSeverity.CRITICAL,
                                  {'error': 'Policy file not found'})
            return False

        policy_content = self.config.policy_file.read_bytes()

        if not self.config.policy_signature_file.exists():
            self.logger.log_event("POLICY_SIG_MISSING", AlertSeverity.WARNING,
                                  {'sig_path': str(self.config.policy_signature_file)})
            return not self.config.hsm_required

        signature = self.config.policy_signature_file.read_bytes()

        try:
            result = self.hsm_manager.verify_policy_signature(
                policy_content, signature)
        except Exception as e:
            self.logger.log_event("POLICY_HSM_ERROR", AlertSeverity.CRITICAL,
                                  {'error': str(e)})
            return False

        if result.is_valid:
            self.logger.log_event("POLICY_HSM_VERIFIED", AlertSeverity.INFO, {
                'hash': result.policy_hash[:16],
                'signer': result.signer_key_id or 'unknown'})
            print("  ✓ HSM signature verified")
            return True

        self.logger.log_event("POLICY_HSM_FAILED", AlertSeverity.CRITICAL, {
            'hash': result.policy_hash[:16],
            'error': result.error_message or 'Verification failed'})
        print(f"  ✗ HSM verification failed: {result.error_message}")
        return False

    def _initialize_fido2(self):
        """Initialize FIDO2/WebAuthn approval system."""
        try:
            fido2_config = {
                'host': self.config.fido2_server_host,
                'port': self.config.fido2_server_port,
                'rp_id': 'localhost',
                'rp_name': 'AIOHAI',
                'origin': f'https://localhost:{self.config.fido2_server_port}',
                'storage_path': str(self.config.base_dir / 'data' / 'fido2'),
                'request_expiry_minutes': self.config.approval_expiry_minutes,
            }

            cert_dir = self.config.base_dir / 'data' / 'ssl'
            cert_file = str(cert_dir / 'aiohai.crt')
            fido2_server = FIDO2ApprovalServer(fido2_config)
            fido2_client = FIDO2ApprovalClient(
                server=fido2_server, cert_path=cert_file)

            users = fido2_server.credential_store.get_all_users()
            self.logger.log_event("FIDO2_INITIALIZED", AlertSeverity.INFO,
                                  {'users': len(users)})
            return fido2_server, fido2_client
        except Exception as e:
            self.logger.log_event("FIDO2_INIT_FAILED", AlertSeverity.WARNING,
                                  {'error': str(e)})
            print(f"  ⚠  FIDO2 initialization failed: {e}")
            return None, None

    def _start_hsm_monitor(self):
        """Background thread that checks HSM health and attempts reconnection."""
        HSM_CHECK_INTERVAL = HSM_HEALTH_CHECK_INTERVAL
        HSM_ALERT_THRESHOLD = 3

        def _monitor():
            was_connected = (self.hsm_manager is not None
                             and self.hsm_manager.is_connected())
            consecutive_failures = 0

            while True:
                time.sleep(HSM_CHECK_INTERVAL)
                if not self.hsm_manager:
                    continue

                is_connected = self.hsm_manager.is_connected()

                if was_connected and not is_connected:
                    self.logger.log_event("HSM_DISCONNECTED", AlertSeverity.HIGH, {
                        'impact': 'Log signing disabled, falling back to software mode'})
                    print("\n  ⚠  HSM disconnected — running in degraded mode")
                    consecutive_failures = 0

                elif not was_connected and not is_connected:
                    try:
                        success, msg = self.hsm_manager.initialize()
                        if success and self.config.hsm_pin:
                            login_ok, _ = self.hsm_manager.login(self.config.hsm_pin)
                            if login_ok:
                                self.logger.set_hsm_manager(self.hsm_manager)
                                self.logger.log_event("HSM_RECONNECTED",
                                                      AlertSeverity.INFO, {})
                                print("\n  ✓ HSM reconnected")
                                is_connected = True
                                consecutive_failures = 0
                            else:
                                consecutive_failures += 1
                        else:
                            consecutive_failures += 1
                    except Exception as e:
                        consecutive_failures += 1
                        self.logger.log_event("HSM_RECONNECT_FAILED",
                                              AlertSeverity.WARNING,
                                              {'error': str(e),
                                               'consecutive_failures':
                                                   consecutive_failures})

                    if consecutive_failures >= HSM_ALERT_THRESHOLD:
                        self.logger.log_event("HSM_PERSISTENT_FAILURE",
                                              AlertSeverity.CRITICAL, {
                            'consecutive_failures': consecutive_failures,
                            'impact': 'HSM unreachable'})
                        if (hasattr(self, 'notification_bridge')
                                and self.notification_bridge):
                            try:
                                self.notification_bridge.send_alert(
                                    title="HSM Connection Lost",
                                    message=(
                                        f"HSM unreachable for "
                                        f"{consecutive_failures} consecutive checks."),
                                    severity="critical")
                            except Exception:
                                pass
                        consecutive_failures = 0
                else:
                    consecutive_failures = 0

                was_connected = is_connected

        t = threading.Thread(target=_monitor, daemon=True)
        t.start()
        return t

    def _start_approval_server(self):
        """Start the FIDO2 approval web server in a background thread."""
        if not self.fido2_server:
            return

        try:
            if self.hsm_manager:
                self.fido2_server.set_hsm_manager(self.hsm_manager)

            cert_dir = self.config.base_dir / 'data' / 'ssl'
            self.fido2_server.start(
                use_ssl=True, cert_dir=cert_dir, threaded=True)

            self.logger.log_event("APPROVAL_SERVER_STARTED", AlertSeverity.INFO,
                                  {'port': self.config.fido2_server_port})
        except Exception as e:
            print(f"  ⚠  Approval server failed to start: {e}")
            self.logger.log_event("APPROVAL_SERVER_FAILED", AlertSeverity.WARNING,
                                  {'error': str(e)})

    # ----- Startup banner -----

    def _print_startup_banner(self):
        """Print the full status banner after all startup steps complete."""
        print("\n" + "=" * 70)
        print("PROXY ACTIVE - v3.0 WITH HARDWARE SECURITY + FIDO2")
        print("=" * 70)
        print(f"Listen:   http://{self.config.listen_host}:{self.config.listen_port}")
        print(f"Ollama:   http://{self.config.ollama_host}:{self.config.ollama_port}")
        print(f"Policy:   {'✓ Loaded' if self.policy else '✗ Not found'}")

        fw_dir = self.config.policy_file.parent
        fw_files = sorted(fw_dir.glob('*_framework_*.md'))
        if fw_files:
            fw_names = [f.stem for f in fw_files]
            print(f"Frameworks: {len(fw_files)} loaded ({', '.join(fw_names)})")
        else:
            print("Frameworks: None")

        print(f"Session:  {self.logger.session_id}")

        if self.hsm_manager and self.hsm_manager.is_connected():
            print("HSM:      ✓ Connected (logs signed)")
        elif self.config.hsm_enabled:
            print("HSM:      ⚠ Enabled but not connected")
        else:
            print("HSM:      ○ Disabled")

        if self.fido2_server:
            try:
                _s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                _s.connect(("8.8.8.8", 80))
                _local_ip = _s.getsockname()[0]
                _s.close()
            except Exception:
                _local_ip = "your-server-ip"
            print(f"FIDO2:    ✓ Active "
                  f"(approve at https://{_local_ip}:{self.config.fido2_server_port})")
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
        if self.doc_scanner:
            features.extend([
                "Office document PII scanning",
                "Macro-enabled format blocking",
                "Document metadata sanitization",
                "Excel formula safety enforcement",
            ])
        if self.graph_api_registry:
            features.append("Graph API scope enforcement")
        if self.doc_audit_logger:
            features.append("Document operation audit logging")
        if self.config.enable_dual_llm:
            features.append("Dual-LLM verification enabled")
        for f in features:
            print(f"  ✓ {f}")

        print("=" * 70)
        print("\nCOMMANDS: HELP | PENDING | REPORT | STATUS | EXPLAIN <id>")
        print("          CONFIRM <id> | REJECT <id> | CONFIRM ALL | STOP")
        print("=" * 70)
        print("\nPress Ctrl+C to stop\n")

    # ----- Main start method -----

    def start(self) -> None:
        """O4: Decomposed startup — each step returns (ok, message)."""
        print("=" * 70)
        print("AIOHAI Unified Proxy v3.0 - HARDWARE SECURITY + FIDO2 APPROVAL")
        print("=" * 70)

        # Ordered startup steps. Each returns True on success.
        steps = [
            ("Security components",    self._step_security_components),
            ("Hardware Security Module", self._step_hsm_status),
            ("Startup security checks", self._step_startup_checks),
            ("Policy integrity (hash)", self._step_policy_hash),
            ("Policy integrity (HSM)",  self._step_policy_hsm),
            ("Network interceptor",     self._step_network),
            ("Integrity monitoring",    self._step_integrity_monitor),
            ("FIDO2/WebAuthn system",   self._step_fido2),
            ("Request handler",         self._step_configure_handler),
            ("HTTP proxy server",       self._step_start_server),
        ]

        for i, (name, step_fn) in enumerate(steps):
            print(f"\n[{i}/{len(steps) - 1}] {name}...")
            if not step_fn():
                return  # step_fn handles sys.exit or error messages

    def _step_security_components(self) -> bool:
        if not _SECURITY_COMPONENTS_AVAILABLE:
            if self.config.allow_degraded_security:
                print("  ⚠  DEGRADED MODE: Security components unavailable")
                self.logger.log_event("DEGRADED_MODE", AlertSeverity.HIGH, {
                    'reason': 'Security components import failed'})
            else:
                print("  ✗ SECURITY COMPONENTS UNAVAILABLE")
                print("    Use --allow-degraded flag to override.")
                sys.exit(1)
        else:
            print("  ✓ Available")
        return True

    def _step_hsm_status(self) -> bool:
        if not self.config.hsm_enabled:
            print("  SKIPPED")
            return True
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
        return True

    def _step_startup_checks(self) -> bool:
        ok, issues = self.startup.verify_all()
        for i in issues:
            print(f"  {'✗' if 'CRITICAL' in i else '⚠'} {i}")
        if not ok:
            print("\n❌ FAILED")
            sys.exit(1)
        print("  ✓ Passed")
        return True

    def _step_policy_hash(self) -> bool:
        if not self.integrity.verify_policy():
            print("  ✗ FAILED")
            sys.exit(1)
        print("  ✓ Hash verified")
        return True

    def _step_policy_hsm(self) -> bool:
        if not self.config.hsm_enabled:
            print("  SKIPPED")
            return True
        if not self._verify_policy_with_hsm():
            if self.config.hsm_required:
                print("\n❌ HSM POLICY VERIFICATION FAILED")
                sys.exit(1)
        return True

    def _step_network(self) -> bool:
        self.network.install_hooks()
        print("  ✓ Hooks active (including DoH blocking)")
        return True

    def _step_integrity_monitor(self) -> bool:
        self.integrity.start_monitoring()
        print("  ✓ Active (10s interval)")
        if self.hsm_manager:
            self._start_hsm_monitor()
            print("  ✓ HSM health monitor active (30s interval)")
        return True

    def _step_fido2(self) -> bool:
        if not self.config.fido2_enabled:
            print("  SKIPPED")
            return True
        if self.fido2_server:
            users = self.fido2_server.credential_store.get_all_users()
            total_creds = sum(len(u.credentials) for u in users.values())
            print(f"  ✓ {len(users)} users, {total_creds} devices registered")
            if self.config.fido2_auto_start_server:
                self._start_approval_server()
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect(("8.8.8.8", 80))
                    local_ip = s.getsockname()[0]
                    s.close()
                except Exception:
                    local_ip = "localhost"
                print(f"  ✓ Approval URL: "
                      f"https://{local_ip}:{self.config.fido2_server_port}")
                if not users:
                    print(f"  ⚠ No users registered. Visit "
                          f"https://{local_ip}:"
                          f"{self.config.fido2_server_port}/register")
        else:
            print("  ⚠ FIDO2 not initialized (missing dependencies?)")
        return True

    def _step_configure_handler(self) -> bool:
        transparency_tracker = None
        credential_redactor = None
        sensitive_detector = None

        if _SECURITY_COMPONENTS_AVAILABLE:
            transparency_tracker = SessionTransparencyTracker(
                self.logger.session_id)
            credential_redactor = CredentialRedactor()
            sensitive_detector = SensitiveOperationDetector()
            self.executor.transparency = transparency_tracker

        UnifiedProxyHandler.ctx = HandlerContext(
            config=self.config,
            logger=self.logger,
            alerts=self.alerts,
            sanitizer=self.sanitizer,
            executor=self.executor,
            approval_mgr=self.approval_mgr,
            security_policy=self.policy,
            agentic_instructions=AGENTIC_INSTRUCTIONS,
            dual_verifier=self.dual_verifier,
            pii_protector=self.pii_protector,
            transparency_tracker=transparency_tracker,
            credential_redactor=credential_redactor,
            sensitive_detector=sensitive_detector,
            hsm_manager=self.hsm_manager,
            fido2_client=self.fido2_client,
            fido2_server=self.fido2_server,
            api_query_executor=self.api_query_executor,
            graph_api_registry=self.graph_api_registry,
            integrity_verifier=self.integrity,
            ollama_breaker=OllamaCircuitBreaker(),
            session_manager=self.session_manager,
            matrix_adjuster=self.matrix_adjuster,
            change_request_log=self.change_request_log,
        )
        print("  ✓ Configured")
        return True

    def _step_start_server(self) -> bool:
        addr = (self.config.listen_host, self.config.listen_port)

        try:
            httpd = ThreadedHTTPServer(addr, UnifiedProxyHandler)
            self._print_startup_banner()

            self.logger.log_event("PROXY_STARTED", AlertSeverity.INFO, {
                'version': '3.0.0',
                'listen': f"{self.config.listen_host}:{self.config.listen_port}",
                'hsm_connected': (self.hsm_manager is not None
                                  and self.hsm_manager.is_connected()),
                'fido2_active': self.fido2_client is not None,
            })

            # Start admin API server (Phase 4)
            if self.admin_api:
                if self.admin_api.start():
                    print(f"   Admin API ......... http://127.0.0.1:{self.admin_api.port}")
                    self.logger.log_event("ADMIN_API_STARTED", AlertSeverity.INFO, {
                        'port': self.admin_api.port,
                    })

            httpd.serve_forever()

        except KeyboardInterrupt:
            print("\n\nShutting down...")
        except Exception as e:
            self.logger.log_event("PROXY_ERROR", AlertSeverity.CRITICAL,
                                  {'error': str(e)})
            raise
        finally:
            if self.admin_api:
                self.admin_api.stop()
            self.integrity.stop_monitoring()
            self.alerts.shutdown()
            if self.hsm_manager:
                self.hsm_manager.logout()
            self.logger.log_event("PROXY_STOPPED", AlertSeverity.INFO, {})
        return True


# =============================================================================
# CONFIG FILE LOADING
# =============================================================================

def _load_config_from_file(config: UnifiedConfig, config_path: Path) -> None:
    """SECURITY FIX (F-005): Merge config.json settings into UnifiedConfig."""
    if not config_path.exists():
        return

    try:
        with open(config_path, encoding='utf-8') as f:
            file_cfg = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"  ⚠ Could not read {config_path}: {e}")
        return

    gen = file_cfg.get('general', {})
    if 'base_directory' in gen:
        config.base_dir = Path(gen['base_directory'])

    prx = file_cfg.get('proxy', {})
    if 'listen_port' in prx:
        config.listen_port = prx['listen_port']

    oll = file_cfg.get('ollama', {})
    if 'port' in oll:
        config.ollama_port = oll['port']

    net = file_cfg.get('network', {})
    if 'allowlist' in net:
        base = {'localhost', '127.0.0.1'}
        config.network_allowlist = list(base | set(net['allowlist']))
    if 'install_socket_hooks' in net:
        config.enforce_network_allowlist = net['install_socket_hooks']

    dns = file_cfg.get('dns_security', {})
    if 'max_query_length' in dns:
        config.max_dns_query_length = dns['max_query_length']
    if 'max_label_entropy' in dns:
        config.max_dns_entropy = dns['max_label_entropy']

    res = file_cfg.get('resource_limits', {})
    if 'max_single_file_mb' in res:
        config.max_file_size_mb = res['max_single_file_mb']
    if 'rate_limit_per_minute' in res:
        config.rate_limit_per_minute = res['rate_limit_per_minute']
    if 'max_concurrent_actions' in res:
        config.max_concurrent_actions = res['max_concurrent_actions']

    cmd = file_cfg.get('command_execution', {})
    if 'timeout_seconds' in cmd:
        config.command_timeout = cmd['timeout_seconds']

    sec = file_cfg.get('security', {})
    if 'refuse_admin' in sec:
        config.refuse_admin = sec['refuse_admin']
    if 'inject_system_prompt' in sec:
        config.inject_system_prompt = sec['inject_system_prompt']
    if 'scan_for_injection' in sec:
        config.scan_for_injection = sec['scan_for_injection']

    hsm = file_cfg.get('hsm', {})
    if 'enabled' in hsm:
        config.hsm_enabled = hsm['enabled']
    if 'required' in hsm:
        config.hsm_required = hsm['required']

    fido = file_cfg.get('fido2', {})
    if 'enabled' in fido:
        config.fido2_enabled = fido['enabled']
    if 'server_port' in fido:
        config.fido2_server_port = fido['server_port']
    if 'poll_timeout' in fido:
        config.fido2_poll_timeout = fido['poll_timeout']


# =============================================================================
# ENTRY POINT
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='AIOHAI Unified Proxy v3.0 with Hardware Security')
    parser.add_argument('--listen-port', type=int, default=None)
    parser.add_argument('--ollama-port', type=int, default=None)
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
    parser.add_argument('--hsm-pin', help='HSM PIN')

    # FIDO2 arguments
    parser.add_argument('--no-fido2', action='store_true',
                       help='Disable FIDO2/WebAuthn hardware approval')
    parser.add_argument('--fido2-port', type=int, default=None,
                       help='Approval server HTTPS port (default: 8443)')
    parser.add_argument('--no-approval-server', action='store_true',
                       help='Disable auto-start of approval web server')
    parser.add_argument('--allow-degraded', action='store_true',
                       help='Allow startup without security components')

    args = parser.parse_args()

    config = UnifiedConfig()

    # SECURITY FIX (F-005): Load config.json BEFORE CLI overrides
    config_path = Path(args.base_dir) / 'config' / 'config.json'
    _load_config_from_file(config, config_path)

    # CLI overrides (highest priority)
    if args.listen_port is not None:
        config.listen_port = args.listen_port
    if args.ollama_port is not None:
        config.ollama_port = args.ollama_port
    config.base_dir = Path(args.base_dir)
    if args.no_network_control:
        config.enforce_network_allowlist = False
    if args.no_file_scan:
        config.scan_file_content = False
    if args.enable_dual_llm:
        config.enable_dual_llm = True
    if args.allow_degraded:
        config.allow_degraded_security = True

    if args.no_hsm:
        config.hsm_enabled = False
    if args.hsm_optional:
        config.hsm_required = False
    if args.hsm_mock:
        config.hsm_use_mock = True

    # S3 FIX: HSM PIN handling — environment variable and interactive prompt
    # Priority 1: Environment variable (for scripted/service use)
    hsm_pin_env = os.environ.get('AIOHAI_HSM_PIN')
    if hsm_pin_env:
        config.hsm_pin = hsm_pin_env
    # Priority 2: Interactive prompt (for manual startup)
    elif config.hsm_enabled and not args.no_hsm and not args.hsm_pin and sys.stdin.isatty():
        import getpass
        try:
            pin = getpass.getpass("HSM PIN (or Enter to skip): ")
            if pin:
                config.hsm_pin = pin
        except (EOFError, KeyboardInterrupt):
            pass
    # Priority 3: CLI argument (deprecated, warn)
    if args.hsm_pin:
        print("⚠️  WARNING: --hsm-pin on command line is insecure "
              "(visible in ps/history).")
        print("   Use AIOHAI_HSM_PIN environment variable or "
              "interactive prompt instead.")
        config.hsm_pin = args.hsm_pin

    if args.no_fido2:
        config.fido2_enabled = False
    if args.fido2_port is not None:
        config.fido2_server_port = args.fido2_port
    if args.no_approval_server:
        config.fido2_auto_start_server = False

    if args.policy:
        config.policy_file = Path(args.policy)

    proxy = UnifiedSecureProxy(config)
    proxy.start()
