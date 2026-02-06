#!/usr/bin/env python3
"""
Secure Executor — Sandboxed file/command execution.

Provides sandboxed execution of file operations and system commands
with full security controls: path validation, command validation,
static analysis, content scanning, transparency tracking, and
smart home config analysis.

Phase 5 extraction from proxy/aiohai_proxy.py.
"""

import os
import re
import shlex
import shutil
import subprocess
from typing import Tuple

from aiohai.core.types import AlertSeverity
from aiohai.core.constants import SAFE_ENV_VARS
from aiohai.core.patterns import OFFICE_SCANNABLE_EXTENSIONS
from aiohai.core.config import UnifiedConfig
from aiohai.core.audit.logger import SecurityLogger
from aiohai.core.audit.alerts import AlertManager
from aiohai.core.access.path_validator import PathValidator
from aiohai.core.access.command_validator import CommandValidator

__all__ = ['SecureExecutor']


class SecureExecutor:
    """Sandboxed execution with file content scanning, smart home config analysis,
    and transparency tracking."""

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
                 transparency_tracker=None,
                 doc_scanner=None,
                 macro_blocker=None,
                 metadata_sanitizer=None,
                 doc_audit_logger=None):
        self.config = config
        self.logger = logger
        self.alerts = alerts
        self.path_validator = path_validator
        self.command_validator = command_validator
        self.transparency = transparency_tracker

        # Office document security components
        self.doc_scanner = doc_scanner
        self.macro_blocker = macro_blocker
        self.metadata_sanitizer = metadata_sanitizer
        self.doc_audit_logger = doc_audit_logger

        # Initialize optional security components
        self.static_analyzer = None
        self.resource_limiter = None
        self.multi_stage = None
        self.smart_home_analyzer = None
        self.credential_redactor = None
        self.sensitive_detector = None

        try:
            from aiohai.core.analysis.static_analyzer import StaticSecurityAnalyzer
            from aiohai.core.resources.limiter import ResourceLimiter
            from aiohai.core.analysis.multi_stage import MultiStageDetector
            from aiohai.core.analysis.credentials import CredentialRedactor
            from aiohai.core.analysis.sensitive_ops import SensitiveOperationDetector
            self.static_analyzer = StaticSecurityAnalyzer()
            self.resource_limiter = ResourceLimiter()
            self.multi_stage = MultiStageDetector()
            self.credential_redactor = CredentialRedactor()
            self.sensitive_detector = SensitiveOperationDetector()
        except ImportError:
            pass

        try:
            from aiohai.integrations.smart_home.config_analyzer import SmartHomeConfigAnalyzer
            self.smart_home_analyzer = SmartHomeConfigAnalyzer()
        except ImportError:
            pass

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
                        self.transparency.record_blocked("COMMAND", command[:100],
                                                         "Static analysis")
                    return False, (f"❌ Security analysis blocked:\n"
                                   f"{self.static_analyzer.get_report()}")

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

        # OFFICE: Block macro-enabled extensions at the gate
        if self.macro_blocker:
            ext_ok, ext_reason = self.macro_blocker.check_extension(resolved)
            if not ext_ok:
                self.logger.log_blocked("MACRO_EXTENSION", resolved, ext_reason)
                if self.transparency:
                    self.transparency.record_blocked("WRITE", resolved, ext_reason)
                return False, f"❌ {ext_reason}"

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
                        self.transparency.record_blocked("WRITE", resolved,
                                                         "Insecure Docker config")
                    return False, (f"❌ Docker Compose blocked:\n"
                                   f"{self.smart_home_analyzer.get_report()}")
                elif self.smart_home_analyzer.should_warn():
                    warnings_report = (f"\n\n⚠️ **Security Notes:**\n"
                                       f"{self.smart_home_analyzer.get_report()}")

            elif self._is_smart_home_config(resolved):
                findings = self.smart_home_analyzer.analyze_config(
                    content, os.path.basename(resolved))
                if self.smart_home_analyzer.should_block():
                    self.logger.log_blocked("SMART_HOME_CONFIG", resolved,
                                           f"External endpoints detected: {len(findings)} issues")
                    self.alerts.alert(AlertSeverity.HIGH, "SMART_HOME_EXFIL_BLOCKED",
                                    f"Blocked config with external endpoints")
                    if self.transparency:
                        self.transparency.record_blocked("WRITE", resolved,
                                                         "External endpoints")
                    return False, (f"❌ Smart home config blocked:\n"
                                   f"{self.smart_home_analyzer.get_report()}")
                elif self.smart_home_analyzer.should_warn():
                    warnings_report = (f"\n\n⚠️ **Security Notes:**\n"
                                       f"{self.smart_home_analyzer.get_report()}")

        # OFFICE: Document content scanning for Office file types
        ext = os.path.splitext(resolved)[1].lower()

        cached_scan_result = None  # Cache scan result to avoid re-scanning in audit log

        if ext in OFFICE_SCANNABLE_EXTENSIONS and self.doc_scanner:
            cached_scan_result = self.doc_scanner.scan(
                content, file_type=ext, filename=os.path.basename(resolved))

            if cached_scan_result['should_block']:
                # Critical PII was already escalated to TIER 3 at pre-approval.
                # If we're here, the user has approved (possibly via FIDO2).
                # Log it but proceed — the pre-approval gate is the enforcement point.
                # Exception: dangerous FORMULAS are still hard-blocked here (not PII).
                if cached_scan_result.get('formula_issues'):
                    # Dangerous formulas (WEBSERVICE, DDE, etc.) — always hard block
                    summary = self.doc_scanner.get_scan_summary(cached_scan_result)
                    self.logger.log_blocked("DOCUMENT_FORMULA", resolved, summary[:200])
                    self.alerts.alert(AlertSeverity.HIGH, "DOCUMENT_FORMULA_BLOCKED",
                                      f"Dangerous formula in {os.path.basename(resolved)}")
                    if self.transparency:
                        self.transparency.record_blocked("WRITE", resolved,
                                                         "Dangerous Excel formula")
                    return False, (f"❌ Document content blocked "
                                   f"(dangerous formula):\n{summary}")
                else:
                    # PII-only block — log warning, proceed (FIDO2 approval covers this)
                    summary = self.doc_scanner.get_scan_summary(cached_scan_result)
                    self.logger.log_event("DOCUMENT_PII_APPROVED", AlertSeverity.WARNING,
                                          {'path': resolved[:200], 'summary': summary[:200]})
                    warnings_report += f"\n\n⚠️ **PII Notice (approved):**\n{summary}"

            elif cached_scan_result['findings']:
                warnings_report += (f"\n\n⚠️ **Document Scan:**\n"
                                    f"{self.doc_scanner.get_scan_summary(cached_scan_result)}")

        # OFFICE: VBA content scanning (catches macro code in non-macro extensions too)
        if self.macro_blocker and ext in OFFICE_SCANNABLE_EXTENSIONS:
            vba_ok, vba_reason = self.macro_blocker.scan_content_for_vba(content)
            if not vba_ok:
                self.logger.log_blocked("VBA_CONTENT", resolved, vba_reason)
                if self.transparency:
                    self.transparency.record_blocked("WRITE", resolved, vba_reason)
                return False, f"❌ VBA content blocked: {vba_reason}"

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

            # OFFICE: Auto-run metadata sanitization after successful write
            if ext in {'.docx', '.xlsx', '.pptx'} and self.metadata_sanitizer:
                try:
                    # SECURITY FIX (F-002): Direct function call replaces dynamic code evaluation
                    self.metadata_sanitizer.sanitize_file(resolved, file_type=ext)
                    self.metadata_sanitizer.record_sanitization(resolved)
                    warnings_report += ("\n🧹 Metadata sanitized "
                                        "(author, company, revision stripped)")
                except ImportError:
                    # Library not installed — metadata can't be stripped, warn user
                    warnings_report += ("\n⚠️ Metadata sanitization skipped — "
                                        "Office library not installed for this format")
                except Exception as meta_err:
                    warnings_report += f"\n⚠️ Metadata sanitization failed: {meta_err}"

            # OFFICE: Audit log
            if self.doc_audit_logger and ext in OFFICE_SCANNABLE_EXTENSIONS:
                content_hash = self.doc_audit_logger.hash_content(content.encode('utf-8'))
                pii_findings = []
                # Reuse cached scan result from earlier instead of re-scanning
                if cached_scan_result is not None:
                    pii_findings = cached_scan_result.get('pii_findings', [])
                self.doc_audit_logger.log_operation(
                    'CREATE', resolved, file_type=ext,
                    content_hash=content_hash,
                    pii_findings=pii_findings,
                    metadata_stripped=bool(self.metadata_sanitizer and
                                          ext in {'.docx', '.xlsx', '.pptx'}),
                )

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

            listing = (f"**Contents of `{resolved}`:**\n```\n"
                       + "\n".join(entries) + "\n```")
            self.logger.log_action("DIR_LIST", resolved, "SUCCESS",
                                   {'count': len(entries)})
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
