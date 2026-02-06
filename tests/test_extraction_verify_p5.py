#!/usr/bin/env python3
"""
Phase 5 Extraction Verification Tests
======================================
Verifies that all 8 proxy-layer classes have been correctly extracted
from proxy/aiohai_proxy.py and security/security_components.py into
the aiohai/proxy/ package.

Run: python tests/test_extraction_verify_p5.py
"""

import sys
import os

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PASSED = 0
FAILED = 0


def check(name, condition, detail=""):
    global PASSED, FAILED
    if condition:
        print(f"  PASS  {name}")
        PASSED += 1
    else:
        print(f"  FAIL  {name}  {detail}")
        FAILED += 1


# =============================================================================
# Phase 5: Proxy Layer Extraction
# =============================================================================

print("=== Phase 5: Proxy Layer ===")

# --- ActionParser ---
try:
    from aiohai.proxy.action_parser import ActionParser
    # Verify it's the real implementation, not a stub
    assert hasattr(ActionParser, 'PATTERN'), "Missing PATTERN attribute"
    assert hasattr(ActionParser, 'parse'), "Missing parse method"
    assert hasattr(ActionParser, 'strip_actions'), "Missing strip_actions method"
    # Functional test
    actions = ActionParser.parse('<action type="READ" target="test.txt"></action>')
    assert len(actions) == 1 and actions[0]['type'] == 'READ'
    check("P5_ActionParser_import_and_functional", True)
except Exception as e:
    check("P5_ActionParser_import_and_functional", False, str(e))

# --- OllamaCircuitBreaker ---
try:
    from aiohai.proxy.circuit_breaker import OllamaCircuitBreaker
    cb = OllamaCircuitBreaker(failure_threshold=2, reset_timeout=1)
    assert cb.can_request() == True
    cb.record_failure()
    cb.record_failure()
    assert cb.can_request() == False  # breaker open
    cb.record_success()
    assert cb.can_request() == True  # reset
    check("P5_OllamaCircuitBreaker_import_and_functional", True)
except Exception as e:
    check("P5_OllamaCircuitBreaker_import_and_functional", False, str(e))

# --- DualLLMVerifier ---
try:
    from aiohai.proxy.dual_llm import DualLLMVerifier
    dlv = DualLLMVerifier("127.0.0.1", 11434, "test-model")
    assert hasattr(dlv, 'verify_action')
    assert hasattr(dlv, 'JUDGE_PROMPT')
    assert dlv.model == "test-model"
    check("P5_DualLLMVerifier_import", True)
except Exception as e:
    check("P5_DualLLMVerifier_import", False, str(e))

# --- ApprovalManager ---
try:
    from aiohai.proxy.approval import ApprovalManager
    assert hasattr(ApprovalManager, 'MAX_PENDING_PER_SESSION')
    assert hasattr(ApprovalManager, 'create_request')
    assert hasattr(ApprovalManager, 'approve')
    assert hasattr(ApprovalManager, 'reject')
    assert hasattr(ApprovalManager, 'get_all_pending')
    assert hasattr(ApprovalManager, 'has_destructive_pending')
    assert hasattr(ApprovalManager, 'clear_all')
    check("P5_ApprovalManager_import", True)
except Exception as e:
    check("P5_ApprovalManager_import", False, str(e))

# --- SecureExecutor ---
try:
    from aiohai.proxy.executor import SecureExecutor
    assert hasattr(SecureExecutor, 'SMART_HOME_PATTERNS')
    assert hasattr(SecureExecutor, 'execute_command')
    assert hasattr(SecureExecutor, 'read_file')
    assert hasattr(SecureExecutor, 'write_file')
    assert hasattr(SecureExecutor, 'list_directory')
    assert hasattr(SecureExecutor, 'delete_file')
    check("P5_SecureExecutor_import", True)
except Exception as e:
    check("P5_SecureExecutor_import", False, str(e))

# --- UnifiedProxyHandler ---
try:
    from aiohai.proxy.handler import UnifiedProxyHandler
    from http.server import BaseHTTPRequestHandler
    assert issubclass(UnifiedProxyHandler, BaseHTTPRequestHandler)
    assert hasattr(UnifiedProxyHandler, 'do_GET')
    assert hasattr(UnifiedProxyHandler, 'do_POST')
    assert hasattr(UnifiedProxyHandler, '_handle_chat')
    assert hasattr(UnifiedProxyHandler, '_process_response')
    assert hasattr(UnifiedProxyHandler, '_check_control')
    assert hasattr(UnifiedProxyHandler, '_call_ollama')
    check("P5_UnifiedProxyHandler_import", True)
except Exception as e:
    check("P5_UnifiedProxyHandler_import", False, str(e))

# --- ThreadedHTTPServer ---
try:
    from aiohai.proxy.server import ThreadedHTTPServer
    from http.server import HTTPServer
    from socketserver import ThreadingMixIn
    assert issubclass(ThreadedHTTPServer, HTTPServer)
    assert issubclass(ThreadedHTTPServer, ThreadingMixIn)
    assert ThreadedHTTPServer.daemon_threads == True
    check("P5_ThreadedHTTPServer_import", True)
except Exception as e:
    check("P5_ThreadedHTTPServer_import", False, str(e))

# --- UnifiedSecureProxy ---
try:
    from aiohai.proxy.orchestrator import UnifiedSecureProxy
    assert hasattr(UnifiedSecureProxy, 'start')
    assert hasattr(UnifiedSecureProxy, '_load_policy')
    assert hasattr(UnifiedSecureProxy, '_load_frameworks')
    assert hasattr(UnifiedSecureProxy, '_initialize_fido2')
    assert hasattr(UnifiedSecureProxy, '_print_startup_banner')
    check("P5_UnifiedSecureProxy_import", True)
except Exception as e:
    check("P5_UnifiedSecureProxy_import", False, str(e))

# --- main() function ---
try:
    from aiohai.proxy.orchestrator import main
    assert callable(main)
    check("P5_main_function_import", True)
except Exception as e:
    check("P5_main_function_import", False, str(e))

# --- Package-level imports ---
try:
    from aiohai.proxy import (
        ActionParser, OllamaCircuitBreaker, DualLLMVerifier,
        ApprovalManager, SecureExecutor, UnifiedProxyHandler,
        ThreadedHTTPServer, UnifiedSecureProxy, StartupSecurityVerifier,
    )
    check("P5_package_imports", True)
except Exception as e:
    check("P5_package_imports", False, str(e))

# =============================================================================
# Backward Compatibility
# =============================================================================

print("\n=== Phase 5: Backward Compatibility ===")

# Test imports from the monolith still work
try:
    from proxy.aiohai_proxy import ActionParser as AP1
    from proxy.aiohai_proxy import OllamaCircuitBreaker as CB1
    from proxy.aiohai_proxy import SecureExecutor as SE1
    from proxy.aiohai_proxy import UnifiedProxyHandler as UPH1
    from proxy.aiohai_proxy import ThreadedHTTPServer as THS1
    from proxy.aiohai_proxy import UnifiedSecureProxy as USP1
    from proxy.aiohai_proxy import ApprovalManager as AM1
    check("P5_backward_compat_proxy", True)
except Exception as e:
    check("P5_backward_compat_proxy", False, str(e))

try:
    from security.security_components import DualLLMVerifier as DLV1
    check("P5_backward_compat_security", True)
except Exception as e:
    check("P5_backward_compat_security", False, str(e))

# Verify the extracted versions ARE used (not stubs)
try:
    from aiohai.proxy.action_parser import ActionParser as AP_new
    from proxy.aiohai_proxy import ActionParser as AP_old
    assert AP_new is AP_old, "ActionParser should be same object via re-import"
    check("P5_identity_check_ActionParser", True)
except Exception as e:
    check("P5_identity_check_ActionParser", False, str(e))

try:
    from aiohai.proxy.circuit_breaker import OllamaCircuitBreaker as CB_new
    from proxy.aiohai_proxy import OllamaCircuitBreaker as CB_old
    assert CB_new is CB_old, "OllamaCircuitBreaker should be same object via re-import"
    check("P5_identity_check_OllamaCircuitBreaker", True)
except Exception as e:
    check("P5_identity_check_OllamaCircuitBreaker", False, str(e))

# =============================================================================
# All Phases Cumulative Check
# =============================================================================

print("\n=== Cumulative: All Extracted Classes Importable ===")

try:
    # Phase 1: Core Foundation
    from aiohai.core.config import UnifiedConfig
    from aiohai.core.audit.logger import SecurityLogger
    from aiohai.core.audit.alerts import AlertManager
    # Phase 2: Security Components
    from aiohai.core.audit.startup import StartupSecurityVerifier
    from aiohai.core.audit.integrity import IntegrityVerifier
    from aiohai.core.network.interceptor import NetworkInterceptor
    from aiohai.core.analysis.sanitizer import ContentSanitizer
    from aiohai.core.access.path_validator import PathValidator
    from aiohai.core.access.command_validator import CommandValidator
    from aiohai.core.analysis.static_analyzer import StaticSecurityAnalyzer
    from aiohai.core.analysis.pii_protector import PIIProtector
    from aiohai.core.analysis.credentials import CredentialRedactor
    from aiohai.core.analysis.sensitive_ops import SensitiveOperationDetector
    from aiohai.core.analysis.multi_stage import MultiStageDetector
    from aiohai.core.resources.limiter import ResourceLimiter
    from aiohai.core.audit.transparency import SessionTransparencyTracker
    # Phase 3: FIDO2/Crypto
    from aiohai.core.crypto.classifier import OperationClassifier
    from aiohai.core.crypto.credentials import CredentialStore
    from aiohai.core.crypto.fido_gate import FIDO2ApprovalServer, FIDO2ApprovalClient
    # Phase 4: Integrations
    from aiohai.integrations.smart_home.service_registry import LocalServiceRegistry
    from aiohai.integrations.smart_home.query_executor import LocalAPIQueryExecutor
    from aiohai.integrations.smart_home.stack_detector import SmartHomeStackDetector
    from aiohai.integrations.smart_home.config_analyzer import SmartHomeConfigAnalyzer
    from aiohai.integrations.smart_home.notification import HomeAssistantNotificationBridge
    from aiohai.integrations.office.document_scanner import DocumentContentScanner
    from aiohai.integrations.office.macro_blocker import MacroBlocker
    from aiohai.integrations.office.metadata_sanitizer import MetadataSanitizer
    from aiohai.integrations.office.graph_registry import GraphAPIRegistry
    from aiohai.integrations.office.stack_detector import OfficeStackDetector
    from aiohai.integrations.office.audit_logger import DocumentAuditLogger
    # Phase 5: Proxy Layer
    from aiohai.proxy.action_parser import ActionParser
    from aiohai.proxy.circuit_breaker import OllamaCircuitBreaker
    from aiohai.proxy.dual_llm import DualLLMVerifier
    from aiohai.proxy.approval import ApprovalManager
    from aiohai.proxy.executor import SecureExecutor
    from aiohai.proxy.handler import UnifiedProxyHandler
    from aiohai.proxy.server import ThreadedHTTPServer
    from aiohai.proxy.orchestrator import UnifiedSecureProxy
    check("P_ALL_35_classes_importable", True)
except Exception as e:
    check("P_ALL_35_classes_importable", False, str(e))

# =============================================================================
# Summary
# =============================================================================

print(f"\n=== TOTAL: {PASSED} passed, {FAILED} failed out of {PASSED + FAILED} ===")
sys.exit(1 if FAILED > 0 else 0)
