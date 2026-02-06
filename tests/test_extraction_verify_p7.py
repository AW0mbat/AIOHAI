#!/usr/bin/env python3
"""
Phase 7 Verification Tests — Test & Tool Import Migration
============================================================

Verifies that all tests and tools import from aiohai.* directly
and no consumer (outside facades and extraction-verify tests)
still imports from the old monolith paths.
"""

import sys
import os
import re

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

passed = 0
failed = 0


def run_test(name, fn):
    global passed, failed
    try:
        fn()
        print(f"  PASS  {name}")
        passed += 1
    except Exception as e:
        print(f"  FAIL  {name}: {e}")
        failed += 1


# ============================================================================
# 7a: No test/tool file imports from old facade paths
# ============================================================================

def test_P7_no_facade_imports_in_tests():
    """Test files should not import from proxy.aiohai_proxy or security.*."""
    violations = []
    test_dir = os.path.join(os.path.dirname(__file__))
    for f in os.listdir(test_dir):
        if not f.endswith('.py') or f.startswith('test_extraction_verify'):
            continue
        path = os.path.join(test_dir, f)
        with open(path) as fh:
            content = fh.read()
        for pattern in [
            'from proxy.aiohai_proxy import',
            'from security.security_components import',
            'from security.fido2_approval import',
            'from security.hsm_integration import',
        ]:
            if pattern in content:
                violations.append(f"{f}: {pattern}")
    assert not violations, f"Old imports found: {violations}"


def test_P7_no_facade_imports_in_tools():
    """Tool files should not import from proxy.aiohai_proxy or security.*."""
    violations = []
    tools_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'tools')
    for f in os.listdir(tools_dir):
        if not f.endswith('.py'):
            continue
        path = os.path.join(tools_dir, f)
        with open(path) as fh:
            content = fh.read()
        for pattern in [
            'from proxy.aiohai_proxy import',
            'from security.security_components import',
            'from security.fido2_approval import',
            'from security.hsm_integration import',
        ]:
            if pattern in content:
                violations.append(f"{f}: {pattern}")
    assert not violations, f"Old imports found: {violations}"


# ============================================================================
# 7b: All test imports resolve (simulated import check)
# ============================================================================

def test_P7_conftest_imports():
    """conftest.py imports all resolve from aiohai.*."""
    from aiohai.core.types import AlertSeverity, TrustLevel, SecurityError
    from aiohai.core.config import UnifiedConfig
    from aiohai.core.audit.logger import SecurityLogger
    from aiohai.core.audit.alerts import AlertManager
    from aiohai.core.audit.integrity import IntegrityVerifier
    from aiohai.core.access.path_validator import PathValidator
    from aiohai.core.access.command_validator import CommandValidator
    from aiohai.core.analysis.sanitizer import ContentSanitizer
    from aiohai.core.network.interceptor import NetworkInterceptor
    from aiohai.core.patterns import (
        BLOCKED_PATH_PATTERNS, BLOCKED_COMMAND_PATTERNS, TIER3_PATH_PATTERNS,
        INJECTION_PATTERNS, INVISIBLE_CHARS, HOMOGLYPHS,
    )
    from aiohai.core.constants import SESSION_ID_BYTES, HASH_CHUNK_SIZE
    from aiohai.proxy.executor import SecureExecutor
    from aiohai.proxy.approval import ApprovalManager
    from aiohai.proxy.action_parser import ActionParser


def test_P7_test_security_imports():
    """test_security.py imports all resolve from aiohai.*."""
    from aiohai.core.types import SecurityLevel
    from aiohai.core.patterns import FULLWIDTH_MAP, UAC_BYPASS_PATTERNS
    from aiohai.core.constants import (
        SAFE_ENV_VARS, WHITELISTED_EXECUTABLES, APPROVAL_ID_BYTES,
    )
    from aiohai.core.crypto.fido_gate import FIDO2ApprovalServer, FIDO2ApprovalClient
    from aiohai.core.analysis.credentials import CredentialRedactor
    from aiohai.core.analysis.pii_protector import PIIProtector


def test_P7_test_e2e_imports():
    """test_e2e.py imports all resolve from aiohai.*."""
    from aiohai.core.templates import AGENTIC_INSTRUCTIONS
    from aiohai.proxy.handler import UnifiedProxyHandler
    from aiohai.proxy.orchestrator import UnifiedSecureProxy


def test_P7_test_startup_imports():
    """test_startup.py imports all resolve from aiohai.*."""
    from aiohai.proxy.orchestrator import UnifiedSecureProxy
    from aiohai.core.constants import SAFE_ENV_VARS


def test_P7_test_ha_framework_imports():
    """test_ha_framework.py imports all resolve from aiohai.*."""
    from aiohai.core.types import ActionType
    from aiohai.core.constants import DOCKER_COMMAND_TIERS
    from aiohai.core.templates import AGENTIC_INSTRUCTIONS
    from aiohai.integrations.smart_home.service_registry import LocalServiceRegistry
    from aiohai.integrations.smart_home.query_executor import LocalAPIQueryExecutor
    from aiohai.integrations.smart_home.notification import HomeAssistantNotificationBridge
    from aiohai.integrations.smart_home.stack_detector import SmartHomeStackDetector
    from aiohai.integrations.smart_home.config_analyzer import SmartHomeConfigAnalyzer


def test_P7_test_office_framework_imports():
    """test_office_framework.py imports all resolve from aiohai.*."""
    from aiohai.core.types import ApprovalTier
    from aiohai.core.patterns import (
        MACRO_ENABLED_EXTENSIONS, SAFE_OFFICE_EXTENSIONS,
        BLOCKED_EXCEL_FORMULAS, BLOCKED_EMBED_EXTENSIONS,
        BLOCKED_GRAPH_ENDPOINTS, BLOCKED_GRAPH_SCOPES,
    )
    from aiohai.integrations.office.document_scanner import DocumentContentScanner
    from aiohai.integrations.office.macro_blocker import MacroBlocker
    from aiohai.integrations.office.metadata_sanitizer import MetadataSanitizer
    from aiohai.integrations.office.graph_registry import GraphAPIRegistry
    from aiohai.integrations.office.stack_detector import OfficeStackDetector
    from aiohai.integrations.office.audit_logger import DocumentAuditLogger
    from aiohai.core.crypto.classifier import OperationClassifier


# ============================================================================
# 7c: Tool imports resolve
# ============================================================================

def test_P7_tool_register_devices_imports():
    """tools/register_devices.py imports resolve from aiohai.*."""
    from aiohai.core.crypto.credentials import CredentialStore
    from aiohai.core.crypto.fido_gate import FIDO2ApprovalServer
    from aiohai.core.types import UserRole


def test_P7_tool_hsm_setup_imports():
    """tools/hsm_setup.py imports resolve from aiohai.*."""
    from aiohai.core.crypto.hsm_bridge import (
        get_hsm_manager, NitrokeyHSMManager, PKCS11_AVAILABLE,
    )
    from aiohai.core.types import HSMStatus


def test_P7_tool_aiohai_cli_imports():
    """tools/aiohai_cli.py imports resolve from aiohai.*."""
    from aiohai.core.crypto.credentials import CredentialStore
    from aiohai.core.types import UserRole
    from aiohai.core.crypto.hsm_bridge import get_hsm_manager
    from aiohai.core.analysis.static_analyzer import StaticSecurityAnalyzer
    from aiohai.core.crypto.fido_gate import FIDO2ApprovalServer


# ============================================================================
# 7d: Source-code-scanning tests updated to check aiohai/ not facades
# ============================================================================

def test_P7_source_scan_tests_check_aiohai_dir():
    """Source-scanning tests in test_security.py should reference aiohai/ not proxy/security/."""
    with open('tests/test_security.py') as f:
        content = f.read()
    # The code-hygiene tests should reference aiohai paths
    assert '"aiohai"' in content or "'aiohai'" in content, \
        "test_security.py source-scan tests should reference aiohai/ directory"
    # Should NOT have old-style proxy_file = ... / "proxy" / "aiohai_proxy.py" patterns
    # (except possibly in comments)
    lines = content.split('\n')
    for i, line in enumerate(lines, 1):
        if '/ "proxy" / "aiohai_proxy.py"' in line and not line.strip().startswith('#'):
            assert False, f"test_security.py line {i} still references proxy/aiohai_proxy.py"


# ============================================================================
# Run
# ============================================================================

if __name__ == '__main__':
    print("=== Phase 7a: No Facade Imports in Tests/Tools ===")
    run_test("P7_no_facade_imports_in_tests", test_P7_no_facade_imports_in_tests)
    run_test("P7_no_facade_imports_in_tools", test_P7_no_facade_imports_in_tools)

    print("\n=== Phase 7b: Test Import Resolution ===")
    run_test("P7_conftest_imports", test_P7_conftest_imports)
    run_test("P7_test_security_imports", test_P7_test_security_imports)
    run_test("P7_test_e2e_imports", test_P7_test_e2e_imports)
    run_test("P7_test_startup_imports", test_P7_test_startup_imports)
    run_test("P7_test_ha_framework_imports", test_P7_test_ha_framework_imports)
    run_test("P7_test_office_framework_imports", test_P7_test_office_framework_imports)

    print("\n=== Phase 7c: Tool Import Resolution ===")
    run_test("P7_tool_register_devices_imports", test_P7_tool_register_devices_imports)
    run_test("P7_tool_hsm_setup_imports", test_P7_tool_hsm_setup_imports)
    run_test("P7_tool_aiohai_cli_imports", test_P7_tool_aiohai_cli_imports)

    print("\n=== Phase 7d: Source-Scan Test Updates ===")
    run_test("P7_source_scan_tests_check_aiohai_dir", test_P7_source_scan_tests_check_aiohai_dir)

    print(f"\n=== TOTAL: {passed} passed, {failed} failed out of {passed + failed} ===")
    sys.exit(1 if failed else 0)
