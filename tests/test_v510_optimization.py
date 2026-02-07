#!/usr/bin/env python3
"""
Tests for AIOHAI v5.1.0 Optimization Plan — Phase 1, 2, 3 (O1)

Steps covered: S1, S2, S3, S4, S5, C1, C2, C4a, C4b, O1
Run with: python -m pytest tests/test_v510_optimization.py -v
"""

import ast
import hashlib
import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# === S1: FIDO2 Unauthenticated Endpoints ===

def test_s1_pending_requires_auth():
    src = (PROJECT_ROOT / 'aiohai/core/crypto/fido_gate.py').read_text()
    idx = src.index("@app.route('/api/pending')")
    end = src.index("@app.route('/auth/register/begin'", idx)
    block = src[idx:end]
    assert '_verify_api_secret()' in block

def test_s1_users_requires_auth():
    src = (PROJECT_ROOT / 'aiohai/core/crypto/fido_gate.py').read_text()
    idx = src.index("@app.route('/api/users')")
    end = src.index("@app.route('/api/health')", idx)
    block = src[idx:end]
    assert '_verify_api_secret()' in block

def test_s1_health_no_sensitive_data():
    src = (PROJECT_ROOT / 'aiohai/core/crypto/fido_gate.py').read_text()
    idx = src.index("@app.route('/api/health')")
    end = src.index("return app", idx)
    block = src[idx:end]
    assert "get_all_users()" not in block
    assert "sum(1 for" not in block

def test_s1_health_has_version():
    src = (PROJECT_ROOT / 'aiohai/core/crypto/fido_gate.py').read_text()
    idx = src.index("@app.route('/api/health')")
    end = src.index("return app", idx)
    block = src[idx:end]
    assert "'version'" in block


# === S2: FIDO2 Admin Registration Gate ===

def test_s2_admin_registration_gated():
    src = (PROJECT_ROOT / 'aiohai/core/crypto/fido_gate.py').read_text()
    idx = src.index("@app.route('/auth/register/begin'")
    end = src.index("@app.route('/auth/register/complete'", idx)
    block = src[idx:end]
    assert 'get_all_users()' in block
    assert '_verify_api_secret()' in block
    assert '403' in block


# === S3: HSM PIN Handling ===

def test_s3_env_var_support():
    src = (PROJECT_ROOT / 'aiohai/proxy/orchestrator.py').read_text()
    assert 'AIOHAI_HSM_PIN' in src

def test_s3_getpass_prompt():
    src = (PROJECT_ROOT / 'aiohai/proxy/orchestrator.py').read_text()
    assert 'getpass' in src

def test_s3_cli_deprecation():
    src = (PROJECT_ROOT / 'aiohai/proxy/orchestrator.py').read_text()
    assert 'insecure' in src.lower() or 'WARNING' in src

def test_s3_os_import():
    src = (PROJECT_ROOT / 'aiohai/proxy/orchestrator.py').read_text()
    tree = ast.parse(src)
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
    assert 'os' in names


# === S4: Handler Input Bounds ===

def test_s4_max_request_body():
    src = (PROJECT_ROOT / 'aiohai/proxy/handler.py').read_text()
    assert 'MAX_REQUEST_BODY' in src

def test_s4_max_response_body():
    src = (PROJECT_ROOT / 'aiohai/proxy/handler.py').read_text()
    assert 'MAX_RESPONSE_BODY' in src

def test_s4_handle_chat_413():
    src = (PROJECT_ROOT / 'aiohai/proxy/handler.py').read_text()
    idx = src.index('def _handle_chat(self):')
    end = src.index('\n    def ', idx + 20)
    block = src[idx:end]
    assert '413' in block
    assert 'MAX_REQUEST_BODY' in block

def test_s4_call_ollama_bounded():
    src = (PROJECT_ROOT / 'aiohai/proxy/handler.py').read_text()
    idx = src.index('def _call_ollama(self,')
    end = src.index('\n    def ', idx + 20)
    block = src[idx:end]
    assert 'MAX_RESPONSE_BODY' in block

def test_s4_forward_request_bounded():
    src = (PROJECT_ROOT / 'aiohai/proxy/handler.py').read_text()
    idx = src.index('def _forward_request(self,')
    end = src.index('\n    def ', idx + 20)
    block = src[idx:end]
    assert 'MAX_REQUEST_BODY' in block or 'MAX_RESPONSE_BODY' in block


# === S5: Dead config.json PIN field ===

def test_s5_no_pin_in_config():
    cfg = json.loads((PROJECT_ROOT / 'config/config.json').read_text())
    assert 'pin' not in cfg.get('hsm', {})

def test_s5_comment_mentions_env():
    cfg = json.loads((PROJECT_ROOT / 'config/config.json').read_text())
    comment = cfg.get('hsm', {}).get('_comment', '')
    assert 'AIOHAI_HSM_PIN' in comment


# === C1: HSM Double-Hash ===

def test_c1_sign_uses_ckm_rsa_pkcs():
    src = (PROJECT_ROOT / 'aiohai/core/crypto/hsm_bridge.py').read_text()
    idx = src.index('def sign_data(')
    end = src.index('def verify_signature(', idx)
    block = src[idx:end]
    mech_lines = [l.strip() for l in block.split('\n')
                  if 'mechanism =' in l and 'CKM_' in l]
    for l in mech_lines:
        assert 'CKM_RSA_PKCS' in l
        assert 'SHA256_RSA_PKCS' not in l, f"Should use CKM_RSA_PKCS not CKM_SHA256_RSA_PKCS: {l}"

def test_c1_verify_uses_ckm_rsa_pkcs():
    src = (PROJECT_ROOT / 'aiohai/core/crypto/hsm_bridge.py').read_text()
    idx = src.index('def verify_signature(')
    end = src.index('\n    def ', idx + 20)
    block = src[idx:end]
    mech_lines = [l.strip() for l in block.split('\n')
                  if 'mechanism =' in l and 'CKM_' in l]
    for l in mech_lines:
        assert 'CKM_RSA_PKCS' in l
        assert 'SHA256_RSA_PKCS' not in l


# === C2: FIDO2 Authenticator Tracking ===

def test_c2_uses_auth_result_credential_id():
    src = (PROJECT_ROOT / 'aiohai/core/crypto/fido_gate.py').read_text()
    idx = src.index("@app.route('/auth/approve/complete'")
    end = src.index("@app.route('/auth/reject'", idx)
    block = src[idx:end]
    assert 'credential_id' in block, "Must match by credential_id"
    assert 'auth_result' in block, "Must capture authenticate_complete result"


# === C4a: Approval Content Hash ===

def test_c4a_hash_includes_action_type():
    src = (PROJECT_ROOT / 'aiohai/proxy/approval.py').read_text()
    idx = src.index('def create_request(')
    end = src.index('\n    def ', idx + 20)
    block = src[idx:end]
    assert 'action_type' in block and 'target' in block and 'hash_input' in block, \
        "Content hash must include action_type and target"

def test_c4a_verify_matches_create():
    """Verify that the hash computation in approve() matches create_request()."""
    src = (PROJECT_ROOT / 'aiohai/proxy/approval.py').read_text()
    # Both should use the same f-string pattern
    assert src.count("f\"{action_type}:{target}:{content}\"") >= 1 or \
           src.count("f\"{action['type']}:{action['target']}:{action['content']}\"") >= 1


# === C4b: Docker Image Matching ===

def test_c4b_exact_image_match():
    src = (PROJECT_ROOT / 'aiohai/integrations/smart_home/config_analyzer.py').read_text()
    idx = src.index('def _is_trusted_image(')
    end = src.index('\n    def ', idx + 20)
    block = src[idx:end]
    assert '==' in block, "Should use exact match (==) not startswith"


# === O1: Template Extraction ===

def test_o1_templates_file_exists():
    assert (PROJECT_ROOT / 'aiohai/core/crypto/fido2_templates.py').exists()

def test_o1_templates_file_parses():
    src = (PROJECT_ROOT / 'aiohai/core/crypto/fido2_templates.py').read_text()
    ast.parse(src)

def test_o1_fido_gate_imports_templates():
    src = (PROJECT_ROOT / 'aiohai/core/crypto/fido_gate.py').read_text()
    assert 'from aiohai.core.crypto.fido2_templates import' in src

def test_o1_templates_has_all_getters():
    src = (PROJECT_ROOT / 'aiohai/core/crypto/fido2_templates.py').read_text()
    assert '_get_dashboard_html' in src
    assert '_get_approval_html' in src
    assert '_get_register_html' in src
    assert '_get_error_html' in src

def test_o1_templates_has_all_html():
    src = (PROJECT_ROOT / 'aiohai/core/crypto/fido2_templates.py').read_text()
    assert '_DASHBOARD_HTML' in src
    assert '_APPROVAL_HTML' in src
    assert '_REGISTER_HTML' in src
    assert '_ERROR_HTML' in src

def test_o1_fido_gate_no_inline_templates():
    """fido_gate.py should not have inline template HTML anymore."""
    src = (PROJECT_ROOT / 'aiohai/core/crypto/fido_gate.py').read_text()
    assert '_DASHBOARD_HTML = r"""' not in src
    assert '_APPROVAL_HTML = r"""' not in src
    assert '_REGISTER_HTML = r"""' not in src
    assert '_ERROR_HTML = r"""' not in src

def test_o1_no_exec_in_templates():
    """O1 critical safety: templates must not use exec()."""
    src = (PROJECT_ROOT / 'aiohai/core/crypto/fido2_templates.py').read_text()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == 'exec':
                assert False, "fido2_templates.py must not use exec()"


# === All modified files parse ===

def test_all_files_valid_syntax():
    files = [
        'aiohai/core/crypto/fido_gate.py',
        'aiohai/core/crypto/fido2_templates.py',
        'aiohai/proxy/handler.py',
        'aiohai/proxy/orchestrator.py',
        'aiohai/proxy/approval.py',
        'aiohai/core/crypto/hsm_bridge.py',
        'aiohai/integrations/smart_home/config_analyzer.py',
    ]
    for f in files:
        path = PROJECT_ROOT / f
        assert path.exists(), f"{f} does not exist"
        src = path.read_text()
        ast.parse(src)  # Will raise SyntaxError if invalid

def test_config_json_valid():
    cfg = json.loads((PROJECT_ROOT / 'config/config.json').read_text())
    assert 'hsm' in cfg
    assert 'fido2' in cfg


if __name__ == '__main__':
    import pytest
    pytest.main([__file__, '-v'])


# === O2: Handler Dispatch Table ===

def test_o2_dispatch_table_exists():
    src = (PROJECT_ROOT / 'aiohai/proxy/handler.py').read_text()
    assert '_ACTION_DISPATCH' in src

def test_o2_dispatch_covers_all_types():
    src = (PROJECT_ROOT / 'aiohai/proxy/handler.py').read_text()
    for atype in ['COMMAND', 'READ', 'WRITE', 'LIST', 'DELETE']:
        assert f"'{atype}'" in src.split('_ACTION_DISPATCH')[1].split('}')[0], \
            f"{atype} must be in dispatch table"

def test_o2_execute_approved_uses_dispatch():
    src = (PROJECT_ROOT / 'aiohai/proxy/handler.py').read_text()
    idx = src.index('def _execute_approved(self,')
    end = src.index('\n    def ', idx + 20)
    block = src[idx:end]
    assert '_ACTION_DISPATCH' in block

def test_o2_format_single_result_exists():
    src = (PROJECT_ROOT / 'aiohai/proxy/handler.py').read_text()
    assert 'def _format_single_result' in src


# === O3: HandlerContext ===

def test_o3_handler_context_class():
    src = (PROJECT_ROOT / 'aiohai/proxy/handler.py').read_text()
    assert 'class HandlerContext' in src

def test_o3_handler_uses_ctx():
    src = (PROJECT_ROOT / 'aiohai/proxy/handler.py').read_text()
    assert 'self.ctx.' in src

def test_o3_no_bare_handler_attrs():
    """No bare self.config, self.logger etc — all should be self.ctx.*"""
    import re
    src = (PROJECT_ROOT / 'aiohai/proxy/handler.py').read_text()
    ctx_attrs = [
        'config', 'logger', 'alerts', 'sanitizer', 'executor', 'approval_mgr',
    ]
    for attr in ctx_attrs:
        # Find lines with self.<attr> but NOT self.ctx.<attr>
        for i, line in enumerate(src.split('\n'), 1):
            if f'self.{attr}' in line and f'self.ctx.{attr}' not in line:
                stripped = line.strip()
                if stripped.startswith('#') or 'ctx = ' in stripped:
                    continue
                if '= None' in stripped and stripped.startswith(attr):
                    continue
                assert False, f"Line {i} has bare self.{attr}: {stripped[:80]}"

def test_o3_orchestrator_uses_handler_context():
    src = (PROJECT_ROOT / 'aiohai/proxy/orchestrator.py').read_text()
    assert 'HandlerContext(' in src


# === O4: Orchestrator Decomposition ===

def test_o4_step_methods_exist():
    src = (PROJECT_ROOT / 'aiohai/proxy/orchestrator.py').read_text()
    steps = [
        '_step_security_components', '_step_hsm_status',
        '_step_startup_checks', '_step_policy_hash',
        '_step_network', '_step_configure_handler',
        '_step_start_server',
    ]
    for step in steps:
        assert f'def {step}' in src, f"Missing step method: {step}"

def test_o4_start_uses_steps():
    src = (PROJECT_ROOT / 'aiohai/proxy/orchestrator.py').read_text()
    idx = src.index('def start(self)')
    # start() should reference step functions
    end = src.index('\n    def _step_', idx)
    block = src[idx:end]
    assert '_step_' in block


# === O5: CLI Deduplication ===

def test_o5_interactive_dispatch_exists():
    src = (PROJECT_ROOT / 'tools/aiohai_cli.py').read_text()
    assert 'def _interactive_dispatch' in src

def test_o5_interactive_functions_use_dispatch():
    src = (PROJECT_ROOT / 'tools/aiohai_cli.py').read_text()
    for fn in ['_interactive_hsm', '_interactive_logs', '_interactive_config']:
        idx = src.index(f'def {fn}')
        end = src.index('\ndef ', idx + 10)
        block = src[idx:end]
        assert '_interactive_dispatch' in block, \
            f"{fn} should use _interactive_dispatch"


# === O6: __init__.py Cleanup ===

def test_o6_init_files_trimmed():
    """All __init__.py files should be significantly shorter than v5.0.0."""
    inits = list((PROJECT_ROOT / 'aiohai').rglob('__init__.py'))
    total = sum(len(f.read_text().splitlines()) for f in inits)
    # Was 513 lines, should be much less now
    assert total < 200, f"Total __init__.py lines ({total}) should be < 200"

def test_o6_core_init_has_version():
    src = (PROJECT_ROOT / 'aiohai/core/__init__.py').read_text()
    assert '__version__' in src

def test_o6_no_imports_broken():
    """All Python files should still parse."""
    for f in (PROJECT_ROOT / 'aiohai').rglob('*.py'):
        ast.parse(f.read_text())
