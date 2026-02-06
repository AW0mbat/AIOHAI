"""Tests validating the security audit remediation steps.

Each test group corresponds to a specific audit finding and its fix.
"""
import ast
import os
import re
import sys
from pathlib import Path

import pytest

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================================
# STEP 1: No exec() in fido_gate.py
# ============================================================================

class TestStep1_NoExecInFidoGate:
    """Verify the exec() vulnerability in fido_gate.py has been removed."""

    def _get_fido_gate_source(self):
        path = PROJECT_ROOT / 'aiohai' / 'core' / 'crypto' / 'fido_gate.py'
        return path.read_text(encoding='utf-8')

    def test_no_exec_call_in_source(self):
        """exec() must not appear as a function call in fido_gate.py."""
        source = self._get_fido_gate_source()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id == 'exec':
                    pytest.fail(
                        f"exec() call found at line {node.lineno}. "
                        "This is a critical security vulnerability."
                    )

    def test_no_fido2_templates_file_loading(self):
        """No code should try to load/exec fido2_templates.py."""
        source = self._get_fido_gate_source()
        assert 'fido2_templates.py' not in source, \
            "Reference to fido2_templates.py file should be removed"

    def test_template_variables_defined(self):
        """All four HTML template variables must be defined at module level."""
        source = self._get_fido_gate_source()
        for name in ['_DASHBOARD_HTML', '_APPROVAL_HTML', '_REGISTER_HTML', '_ERROR_HTML']:
            assert f'{name} = ' in source or f'{name} =' in source, \
                f"Template variable {name} must be defined"

    def test_template_getter_functions_exist(self):
        """The getter functions must still exist and be callable."""
        source = self._get_fido_gate_source()
        for func in ['_get_dashboard_html', '_get_approval_html',
                      '_get_register_html', '_get_error_html']:
            assert f'def {func}()' in source, f"Function {func}() must exist"

    def test_templates_contain_html(self):
        """Templates should contain actual HTML content."""
        source = self._get_fido_gate_source()
        for name in ['_DASHBOARD_HTML', '_APPROVAL_HTML', '_REGISTER_HTML', '_ERROR_HTML']:
            # Find the assignment and verify it has DOCTYPE
            pattern = rf'{name}\s*=\s*r""".*?<!DOCTYPE html>'
            assert re.search(pattern, source, re.DOTALL), \
                f"{name} should contain valid HTML starting with <!DOCTYPE html>"


# ============================================================================
# STEP 2: pii_protector.redact() method name fix
# ============================================================================

class TestStep2_PIIProtectorMethodName:
    """Verify handler.py calls the correct PIIProtector method."""

    def _get_handler_source(self):
        path = PROJECT_ROOT / 'aiohai' / 'proxy' / 'handler.py'
        return path.read_text(encoding='utf-8')

    def _get_pii_protector_source(self):
        path = PROJECT_ROOT / 'aiohai' / 'core' / 'analysis' / 'pii_protector.py'
        return path.read_text(encoding='utf-8')

    def test_handler_does_not_call_nonexistent_redact(self):
        """handler.py should not call pii_protector.redact() - that method doesn't exist."""
        source = self._get_handler_source()
        # Check there's no bare .redact( call (the wrong method name)
        # But allow .redact_for_logging( which is the correct one
        lines = source.split('\n')
        for i, line in enumerate(lines, 1):
            if '.redact(' in line and '.redact_for_logging(' not in line:
                # Make sure it's actually calling on pii_protector
                if 'pii_protect' in line or 'pii' in line.lower():
                    pytest.fail(
                        f"Line {i}: Calls .redact() which doesn't exist on PIIProtector. "
                        "Should be .redact_for_logging()"
                    )

    def test_pii_protector_has_redact_for_logging(self):
        """PIIProtector must have a redact_for_logging method."""
        source = self._get_pii_protector_source()
        assert 'def redact_for_logging(' in source, \
            "PIIProtector must define redact_for_logging()"

    def test_pii_protector_does_not_have_bare_redact(self):
        """Verify there's no .redact() method that could cause confusion."""
        source = self._get_pii_protector_source()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == 'redact':
                # Check if it's inside the PIIProtector class
                pytest.fail(
                    f"PIIProtector has a 'redact()' method at line {node.lineno}. "
                    "This creates ambiguity - only redact_for_logging() should exist."
                )


# ============================================================================
# STEP 3: Lockdown checks on GET/DELETE handlers
# ============================================================================

class TestStep3_LockdownChecksAllHandlers:
    """Verify IntegrityVerifier lockdown is checked in all HTTP method handlers."""

    def _get_handler_source(self):
        path = PROJECT_ROOT / 'aiohai' / 'proxy' / 'handler.py'
        return path.read_text(encoding='utf-8')

    def _find_method_bodies(self, source, method_name):
        """Find the body of a do_METHOD handler."""
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == method_name:
                return ast.dump(node)
        return None

    def test_do_GET_checks_lockdown(self):
        """do_GET must check is_locked_down."""
        source = self._get_handler_source()
        body = self._find_method_bodies(source, 'do_GET')
        assert body is not None, "do_GET handler not found"
        assert 'is_locked_down' in source[
            source.find('def do_GET'):source.find('def do_GET') + 2000
        ], "do_GET must check integrity_verifier.is_locked_down"

    def test_do_DELETE_checks_lockdown(self):
        """do_DELETE must check is_locked_down."""
        source = self._get_handler_source()
        body = self._find_method_bodies(source, 'do_DELETE')
        assert body is not None, "do_DELETE handler not found"
        assert 'is_locked_down' in source[
            source.find('def do_DELETE'):source.find('def do_DELETE') + 2000
        ], "do_DELETE must check integrity_verifier.is_locked_down"

    def test_do_POST_checks_lockdown(self):
        """Verify do_POST still checks lockdown (regression test)."""
        source = self._get_handler_source()
        body = self._find_method_bodies(source, 'do_POST')
        assert body is not None, "do_POST handler not found"
        assert 'is_locked_down' in source[
            source.find('def do_POST'):source.find('def do_POST') + 3000
        ], "do_POST must check integrity_verifier.is_locked_down"


# ============================================================================
# STEP 4: Network allowlist doesn't include external domains by default
# ============================================================================

class TestStep4_NetworkAllowlistSafe:
    """Verify network allowlist defaults are localhost-only."""

    def _get_config_source(self):
        path = PROJECT_ROOT / 'aiohai' / 'core' / 'config.py'
        return path.read_text(encoding='utf-8')

    def test_no_github_in_default_allowlist(self):
        """github.com should not be in the default network allowlist."""
        source = self._get_config_source()
        # Find the network_allowlist default value
        assert 'github.com' not in self._extract_default_allowlist(source), \
            "github.com should not be in default network allowlist for a localhost-only proxy"

    def test_no_pypi_in_default_allowlist(self):
        """pypi.org should not be in the default network allowlist."""
        source = self._get_config_source()
        assert 'pypi.org' not in self._extract_default_allowlist(source), \
            "pypi.org should not be in default network allowlist"

    def _extract_default_allowlist(self, source):
        """Extract the default allowlist from config source."""
        # Look for the default value assignment for network_allowlist
        # This is a rough extraction - we're looking at lines containing allowlist defaults
        lines = []
        in_allowlist = False
        for line in source.split('\n'):
            if 'network_allowlist' in line or 'allowlist' in line.lower():
                in_allowlist = True
            if in_allowlist:
                lines.append(line)
                if ']' in line or '}' in line:
                    in_allowlist = False
        return '\n'.join(lines)

    def test_localhost_variants_in_allowlist(self):
        """Default allowlist should include localhost variants."""
        source = self._get_config_source()
        allowlist_text = self._extract_default_allowlist(source)
        assert '127.0.0.1' in allowlist_text or 'localhost' in allowlist_text, \
            "Default allowlist should include localhost"
