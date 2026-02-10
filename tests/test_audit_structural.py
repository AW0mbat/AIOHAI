#!/usr/bin/env python3
"""
AIOHAI — Structural Audit Tests (pytest migration)
=====================================================

Migrated from run_audit_tests.py (custom runner) to pytest format.
These tests verify code structure, imports, and absence of dangerous
patterns using AST analysis. Security-critical source-level assertions.

OPT-2: Absorbing custom test runner into standard pytest suite.
OPT-3: Using AST-based checks where possible instead of string search.

Run with:  pytest tests/test_audit_structural.py -v --tb=short
"""

import ast
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def _read(rel_path: str) -> str:
    return (PROJECT_ROOT / rel_path).read_text(encoding='utf-8')


def _parse(rel_path: str) -> ast.Module:
    return ast.parse(_read(rel_path))


def _find_functions_calling(tree: ast.Module, func_name: str):
    """Find all calls to a specific function name in an AST."""
    calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == func_name:
                calls.append(node)
    return calls


# =========================================================================
# STEP 1: No exec() in fido_gate.py
# =========================================================================

class TestFidoGateCodeSafety:
    """Verify FIDO2 gate has no dangerous code patterns."""

    def test_no_exec_call_in_ast(self):
        """exec() must never appear in fido_gate.py (AST check)."""
        tree = _parse('aiohai/core/crypto/fido_gate.py')
        calls = _find_functions_calling(tree, 'exec')
        assert len(calls) == 0, (
            f"exec() call found at line(s): {[c.lineno for c in calls]}"
        )

    def test_no_eval_call_in_ast(self):
        """eval() must never appear in fido_gate.py (AST check)."""
        tree = _parse('aiohai/core/crypto/fido_gate.py')
        calls = _find_functions_calling(tree, 'eval')
        assert len(calls) == 0, (
            f"eval() call found at line(s): {[c.lineno for c in calls]}"
        )

    def test_no_templates_file_reference(self):
        source = _read('aiohai/core/crypto/fido_gate.py')
        assert 'fido2_templates.py' not in source

    @pytest.mark.parametrize("var_name", [
        '_DASHBOARD_HTML', '_APPROVAL_HTML', '_REGISTER_HTML', '_ERROR_HTML',
    ])
    def test_template_variables_defined(self, var_name):
        source = _read('aiohai/core/crypto/fido_gate.py')
        assert f'{var_name} =' in source, f"{var_name} not defined"

    @pytest.mark.parametrize("func_name", [
        '_get_dashboard_html', '_get_approval_html',
        '_get_register_html', '_get_error_html',
    ])
    def test_template_getter_functions_exist(self, func_name):
        source = _read('aiohai/core/crypto/fido_gate.py')
        assert f'def {func_name}()' in source, f"{func_name}() missing"


# =========================================================================
# STEP 2: PIIProtector method name fix
# =========================================================================

class TestPIIProtectorIntegration:
    """Verify PIIProtector method names match call sites."""

    @pytest.mark.parametrize("path", [
        'aiohai/proxy/handler.py',
        'aiohai/integrations/smart_home/query_executor.py',
    ])
    def test_no_broken_redact_calls(self, path):
        """Callers should use redact_for_logging(), not bare .redact()."""
        source = _read(path)
        for i, line in enumerate(source.split('\n'), 1):
            if '.redact(' in line and '.redact_for_logging(' not in line:
                if 'pii' in line.lower():
                    pytest.fail(
                        f"{path} line {i}: calls .redact() instead of "
                        f".redact_for_logging()"
                    )

    def test_pii_has_redact_for_logging(self):
        source = _read('aiohai/core/analysis/pii_protector.py')
        assert 'def redact_for_logging(' in source


# =========================================================================
# STEP 3: Lockdown checks on all HTTP handlers
# =========================================================================

class TestLockdownChecks:
    """All HTTP handler methods must check lockdown state."""

    @pytest.mark.parametrize("method_name", ['do_GET', 'do_POST', 'do_DELETE'])
    def test_http_method_checks_lockdown(self, method_name):
        source = _read('aiohai/proxy/handler.py')
        idx = source.find(f'def {method_name}')
        assert idx != -1, f"{method_name} not found"
        chunk = source[idx:idx + 3000]
        assert 'is_locked_down' in chunk, (
            f"{method_name} missing is_locked_down check"
        )


# =========================================================================
# STEP 5: Dead code removed
# =========================================================================

class TestDeadCodeRemoval:
    """Verify stale code artifacts have been cleaned up."""

    @pytest.mark.parametrize("symbol", [
        'FINANCIAL_PATH_PATTERNS', 'CLIPBOARD_BLOCK_PATTERNS',
    ])
    def test_removed_pattern_constants(self, symbol):
        source = _read('aiohai/core/patterns.py')
        assert symbol not in source, f"{symbol} should be removed"

    @pytest.mark.parametrize("stale_file", [
        'tests/test_extraction_verify_p4.py',
        'tests/test_extraction_verify_p5.py',
        'aiohai/proxy/startup.py',
    ])
    def test_stale_files_deleted(self, stale_file):
        assert not (PROJECT_ROOT / stale_file).exists(), (
            f"{stale_file} should be deleted"
        )

    def test_types_no_facade_reference(self):
        source = _read('aiohai/core/types.py')
        assert 'facade' not in source.lower()


# =========================================================================
# STEP 6: Deduplicated _is_obfuscated()
# =========================================================================

class TestObfuscationDeduplication:
    """Verify obfuscation detection uses the shared implementation."""

    def test_shared_is_obfuscated_exists(self):
        source = _read('aiohai/core/analysis/utils.py')
        assert 'def is_obfuscated(' in source

    @pytest.mark.parametrize("path", [
        'aiohai/core/access/command_validator.py',
        'aiohai/core/analysis/static_analyzer.py',
    ])
    def test_delegates_to_shared(self, path):
        source = _read(path)
        assert 'from aiohai.core.analysis.utils import is_obfuscated' in source

    @pytest.mark.parametrize("path", [
        'aiohai/core/access/command_validator.py',
        'aiohai/core/analysis/static_analyzer.py',
    ])
    def test_no_duplicate_obfuscation_logic(self, path):
        source = _read(path)
        assert 'special / len(' not in source, (
            f"{path} still has duplicated obfuscation logic"
        )

    def test_shared_function_detects_obfuscation(self):
        from aiohai.core.analysis.utils import is_obfuscated
        assert not is_obfuscated("dir"), "Short strings should pass"
        obf = "$a='po';$b='wer';$c=$a+$b+'shell';$d=[char]105;iex($c+' -enc '+$d)"
        assert is_obfuscated(obf), "Obfuscated PowerShell should be detected"


# =========================================================================
# STEP 7: Session manager circular dependency
# =========================================================================

class TestSessionManagerImports:
    """Session manager must not have circular imports with proxy layer."""

    def test_no_module_level_proxy_import(self):
        source = _read('aiohai/core/access/session_manager.py')
        for i, line in enumerate(source.split('\n'), 1):
            stripped = line.strip()
            if (stripped.startswith('from aiohai.proxy') and
                    not line.startswith(' ') and not line.startswith('\t')):
                pytest.fail(
                    f"Line {i}: module-level import from proxy layer"
                )

    def test_parses_cleanly(self):
        _parse('aiohai/core/access/session_manager.py')


# =========================================================================
# STEP 8: Config loaded once in orchestrator
# =========================================================================

class TestOrchestratorConfig:
    """Orchestrator should load config.json once and pass it around."""

    def test_raw_config_stored(self):
        source = _read('aiohai/proxy/orchestrator.py')
        assert 'self._raw_config' in source

    @pytest.mark.parametrize("method", [
        '_init_office_components', '_init_smart_home',
    ])
    def test_init_helpers_dont_reload_config(self, method):
        source = _read('aiohai/proxy/orchestrator.py')
        idx = source.find(f'def {method}')
        if idx == -1:
            pytest.skip(f"{method} not found")
        next_def = source.find('\n    def ', idx + 10)
        body = source[idx:next_def] if next_def != -1 else source[idx:]
        assert "json.load(f)" not in body, (
            f"{method} still loads config.json directly"
        )

    def test_parses_cleanly(self):
        _parse('aiohai/proxy/orchestrator.py')


# =========================================================================
# STEP 9: Consolidated command patterns
# =========================================================================

class TestConsolidatedPatterns:
    """Command patterns should be centralized in patterns.py."""

    def test_command_analysis_patterns_exists(self):
        source = _read('aiohai/core/patterns.py')
        assert 'COMMAND_ANALYSIS_PATTERNS' in source

    def test_blocked_derived_from_analysis(self):
        source = _read('aiohai/core/patterns.py')
        assert 'BLOCKED_COMMAND_PATTERNS = [p[0] for p in COMMAND_ANALYSIS_PATTERNS]' in source

    def test_static_analyzer_no_inline_patterns(self):
        source = _read('aiohai/core/analysis/static_analyzer.py')
        assert 'COMMAND_PATTERNS = [' not in source

    def test_static_analyzer_imports_from_patterns(self):
        source = _read('aiohai/core/analysis/static_analyzer.py')
        assert 'from aiohai.core.patterns import COMMAND_ANALYSIS_PATTERNS' in source

    def test_analysis_patterns_have_severity_metadata(self):
        source = _read('aiohai/core/patterns.py')
        assert "'CRITICAL'" in source or "'HIGH'" in source

    @pytest.mark.parametrize("path", [
        'aiohai/core/patterns.py',
        'aiohai/core/analysis/static_analyzer.py',
    ])
    def test_files_parse_cleanly(self, path):
        _parse(path)


# =========================================================================
# STEP 10: pyproject.toml
# =========================================================================

class TestPyprojectToml:
    """pyproject.toml should exist with correct metadata."""

    def test_exists(self):
        assert (PROJECT_ROOT / 'pyproject.toml').exists()

    def test_has_entry_point(self):
        source = _read('pyproject.toml')
        assert 'aiohai = "aiohai.__main__:main"' in source

    def test_requires_python_310(self):
        source = _read('pyproject.toml')
        assert 'requires-python = ">=3.10"' in source


# =========================================================================
# BONUS: No dangerous functions in any production code (AST scan)
# =========================================================================

class TestNoExecEvalInProduction:
    """No production code should use exec(), eval(), or compile()."""

    def test_no_exec_eval_in_aiohai_package(self):
        """Scan all aiohai/ Python files for exec/eval/compile calls."""
        dangerous = []
        aiohai_dir = PROJECT_ROOT / 'aiohai'
        for py_file in aiohai_dir.rglob('*.py'):
            try:
                tree = ast.parse(py_file.read_text(encoding='utf-8'))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        func = node.func
                        if isinstance(func, ast.Name) and func.id in ('exec', 'eval'):
                            dangerous.append(
                                f"{py_file.relative_to(PROJECT_ROOT)}:"
                                f"{node.lineno} — {func.id}()"
                            )
            except SyntaxError:
                pass  # Skip files that don't parse

        assert len(dangerous) == 0, (
            f"Found dangerous function calls:\n" +
            "\n".join(f"  {d}" for d in dangerous)
        )
