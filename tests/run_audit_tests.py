"""Minimal test runner - no pytest dependency needed."""
import ast
import re
import sys
import traceback
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

passed = 0
failed = 0
errors = []


def run_test(name, func):
    global passed, failed
    try:
        func()
        print(f"  ✓ {name}")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ {name}: {e}")
        failed += 1
        errors.append((name, str(e)))
    except Exception as e:
        print(f"  ✗ {name}: UNEXPECTED {type(e).__name__}: {e}")
        failed += 1
        errors.append((name, f"{type(e).__name__}: {e}"))


def read_file(rel_path):
    return (PROJECT_ROOT / rel_path).read_text(encoding='utf-8')


# ============================================================================
# STEP 1: No exec() in fido_gate.py
# ============================================================================
print("\n=== STEP 1: No exec() in fido_gate.py ===")

def test_no_exec_call():
    source = read_file('aiohai/core/crypto/fido_gate.py')
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id == 'exec':
                raise AssertionError(f"exec() call found at line {node.lineno}")

def test_no_templates_file_ref():
    source = read_file('aiohai/core/crypto/fido_gate.py')
    assert 'fido2_templates.py' not in source, "fido2_templates.py reference remains"

def test_template_vars_defined():
    source = read_file('aiohai/core/crypto/fido_gate.py')
    for name in ['_DASHBOARD_HTML', '_APPROVAL_HTML', '_REGISTER_HTML', '_ERROR_HTML']:
        assert f'{name} =' in source, f"{name} not defined"

def test_template_getters_exist():
    source = read_file('aiohai/core/crypto/fido_gate.py')
    for func in ['_get_dashboard_html', '_get_approval_html',
                  '_get_register_html', '_get_error_html']:
        assert f'def {func}()' in source, f"{func}() missing"

run_test("no exec() call in AST", test_no_exec_call)
run_test("no fido2_templates.py reference", test_no_templates_file_ref)
run_test("template variables defined", test_template_vars_defined)
run_test("template getter functions exist", test_template_getters_exist)


# ============================================================================
# STEP 2: PIIProtector method name
# ============================================================================
print("\n=== STEP 2: PIIProtector method name fix ===")

def test_no_bare_redact_call():
    """Check handler.py and query_executor.py for broken .redact() calls on pii_protector."""
    for path in ['aiohai/proxy/handler.py', 'aiohai/integrations/smart_home/query_executor.py']:
        source = read_file(path)
        for i, line in enumerate(source.split('\n'), 1):
            if '.redact(' in line and '.redact_for_logging(' not in line:
                if 'pii' in line.lower():
                    raise AssertionError(f"{path} line {i}: calls .redact() instead of .redact_for_logging()")

def test_pii_has_redact_for_logging():
    source = read_file('aiohai/core/analysis/pii_protector.py')
    assert 'def redact_for_logging(' in source, "redact_for_logging() not found in PIIProtector"

run_test("handler doesn't call nonexistent .redact()", test_no_bare_redact_call)
run_test("PIIProtector has redact_for_logging()", test_pii_has_redact_for_logging)


# ============================================================================
# STEP 3: Lockdown checks on all HTTP handlers
# ============================================================================
print("\n=== STEP 3: Lockdown checks on GET/DELETE ===")

def test_do_GET_lockdown():
    source = read_file('aiohai/proxy/handler.py')
    idx = source.find('def do_GET')
    assert idx != -1, "do_GET not found"
    # Look in the next 2000 chars for the lockdown check
    chunk = source[idx:idx+2000]
    assert 'is_locked_down' in chunk, "do_GET missing is_locked_down check"

def test_do_DELETE_lockdown():
    source = read_file('aiohai/proxy/handler.py')
    idx = source.find('def do_DELETE')
    assert idx != -1, "do_DELETE not found"
    chunk = source[idx:idx+2000]
    assert 'is_locked_down' in chunk, "do_DELETE missing is_locked_down check"

def test_do_POST_lockdown():
    source = read_file('aiohai/proxy/handler.py')
    idx = source.find('def do_POST')
    assert idx != -1, "do_POST not found"
    chunk = source[idx:idx+3000]
    assert 'is_locked_down' in chunk, "do_POST missing is_locked_down check (regression)"

run_test("do_GET checks lockdown", test_do_GET_lockdown)
run_test("do_DELETE checks lockdown", test_do_DELETE_lockdown)
run_test("do_POST checks lockdown", test_do_POST_lockdown)


# ============================================================================
# STEP 4: Network allowlist safe defaults
# ============================================================================
print("\n=== STEP 4: Network allowlist safe defaults ===")

def test_no_github_in_default_allowlist():
    source = read_file('aiohai/core/config.py')
    # Find lines around network_allowlist default
    lines = source.split('\n')
    in_block = False
    block = []
    for line in lines:
        if 'network_allowlist' in line:
            in_block = True
        if in_block:
            block.append(line)
            if ']' in line:
                in_block = False
    block_text = '\n'.join(block)
    assert 'github.com' not in block_text, "github.com in default allowlist"

def test_no_pypi_in_default_allowlist():
    source = read_file('aiohai/core/config.py')
    lines = source.split('\n')
    in_block = False
    block = []
    for line in lines:
        if 'network_allowlist' in line:
            in_block = True
        if in_block:
            block.append(line)
            if ']' in line:
                in_block = False
    block_text = '\n'.join(block)
    assert 'pypi.org' not in block_text, "pypi.org in default allowlist"

run_test("no github.com in default allowlist", test_no_github_in_default_allowlist)
run_test("no pypi.org in default allowlist", test_no_pypi_in_default_allowlist)


# ============================================================================
# STEP 5: Dead code removed
# ============================================================================
print("\n=== STEP 5: Dead code removed ===")

def test_no_financial_path_patterns():
    source = read_file('aiohai/core/patterns.py')
    assert 'FINANCIAL_PATH_PATTERNS' not in source, "FINANCIAL_PATH_PATTERNS should be removed"

def test_no_clipboard_block_patterns():
    source = read_file('aiohai/core/patterns.py')
    assert 'CLIPBOARD_BLOCK_PATTERNS' not in source, "CLIPBOARD_BLOCK_PATTERNS should be removed"

def test_no_stale_p4_test():
    assert not (PROJECT_ROOT / 'tests' / 'test_extraction_verify_p4.py').exists(), "p4 test file should be deleted"

def test_no_stale_p5_test():
    assert not (PROJECT_ROOT / 'tests' / 'test_extraction_verify_p5.py').exists(), "p5 test file should be deleted"

def test_no_proxy_startup_shim():
    assert not (PROJECT_ROOT / 'aiohai' / 'proxy' / 'startup.py').exists(), "proxy/startup.py shim should be deleted"

def test_proxy_init_imports_from_core():
    source = read_file('aiohai/proxy/__init__.py')
    assert 'from aiohai.core.audit.startup import StartupSecurityVerifier' in source, \
        "Should import StartupSecurityVerifier from core.audit.startup"

def test_types_no_facade_reference():
    source = read_file('aiohai/core/types.py')
    assert 'facade' not in source.lower(), "types.py should not reference facades"

run_test("FINANCIAL_PATH_PATTERNS removed", test_no_financial_path_patterns)
run_test("CLIPBOARD_BLOCK_PATTERNS removed", test_no_clipboard_block_patterns)
run_test("stale p4 test deleted", test_no_stale_p4_test)
run_test("stale p5 test deleted", test_no_stale_p5_test)
run_test("proxy/startup.py shim removed", test_no_proxy_startup_shim)
run_test("proxy/__init__ imports from core", test_proxy_init_imports_from_core)
run_test("types.py no facade references", test_types_no_facade_reference)

# ============================================================================
# STEP 6: Deduplicated _is_obfuscated()
# ============================================================================
print("\n=== STEP 6: Deduplicated _is_obfuscated() ===")

def test_shared_is_obfuscated_exists():
    source = read_file('aiohai/core/analysis/utils.py')
    assert 'def is_obfuscated(' in source, "Shared is_obfuscated() should exist in utils.py"

def test_command_validator_delegates():
    source = read_file('aiohai/core/access/command_validator.py')
    assert 'from aiohai.core.analysis.utils import is_obfuscated' in source, \
        "command_validator should import from utils"

def test_static_analyzer_delegates():
    source = read_file('aiohai/core/analysis/static_analyzer.py')
    assert 'from aiohai.core.analysis.utils import is_obfuscated' in source, \
        "static_analyzer should import from utils"

def test_no_duplicate_obfuscation_logic():
    """Neither file should have the full duplicate logic (special/len(text) > 0.15)."""
    for path in ['aiohai/core/access/command_validator.py', 'aiohai/core/analysis/static_analyzer.py']:
        source = read_file(path)
        assert 'special / len(' not in source, \
            f"{path} still contains duplicated obfuscation logic"

def test_shared_function_works():
    """The shared function should detect obfuscation correctly."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("utils", PROJECT_ROOT / 'aiohai' / 'core' / 'analysis' / 'utils.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # Short strings should not be flagged
    assert not mod.is_obfuscated("dir"), "Short strings should not be obfuscated"
    # Highly obfuscated strings should be flagged
    obf = "$a='po';$b='wer';$c=$a+$b+'shell';$d=[char]105;iex($c+' -enc '+$d)"
    assert mod.is_obfuscated(obf), "Obfuscated PowerShell should be detected"

run_test("shared is_obfuscated() exists", test_shared_is_obfuscated_exists)
run_test("command_validator delegates to shared", test_command_validator_delegates)
run_test("static_analyzer delegates to shared", test_static_analyzer_delegates)
run_test("no duplicate obfuscation logic", test_no_duplicate_obfuscation_logic)
run_test("shared function detects obfuscation", test_shared_function_works)

# ============================================================================
# STEP 7: Resolved session_manager circular dependency
# ============================================================================
print("\n=== STEP 7: Session manager circular dependency ===")

def test_session_manager_no_module_level_proxy_import():
    """session_manager.py must not import from proxy at module level."""
    source = read_file('aiohai/core/access/session_manager.py')
    lines = source.split('\n')
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        # Skip lines inside function bodies (indented)
        if stripped.startswith('from aiohai.proxy') and not line.startswith(' ') and not line.startswith('\t'):
            raise AssertionError(f"Line {i}: module-level import from proxy layer")

def test_session_manager_uses_lazy_import():
    source = read_file('aiohai/core/access/session_manager.py')
    assert 'def _get_approval_manager' in source or '__new__' in source, \
        "Should use lazy import pattern"

def test_session_manager_parses():
    import ast
    source = read_file('aiohai/core/access/session_manager.py')
    ast.parse(source)  # Will raise if broken

run_test("no module-level proxy import", test_session_manager_no_module_level_proxy_import)
run_test("uses lazy import pattern", test_session_manager_uses_lazy_import)
run_test("session_manager.py parses cleanly", test_session_manager_parses)

# ============================================================================
# STEP 8: Config loaded once in orchestrator
# ============================================================================
print("\n=== STEP 8: Config loaded once in orchestrator ===")

def test_raw_config_stored_in_init():
    source = read_file('aiohai/proxy/orchestrator.py')
    assert 'self._raw_config' in source, "Should store raw config as instance attribute"

def test_init_helpers_use_raw_config():
    source = read_file('aiohai/proxy/orchestrator.py')
    # The init helpers should reference _raw_config, not re-open config.json
    # Find _init_office_components and _init_smart_home, check they don't load config.json
    for method_name in ['_init_office_components', '_init_smart_home']:
        idx = source.find(f'def {method_name}')
        if idx == -1:
            continue
        # Find the next method (def at same indentation)
        next_def = source.find('\n    def ', idx + 10)
        method_body = source[idx:next_def] if next_def != -1 else source[idx:]
        assert "json.load(f)" not in method_body, \
            f"{method_name} still loads config.json directly"

def test_orchestrator_parses():
    import ast
    source = read_file('aiohai/proxy/orchestrator.py')
    ast.parse(source)

run_test("_raw_config stored in __init__", test_raw_config_stored_in_init)
run_test("init helpers use _raw_config, not re-load", test_init_helpers_use_raw_config)
run_test("orchestrator.py parses cleanly", test_orchestrator_parses)

# ============================================================================
# STEP 9: Merged COMMAND_PATTERNS into patterns.py
# ============================================================================
print("\n=== STEP 9: Consolidated command patterns ===")

def test_command_analysis_patterns_exists():
    source = read_file('aiohai/core/patterns.py')
    assert 'COMMAND_ANALYSIS_PATTERNS' in source, "COMMAND_ANALYSIS_PATTERNS should exist in patterns.py"

def test_blocked_derived_from_analysis():
    source = read_file('aiohai/core/patterns.py')
    assert 'BLOCKED_COMMAND_PATTERNS = [p[0] for p in COMMAND_ANALYSIS_PATTERNS]' in source, \
        "BLOCKED_COMMAND_PATTERNS should be derived from COMMAND_ANALYSIS_PATTERNS"

def test_static_analyzer_no_inline_command_patterns():
    source = read_file('aiohai/core/analysis/static_analyzer.py')
    assert 'COMMAND_PATTERNS = [' not in source, \
        "StaticAnalyzer should not define its own COMMAND_PATTERNS"

def test_static_analyzer_imports_from_patterns():
    source = read_file('aiohai/core/analysis/static_analyzer.py')
    assert 'from aiohai.core.patterns import COMMAND_ANALYSIS_PATTERNS' in source, \
        "StaticAnalyzer should import COMMAND_ANALYSIS_PATTERNS"

def test_analysis_patterns_have_metadata():
    """Each entry should be a tuple with (regex, severity, cwe, description)."""
    source = read_file('aiohai/core/patterns.py')
    # Check it has tuples not bare strings
    assert "'CRITICAL'" in source or "'HIGH'" in source, \
        "COMMAND_ANALYSIS_PATTERNS should contain severity strings"

def test_patterns_py_parses():
    import ast
    source = read_file('aiohai/core/patterns.py')
    ast.parse(source)

def test_static_analyzer_parses():
    import ast
    source = read_file('aiohai/core/analysis/static_analyzer.py')
    ast.parse(source)

run_test("COMMAND_ANALYSIS_PATTERNS exists in patterns.py", test_command_analysis_patterns_exists)
run_test("BLOCKED_COMMAND_PATTERNS derived from analysis", test_blocked_derived_from_analysis)
run_test("StaticAnalyzer no inline COMMAND_PATTERNS", test_static_analyzer_no_inline_command_patterns)
run_test("StaticAnalyzer imports from patterns.py", test_static_analyzer_imports_from_patterns)
run_test("analysis patterns have severity metadata", test_analysis_patterns_have_metadata)
run_test("patterns.py parses cleanly", test_patterns_py_parses)
run_test("static_analyzer.py parses cleanly", test_static_analyzer_parses)

# ============================================================================
# STEP 10: pyproject.toml exists and is valid
# ============================================================================
print("\n=== STEP 10: pyproject.toml ===")

def test_pyproject_exists():
    assert (PROJECT_ROOT / 'pyproject.toml').exists(), "pyproject.toml should exist"

def test_pyproject_has_version():
    source = read_file('pyproject.toml')
    assert 'version = "5.0.0"' in source, "Should have version 5.0.0"

def test_pyproject_has_entry_point():
    source = read_file('pyproject.toml')
    assert 'aiohai = "aiohai.__main__:main"' in source, "Should have aiohai CLI entry point"

def test_pyproject_has_optional_deps():
    source = read_file('pyproject.toml')
    for group in ['fido2', 'hsm', 'office', 'dev']:
        assert f'[project.optional-dependencies]\n' in source or f'{group} = [' in source, \
            f"Should have {group} optional dependency group"

def test_pyproject_python_version():
    source = read_file('pyproject.toml')
    assert 'requires-python = ">=3.10"' in source, "Should require Python 3.10+"

run_test("pyproject.toml exists", test_pyproject_exists)
run_test("version is 5.0.0", test_pyproject_has_version)
run_test("has CLI entry point", test_pyproject_has_entry_point)
run_test("has optional dependency groups", test_pyproject_has_optional_deps)
run_test("requires Python 3.10+", test_pyproject_python_version)

# ============================================================================
# Summary
# ============================================================================
print(f"\n{'='*50}")
print(f"Results: {passed} passed, {failed} failed")
if errors:
    print("\nFailures:")
    for name, msg in errors:
        print(f"  - {name}: {msg}")
    sys.exit(1)
else:
    print("All tests passed!")
    sys.exit(0)
