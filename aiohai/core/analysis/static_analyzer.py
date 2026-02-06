#!/usr/bin/env python3
"""
AIOHAI Core Analysis — Static Security Analyzer
=================================================
Bandit-style static analysis for LLM-generated code:
- AST-based dangerous function call detection
- Regex-based pattern matching for credentials, injection, obfuscation
- Command-specific analysis (PowerShell, CMD patterns)
- Risk scoring and block recommendations

Previously defined inline in security/security_components.py.
Extracted as Phase 2b of the monolith → layered architecture migration.

Import from: aiohai.core.analysis.static_analyzer
"""

import re
import ast
from typing import List

from aiohai.core.types import Severity, SecurityFinding
from aiohai.core.patterns import COMMAND_ANALYSIS_PATTERNS


class StaticSecurityAnalyzer:
    """Comprehensive static analysis for code/commands before execution."""

    DANGEROUS_CALLS = {
        'eval': (Severity.CRITICAL, 'CWE-95', 'Arbitrary code execution via eval()'),
        'exec': (Severity.CRITICAL, 'CWE-95', 'Arbitrary code execution via exec()'),
        'compile': (Severity.HIGH, 'CWE-95', 'Dynamic code compilation'),
        '__import__': (Severity.HIGH, 'CWE-95', 'Dynamic import'),
        'os.system': (Severity.CRITICAL, 'CWE-78', 'Shell command execution'),
        'os.popen': (Severity.CRITICAL, 'CWE-78', 'Shell command execution'),
        'subprocess.call': (Severity.HIGH, 'CWE-78', 'Command execution'),
        'subprocess.Popen': (Severity.HIGH, 'CWE-78', 'Command execution'),
        'pickle.loads': (Severity.CRITICAL, 'CWE-502', 'Unsafe deserialization'),
        'pickle.load': (Severity.CRITICAL, 'CWE-502', 'Unsafe deserialization'),
        'yaml.load': (Severity.HIGH, 'CWE-502', 'Unsafe YAML loading'),
        'yaml.unsafe_load': (Severity.CRITICAL, 'CWE-502', 'Unsafe YAML loading'),
        'marshal.loads': (Severity.CRITICAL, 'CWE-502', 'Unsafe deserialization'),
        'shutil.rmtree': (Severity.HIGH, 'CWE-22', 'Recursive deletion'),
        'os.remove': (Severity.MEDIUM, 'CWE-22', 'File deletion'),
        'os.chmod': (Severity.MEDIUM, 'CWE-732', 'Permission modification'),
        'socket.socket': (Severity.MEDIUM, 'CWE-918', 'Network socket'),
        'urllib.request.urlopen': (Severity.MEDIUM, 'CWE-918', 'URL request'),
        'requests.post': (Severity.HIGH, 'CWE-918', 'HTTP POST - data exfil risk'),
        'hashlib.md5': (Severity.MEDIUM, 'CWE-328', 'Weak hash algorithm'),
        'random.random': (Severity.MEDIUM, 'CWE-330', 'Non-cryptographic RNG'),
        'ctypes.windll': (Severity.HIGH, 'CWE-676', 'Low-level Windows API'),
        'ctypes.CDLL': (Severity.HIGH, 'CWE-676', 'Native library loading'),
    }

    DANGEROUS_PATTERNS = [
        (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']+["\']', Severity.CRITICAL, 'CWE-798', 'Hardcoded password'),
        (r'(?i)(api_?key|apikey)\s*=\s*["\'][A-Za-z0-9]{16,}["\']', Severity.CRITICAL, 'CWE-798', 'Hardcoded API key'),
        (r'(?i)(secret|token)\s*=\s*["\'][A-Za-z0-9+/=]{20,}["\']', Severity.CRITICAL, 'CWE-798', 'Hardcoded secret'),
        (r'(?i)aws_access_key_id\s*=\s*["\']AKIA', Severity.CRITICAL, 'CWE-798', 'AWS access key'),
        (r'(?i)aws_secret_access_key\s*=', Severity.CRITICAL, 'CWE-798', 'AWS secret key'),
        (r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', Severity.CRITICAL, 'CWE-798', 'Embedded private key'),
        (r'execute\s*\(\s*["\'].*%s', Severity.HIGH, 'CWE-89', 'SQL injection via %s'),
        (r'execute\s*\(\s*f["\']', Severity.HIGH, 'CWE-89', 'SQL injection via f-string'),
        (r'shell\s*=\s*True', Severity.CRITICAL, 'CWE-78', 'shell=True is dangerous'),
        (r'bytes\.fromhex\s*\(\s*["\'][0-9a-fA-F]+["\']\s*\)', Severity.CRITICAL, 'CWE-506', 'Hex-encoded payload'),
        (r'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}', Severity.HIGH, 'CWE-506', 'Hex escape sequence'),
        (r'\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){5,}', Severity.HIGH, 'CWE-506', 'Unicode escape obfuscation'),
        (r'zlib\.decompress', Severity.CRITICAL, 'CWE-506', 'Compressed payload'),
        (r'gzip\.decompress', Severity.CRITICAL, 'CWE-506', 'Compressed payload'),
        (r'bz2\.decompress', Severity.CRITICAL, 'CWE-506', 'Compressed payload'),
        (r'lzma\.decompress', Severity.CRITICAL, 'CWE-506', 'Compressed payload'),
        (r'base64\.b64decode\s*\([^)]+\)\s*\)', Severity.HIGH, 'CWE-506', 'Base64 decoded execution'),
        (r'exec\s*\(\s*compile\s*\(', Severity.CRITICAL, 'CWE-506', 'Dynamic compilation + execution'),
        (r'getattr\s*\(\s*__builtins__', Severity.CRITICAL, 'CWE-506', 'Builtin access bypass'),
        (r'chr\s*\(\s*\d+\s*\)(?:\s*\+\s*chr\s*\(\s*\d+\s*\)){3,}', Severity.HIGH, 'CWE-506', 'Char code assembly'),
        (r'codecs\.decode\s*\([^)]+,\s*["\']rot', Severity.HIGH, 'CWE-506', 'ROT13 obfuscation'),
        (r'(?i)\[char\]\s*\d+(?:\s*\+\s*\[char\]\s*\d+){3,}', Severity.HIGH, 'CWE-506', 'PowerShell char assembly'),
        (r'\.\.[/\\]', Severity.MEDIUM, 'CWE-22', 'Path traversal'),
    ]

    # Command patterns imported from centralized patterns.py (single source of truth).
    # Severity strings are converted to Severity enums at compile time.
    _SEVERITY_MAP = {s.name: s for s in Severity}

    def __init__(self):
        self.findings: List[SecurityFinding] = []
        self.compiled_patterns = [(re.compile(p, re.I), s, c, m) for p, s, c, m in self.DANGEROUS_PATTERNS]
        self.compiled_commands = [
            (re.compile(p, re.I), self._SEVERITY_MAP[s], c, m)
            for p, s, c, m in COMMAND_ANALYSIS_PATTERNS
        ]

    def analyze_code(self, code: str) -> List[SecurityFinding]:
        """Analyze Python code for security issues."""
        self.findings = []
        lines = code.split('\n')

        # Pattern-based
        for i, line in enumerate(lines, 1):
            for pattern, severity, cwe, message in self.compiled_patterns:
                if pattern.search(line):
                    self.findings.append(SecurityFinding(
                        severity=severity, category='DANGEROUS_PATTERN',
                        message=message, line=i,
                        code_snippet=line.strip()[:100], cwe_id=cwe
                    ))

        # AST-based
        try:
            tree = ast.parse(code)
            self._analyze_ast(tree)
        except SyntaxError:
            pass

        return self.findings

    def analyze_command(self, command: str) -> List[SecurityFinding]:
        """Analyze shell command for security issues."""
        self.findings = []

        for pattern, severity, cwe, message in self.compiled_commands:
            if pattern.search(command):
                self.findings.append(SecurityFinding(
                    severity=severity, category='DANGEROUS_COMMAND',
                    message=message, line=1,
                    code_snippet=command[:100], cwe_id=cwe
                ))

        if self._is_obfuscated(command):
            self.findings.append(SecurityFinding(
                severity=Severity.HIGH, category='OBFUSCATION',
                message='Command appears obfuscated', line=1,
                code_snippet=command[:100], cwe_id='CWE-506'
            ))

        return self.findings

    def _analyze_ast(self, tree: ast.AST):
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node)
                if func_name in self.DANGEROUS_CALLS:
                    severity, cwe, message = self.DANGEROUS_CALLS[func_name]
                    self.findings.append(SecurityFinding(
                        severity=severity, category='DANGEROUS_CALL',
                        message=message, line=getattr(node, 'lineno', None),
                        code_snippet=func_name, cwe_id=cwe
                    ))

                if func_name in ('subprocess.run', 'subprocess.call', 'subprocess.Popen'):
                    for kw in node.keywords:
                        if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value:
                            self.findings.append(SecurityFinding(
                                severity=Severity.CRITICAL, category='SHELL_INJECTION',
                                message='subprocess with shell=True', line=node.lineno,
                                code_snippet='shell=True', cwe_id='CWE-78'
                            ))

                if func_name == 'getattr' and len(node.args) >= 2:
                    if isinstance(node.args[0], ast.Name) and node.args[0].id == '__builtins__':
                        if isinstance(node.args[1], ast.Constant):
                            accessed = node.args[1].value
                            if accessed in ('eval', 'exec', '__import__', 'open', 'compile'):
                                self.findings.append(SecurityFinding(
                                    severity=Severity.CRITICAL, category='OBFUSCATED_BUILTIN',
                                    message=f'Obfuscated access to {accessed}', line=node.lineno,
                                    code_snippet=f"getattr(__builtins__, '{accessed}')", cwe_id='CWE-506'
                                ))

    def _get_call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return '.'.join(reversed(parts))
        return ''

    def _is_obfuscated(self, text: str) -> bool:
        from aiohai.core.analysis.utils import is_obfuscated
        return is_obfuscated(text)

    def get_risk_score(self) -> int:
        score = 0
        for f in self.findings:
            if f.severity == Severity.CRITICAL: score += 40
            elif f.severity == Severity.HIGH: score += 25
            elif f.severity == Severity.MEDIUM: score += 10
            elif f.severity == Severity.LOW: score += 3
        return min(100, score)

    def should_block(self) -> bool:
        critical = sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in self.findings if f.severity == Severity.HIGH)
        return critical > 0 or high >= 2 or self.get_risk_score() >= 50

    def get_report(self) -> str:
        if not self.findings:
            return "\u2705 No security issues found."
        lines = [f"\u26a0\ufe0f Found {len(self.findings)} security issue(s):\n"]
        icons = {Severity.CRITICAL: "\U0001f534", Severity.HIGH: "\U0001f7e0", Severity.MEDIUM: "\U0001f7e1", Severity.LOW: "\U0001f7e2"}
        for f in sorted(self.findings, key=lambda x: x.severity.value, reverse=True):
            lines.append(f"{icons[f.severity]} [{f.severity.name}] {f.message}")
            if f.line: lines.append(f"   Line {f.line}: {f.code_snippet}")
            if f.cwe_id: lines.append(f"   Reference: {f.cwe_id}")
            lines.append("")
        lines.append(f"Risk Score: {self.get_risk_score()}/100")
        lines.append(f"Recommendation: {'BLOCK' if self.should_block() else 'ALLOW with caution'}")
        return "\n".join(lines)


__all__ = [
    'StaticSecurityAnalyzer',
    'Severity',
    'SecurityFinding',
]
