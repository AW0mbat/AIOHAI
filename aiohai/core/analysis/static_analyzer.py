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

    COMMAND_PATTERNS = [
        (r'(?i)-e\s+[A-Za-z0-9+/=]{10,}', Severity.CRITICAL, 'CWE-78', 'Encoded command'),
        (r'(?i)-en\s+[A-Za-z0-9+/=]{10,}', Severity.CRITICAL, 'CWE-78', 'Encoded command'),
        (r'(?i)-enc\s+[A-Za-z0-9+/=]{10,}', Severity.CRITICAL, 'CWE-78', 'Encoded command'),
        (r'(?i)-enco', Severity.CRITICAL, 'CWE-78', 'Encoded command prefix'),
        (r'(?i)-encod', Severity.CRITICAL, 'CWE-78', 'Encoded command prefix'),
        (r'(?i)-encode', Severity.CRITICAL, 'CWE-78', 'Encoded command prefix'),
        (r'(?i)-encodedcommand', Severity.CRITICAL, 'CWE-78', 'Encoded command'),
        (r'(?i)invoke-expression', Severity.CRITICAL, 'CWE-78', 'PowerShell IEX'),
        (r'(?i)\biex\s', Severity.CRITICAL, 'CWE-78', 'PowerShell IEX alias'),
        (r'(?i)downloadstring', Severity.CRITICAL, 'CWE-78', 'Remote download'),
        (r'(?i)downloadfile', Severity.HIGH, 'CWE-78', 'File download'),
        (r'(?i)invoke-webrequest.*\|.*iex', Severity.CRITICAL, 'CWE-78', 'Download + execute'),
        (r'(?i)set-executionpolicy\s+(bypass|unrestricted)', Severity.CRITICAL, 'CWE-78', 'Policy bypass'),
        (r'(?i)add-type.*-typedefinition', Severity.HIGH, 'CWE-78', 'C# compilation'),
        (r'(?i)\[System\.Reflection\.Assembly\]::Load', Severity.CRITICAL, 'CWE-78', 'Assembly loading'),
        (r'(?i)frombase64string', Severity.HIGH, 'CWE-506', 'Base64 decoding'),
        (r'(?i)\[convert\]::frombase64', Severity.HIGH, 'CWE-506', 'Base64 decoding'),
        (r'(?i)certutil.*-urlcache', Severity.CRITICAL, 'CWE-78', 'certutil download'),
        (r'(?i)certutil.*-decode', Severity.HIGH, 'CWE-506', 'certutil decode'),
        (r'(?i)bitsadmin.*/transfer', Severity.HIGH, 'CWE-78', 'BITS download'),
        (r'(?i)\bmshta\b', Severity.CRITICAL, 'CWE-78', 'MSHTA execution'),
        (r'(?i)regsvr32.*/s', Severity.HIGH, 'CWE-78', 'Silent DLL registration'),
        (r'(?i)rundll32.*javascript', Severity.CRITICAL, 'CWE-78', 'rundll32 JavaScript'),
        (r'(?i)wmic.*process.*call.*create', Severity.HIGH, 'CWE-78', 'WMI process creation'),
        (r'(?i)schtasks.*/create', Severity.HIGH, 'CWE-78', 'Scheduled task'),
        (r'(?i)reg\s+add.*\\run', Severity.HIGH, 'CWE-78', 'Registry Run key'),
        (r'(?i)sc\s+create', Severity.HIGH, 'CWE-78', 'Service creation'),
        (r'(?i)new-service', Severity.HIGH, 'CWE-78', 'PowerShell service'),
        (r'(?i)\\start\s*menu\\programs\\startup', Severity.HIGH, 'CWE-78', 'Startup folder'),
        (r'(?i)\$profile', Severity.HIGH, 'CWE-78', 'PowerShell profile'),
        (r'(?i)set-wmiinstance.*__eventfilter', Severity.CRITICAL, 'CWE-78', 'WMI subscription'),
        (r'(?i)new-itemproperty.*\\run', Severity.HIGH, 'CWE-78', 'Registry Run'),
        (r'(?i)\\currentversion\\explorer\\shell', Severity.HIGH, 'CWE-78', 'Shell folders'),
        (r'(?i)userinit', Severity.HIGH, 'CWE-78', 'Userinit key'),
        (r'(?i)winlogon\\shell', Severity.HIGH, 'CWE-78', 'Winlogon shell'),
        (r'(?i)set-mppreference.*-disable', Severity.CRITICAL, 'CWE-78', 'Defender disable'),
        (r'(?i)add-mppreference.*-exclusion', Severity.HIGH, 'CWE-78', 'Defender exclusion'),
        (r'(?i)amsiutils', Severity.CRITICAL, 'CWE-78', 'AMSI bypass'),
        (r'(?i)amsiinitfailed', Severity.CRITICAL, 'CWE-78', 'AMSI bypass'),
        (r'(?i)net\s+user.*\/add', Severity.HIGH, 'CWE-78', 'User creation'),
        (r'(?i)net\s+localgroup.*admin', Severity.CRITICAL, 'CWE-78', 'Admin group modification'),
        (r'(?i)mimikatz', Severity.CRITICAL, 'CWE-78', 'Mimikatz'),
        (r'(?i)sekurlsa', Severity.CRITICAL, 'CWE-78', 'Credential dumping'),
        (r'(?i)procdump.*lsass', Severity.CRITICAL, 'CWE-78', 'LSASS dump'),
        (r'(?i)\bclip\b', Severity.MEDIUM, 'CWE-200', 'Clipboard access'),
        (r'(?i)set-clipboard', Severity.MEDIUM, 'CWE-200', 'Clipboard write'),
        (r'(?i)get-clipboard', Severity.MEDIUM, 'CWE-200', 'Clipboard read'),
    ]

    def __init__(self):
        self.findings: List[SecurityFinding] = []
        self.compiled_patterns = [(re.compile(p, re.I), s, c, m) for p, s, c, m in self.DANGEROUS_PATTERNS]
        self.compiled_commands = [(re.compile(p, re.I), s, c, m) for p, s, c, m in self.COMMAND_PATTERNS]

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
        if len(text) < 20:
            return False
        indicators = 0
        special = len(re.findall(r'[`$\[\]{}()\\^]', text))
        if len(text) > 0 and special / len(text) > 0.15:
            indicators += 1
        if re.search(r'["\'][^"\']{1,10}["\']\s*\+\s*["\']', text):
            indicators += 1
        if re.search(r'\$\w+\s*=\s*["\'].*["\']\s*;', text):
            indicators += 1
        if re.search(r'\[char\]|\[int\].*-join', text, re.I):
            indicators += 1
        if text.count('^') > 5:
            indicators += 1
        if re.search(r'[A-Za-z0-9+/]{40,}={0,2}', text):
            indicators += 1
        return indicators >= 2

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
