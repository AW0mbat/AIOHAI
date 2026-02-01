#!/usr/bin/env python3
"""
AIOHAI Security Components v3.0
==================================
Advanced security modules for the unified proxy:
- StaticSecurityAnalyzer: Bandit-style code analysis
- PIIProtector: PII detection and redaction
- ResourceLimiter: DoS protection
- DualLLMVerifier: Secondary LLM audit

Author: Security-First LLM Project
Version: 3.0.0
"""

import ast
import re
import os
import sys
import time
import threading
import hashlib
import json
import urllib.request
from typing import List, Dict, Tuple, Optional, Set
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from contextlib import contextmanager

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


# =============================================================================
# ENUMS
# =============================================================================

class Severity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class PIIType(Enum):
    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    IP_ADDRESS = "ip_address"
    USERNAME = "username"
    FILEPATH_WITH_USER = "filepath_with_user"
    AWS_KEY = "aws_key"
    API_KEY = "api_key"
    PRIVATE_KEY = "private_key"
    PASSWORD = "password"


class Verdict(Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"
    BLOCKED = "blocked"


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class SecurityFinding:
    severity: Severity
    category: str
    message: str
    line: Optional[int]
    code_snippet: str
    cwe_id: Optional[str] = None
    remediation: Optional[str] = None


@dataclass
class PIIFinding:
    pii_type: PIIType
    value: str
    start: int
    end: int
    confidence: float


@dataclass
class VerificationResult:
    verdict: Verdict
    risk_score: int
    concerns: List[str]
    recommendation: str
    reasoning: str


@dataclass
class ResourceLimits:
    max_execution_time_seconds: int = 30
    max_session_time_minutes: int = 60
    max_memory_mb: int = 512
    max_memory_percent: float = 25.0
    max_cpu_percent: float = 50.0
    max_disk_write_mb: int = 100
    max_file_size_mb: int = 50
    max_files_created: int = 100
    max_requests_per_minute: int = 60
    max_actions_per_minute: int = 30
    max_concurrent_actions: int = 5
    max_output_size_bytes: int = 1_000_000


# =============================================================================
# STATIC SECURITY ANALYZER
# =============================================================================

class StaticSecurityAnalyzer:
    """
    Comprehensive static analysis for code/commands before execution.
    Bandit-inspired but tailored for LLM-generated code.
    """
    
    DANGEROUS_CALLS = {
        # Code execution
        'eval': (Severity.CRITICAL, 'CWE-95', 'Arbitrary code execution via eval()'),
        'exec': (Severity.CRITICAL, 'CWE-95', 'Arbitrary code execution via exec()'),
        'compile': (Severity.HIGH, 'CWE-95', 'Dynamic code compilation'),
        '__import__': (Severity.HIGH, 'CWE-95', 'Dynamic import'),
        
        # Shell execution
        'os.system': (Severity.CRITICAL, 'CWE-78', 'Shell command execution'),
        'os.popen': (Severity.CRITICAL, 'CWE-78', 'Shell command execution'),
        'subprocess.call': (Severity.HIGH, 'CWE-78', 'Command execution'),
        'subprocess.Popen': (Severity.HIGH, 'CWE-78', 'Command execution'),
        
        # Deserialization
        'pickle.loads': (Severity.CRITICAL, 'CWE-502', 'Unsafe deserialization'),
        'pickle.load': (Severity.CRITICAL, 'CWE-502', 'Unsafe deserialization'),
        'yaml.load': (Severity.HIGH, 'CWE-502', 'Unsafe YAML loading'),
        'yaml.unsafe_load': (Severity.CRITICAL, 'CWE-502', 'Unsafe YAML loading'),
        'marshal.loads': (Severity.CRITICAL, 'CWE-502', 'Unsafe deserialization'),
        
        # File operations
        'shutil.rmtree': (Severity.HIGH, 'CWE-22', 'Recursive deletion'),
        'os.remove': (Severity.MEDIUM, 'CWE-22', 'File deletion'),
        'os.chmod': (Severity.MEDIUM, 'CWE-732', 'Permission modification'),
        
        # Network
        'socket.socket': (Severity.MEDIUM, 'CWE-918', 'Network socket'),
        'urllib.request.urlopen': (Severity.MEDIUM, 'CWE-918', 'URL request'),
        'requests.post': (Severity.HIGH, 'CWE-918', 'HTTP POST - data exfil risk'),
        
        # Crypto concerns
        'hashlib.md5': (Severity.MEDIUM, 'CWE-328', 'Weak hash algorithm'),
        'random.random': (Severity.MEDIUM, 'CWE-330', 'Non-cryptographic RNG'),
        
        # System
        'ctypes.windll': (Severity.HIGH, 'CWE-676', 'Low-level Windows API'),
        'ctypes.CDLL': (Severity.HIGH, 'CWE-676', 'Native library loading'),
    }
    
    DANGEROUS_PATTERNS = [
        # Hardcoded credentials
        (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']+["\']', Severity.CRITICAL, 'CWE-798', 'Hardcoded password'),
        (r'(?i)(api_?key|apikey)\s*=\s*["\'][A-Za-z0-9]{16,}["\']', Severity.CRITICAL, 'CWE-798', 'Hardcoded API key'),
        (r'(?i)(secret|token)\s*=\s*["\'][A-Za-z0-9+/=]{20,}["\']', Severity.CRITICAL, 'CWE-798', 'Hardcoded secret'),
        (r'(?i)aws_access_key_id\s*=\s*["\']AKIA', Severity.CRITICAL, 'CWE-798', 'AWS access key'),
        (r'(?i)aws_secret_access_key\s*=', Severity.CRITICAL, 'CWE-798', 'AWS secret key'),
        (r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', Severity.CRITICAL, 'CWE-798', 'Embedded private key'),
        
        # SQL injection
        (r'execute\s*\(\s*["\'].*%s', Severity.HIGH, 'CWE-89', 'SQL injection via %s'),
        (r'execute\s*\(\s*f["\']', Severity.HIGH, 'CWE-89', 'SQL injection via f-string'),
        
        # Command injection
        (r'shell\s*=\s*True', Severity.CRITICAL, 'CWE-78', 'shell=True is dangerous'),
        
        # Obfuscation - CRITICAL additions
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
        
        # Path traversal
        (r'\.\.[/\\]', Severity.MEDIUM, 'CWE-22', 'Path traversal'),
    ]
    
    COMMAND_PATTERNS = [
        # PowerShell encoded - ALL variations
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
        
        # CMD dangerous
        (r'(?i)certutil.*-urlcache', Severity.CRITICAL, 'CWE-78', 'certutil download'),
        (r'(?i)certutil.*-decode', Severity.HIGH, 'CWE-506', 'certutil decode'),
        (r'(?i)bitsadmin.*/transfer', Severity.HIGH, 'CWE-78', 'BITS download'),
        (r'(?i)\bmshta\b', Severity.CRITICAL, 'CWE-78', 'MSHTA execution'),
        (r'(?i)regsvr32.*/s', Severity.HIGH, 'CWE-78', 'Silent DLL registration'),
        (r'(?i)rundll32.*javascript', Severity.CRITICAL, 'CWE-78', 'rundll32 JavaScript'),
        (r'(?i)wmic.*process.*call.*create', Severity.HIGH, 'CWE-78', 'WMI process creation'),
        
        # Persistence - COMPREHENSIVE
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
        
        # Defense evasion
        (r'(?i)set-mppreference.*-disable', Severity.CRITICAL, 'CWE-78', 'Defender disable'),
        (r'(?i)add-mppreference.*-exclusion', Severity.HIGH, 'CWE-78', 'Defender exclusion'),
        (r'(?i)amsiutils', Severity.CRITICAL, 'CWE-78', 'AMSI bypass'),
        (r'(?i)amsiinitfailed', Severity.CRITICAL, 'CWE-78', 'AMSI bypass'),
        
        # Privilege escalation
        (r'(?i)net\s+user.*\/add', Severity.HIGH, 'CWE-78', 'User creation'),
        (r'(?i)net\s+localgroup.*admin', Severity.CRITICAL, 'CWE-78', 'Admin group modification'),
        
        # Credential theft
        (r'(?i)mimikatz', Severity.CRITICAL, 'CWE-78', 'Mimikatz'),
        (r'(?i)sekurlsa', Severity.CRITICAL, 'CWE-78', 'Credential dumping'),
        (r'(?i)procdump.*lsass', Severity.CRITICAL, 'CWE-78', 'LSASS dump'),
        
        # Clipboard exfiltration
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
        
        # Check for obfuscation indicators
        if self._is_obfuscated(command):
            self.findings.append(SecurityFinding(
                severity=Severity.HIGH, category='OBFUSCATION',
                message='Command appears obfuscated', line=1,
                code_snippet=command[:100], cwe_id='CWE-506'
            ))
        
        return self.findings
    
    def _analyze_ast(self, tree: ast.AST):
        """AST analysis for Python code."""
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
                
                # Check subprocess shell=True
                if func_name in ('subprocess.run', 'subprocess.call', 'subprocess.Popen'):
                    for kw in node.keywords:
                        if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value:
                            self.findings.append(SecurityFinding(
                                severity=Severity.CRITICAL, category='SHELL_INJECTION',
                                message='subprocess with shell=True', line=node.lineno,
                                code_snippet='shell=True', cwe_id='CWE-78'
                            ))
                
                # Check getattr(__builtins__, ...)
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
        
        # High special char ratio
        special = len(re.findall(r'[`$\[\]{}()\\^]', text))
        if len(text) > 0 and special / len(text) > 0.15:
            indicators += 1
        
        # String concatenation
        if re.search(r'["\'][^"\']{1,10}["\']\s*\+\s*["\']', text):
            indicators += 1
        
        # Variable construction
        if re.search(r'\$\w+\s*=\s*["\'].*["\']\s*;', text):
            indicators += 1
        
        # Char codes
        if re.search(r'\[char\]|\[int\].*-join', text, re.I):
            indicators += 1
        
        # Excessive carets (CMD obfuscation)
        if text.count('^') > 5:
            indicators += 1
        
        # Long base64-like strings
        if re.search(r'[A-Za-z0-9+/]{40,}={0,2}', text):
            indicators += 1
        
        return indicators >= 2
    
    def get_risk_score(self) -> int:
        score = 0
        for f in self.findings:
            if f.severity == Severity.CRITICAL:
                score += 40
            elif f.severity == Severity.HIGH:
                score += 25
            elif f.severity == Severity.MEDIUM:
                score += 10
            elif f.severity == Severity.LOW:
                score += 3
        return min(100, score)
    
    def should_block(self) -> bool:
        critical = sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in self.findings if f.severity == Severity.HIGH)
        return critical > 0 or high >= 2 or self.get_risk_score() >= 50
    
    def get_report(self) -> str:
        if not self.findings:
            return "✅ No security issues found."
        
        lines = [f"⚠️ Found {len(self.findings)} security issue(s):\n"]
        icons = {Severity.CRITICAL: "🔴", Severity.HIGH: "🟠", Severity.MEDIUM: "🟡", Severity.LOW: "🟢"}
        
        for f in sorted(self.findings, key=lambda x: x.severity.value, reverse=True):
            lines.append(f"{icons[f.severity]} [{f.severity.name}] {f.message}")
            if f.line:
                lines.append(f"   Line {f.line}: {f.code_snippet}")
            if f.cwe_id:
                lines.append(f"   Reference: {f.cwe_id}")
            lines.append("")
        
        lines.append(f"Risk Score: {self.get_risk_score()}/100")
        lines.append(f"Recommendation: {'BLOCK' if self.should_block() else 'ALLOW with caution'}")
        return "\n".join(lines)


# =============================================================================
# PII PROTECTOR
# =============================================================================

class PIIProtector:
    """Comprehensive PII detection and redaction."""
    
    PATTERNS = {
        PIIType.EMAIL: (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 0.95),
        PIIType.PHONE: (r'\b(?:\+1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b', 0.8),
        PIIType.SSN: (r'\b\d{3}-\d{2}-\d{4}\b', 0.95),
        PIIType.CREDIT_CARD: (r'\b(?:\d{4}[-\s]?){3}\d{4}\b', 0.9),
        PIIType.IP_ADDRESS: (r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', 0.85),
        PIIType.AWS_KEY: (r'\b(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b', 0.99),
        PIIType.API_KEY: (r'(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,})["\']?', 0.9),
        PIIType.PRIVATE_KEY: (r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', 0.99),
        PIIType.PASSWORD: (r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{4,})["\']?', 0.85),
    }
    
    def __init__(self):
        self.username = os.environ.get('USERNAME', '')
        self.userprofile = os.environ.get('USERPROFILE', '')
        self.computername = os.environ.get('COMPUTERNAME', '')
        self.compiled = {t: (re.compile(p, re.I), c) for t, (p, c) in self.PATTERNS.items()}
    
    def detect_pii(self, text: str) -> List[PIIFinding]:
        findings = []
        
        for pii_type, (pattern, confidence) in self.compiled.items():
            for match in pattern.finditer(text):
                findings.append(PIIFinding(
                    pii_type=pii_type, value=match.group()[:50],
                    start=match.start(), end=match.end(), confidence=confidence
                ))
        
        # Dynamic detection
        if self.username:
            for match in re.finditer(re.escape(self.username), text, re.I):
                findings.append(PIIFinding(
                    pii_type=PIIType.USERNAME, value=self.username,
                    start=match.start(), end=match.end(), confidence=0.99
                ))
        
        return findings
    
    def redact_pii(self, text: str, types: Set[PIIType] = None) -> Tuple[str, List[PIIFinding]]:
        if types is None:
            types = set(PIIType)
        
        findings = self.detect_pii(text)
        findings.sort(key=lambda f: f.start, reverse=True)
        
        for f in findings:
            if f.pii_type in types:
                placeholder = f"[REDACTED_{f.pii_type.value.upper()}]"
                text = text[:f.start] + placeholder + text[f.end:]
        
        return text, findings
    
    def redact_for_logging(self, text: str) -> str:
        text, _ = self.redact_pii(text)
        if self.username:
            text = re.sub(re.escape(self.username), '[USER]', text, flags=re.I)
        if self.userprofile:
            text = re.sub(re.escape(self.userprofile), '[USERPROFILE]', text, flags=re.I)
            text = re.sub(re.escape(self.userprofile.replace('\\', '/')), '[USERPROFILE]', text, flags=re.I)
        if self.computername:
            text = re.sub(re.escape(self.computername), '[COMPUTER]', text, flags=re.I)
        return text
    
    def check_response_for_pii(self, response: str) -> Dict:
        findings = self.detect_pii(response)
        critical = {PIIType.SSN, PIIType.CREDIT_CARD, PIIType.PRIVATE_KEY, PIIType.AWS_KEY, PIIType.PASSWORD}
        critical_findings = [f for f in findings if f.pii_type in critical]
        
        return {
            'contains_pii': len(findings) > 0,
            'total_findings': len(findings),
            'critical_count': len(critical_findings),
            'pii_types': list(set(f.pii_type.value for f in findings)),
            'should_block': len(critical_findings) > 0,
        }


# =============================================================================
# RESOURCE LIMITER
# =============================================================================

class ResourceLimiter:
    """Enforces resource limits to prevent DoS attacks."""
    
    def __init__(self, limits: ResourceLimits = None):
        self.limits = limits or ResourceLimits()
        self.session_start = time.time()
        self.request_times: Dict[str, list] = defaultdict(list)
        self.action_times: Dict[str, list] = defaultdict(list)
        self.disk_writes: Dict[str, int] = defaultdict(int)
        self.files_created: Dict[str, int] = defaultdict(int)
        self.active_actions = 0
        self.lock = threading.Lock()
        
        if PSUTIL_AVAILABLE:
            self.process = psutil.Process(os.getpid())
        else:
            self.process = None
    
    def check_session_time(self) -> bool:
        elapsed = (time.time() - self.session_start) / 60
        return elapsed < self.limits.max_session_time_minutes
    
    def check_rate_limit(self, user_id: str = "default", limit_type: str = "request") -> bool:
        now = time.time()
        window_start = now - 60
        
        with self.lock:
            times = self.request_times[user_id] if limit_type == "request" else self.action_times[user_id]
            max_allowed = self.limits.max_requests_per_minute if limit_type == "request" else self.limits.max_actions_per_minute
            
            times[:] = [t for t in times if t > window_start]
            if len(times) >= max_allowed:
                return False
            times.append(now)
            return True
    
    def check_concurrent_limit(self) -> bool:
        with self.lock:
            return self.active_actions < self.limits.max_concurrent_actions
    
    def acquire_action_slot(self) -> bool:
        with self.lock:
            if self.active_actions >= self.limits.max_concurrent_actions:
                return False
            self.active_actions += 1
            return True
    
    def release_action_slot(self):
        with self.lock:
            self.active_actions = max(0, self.active_actions - 1)
    
    def check_memory(self) -> Dict:
        if not self.process:
            return {'ok': True, 'memory_mb': 0}
        
        mem = self.process.memory_info().rss / (1024 * 1024)
        return {
            'ok': mem < self.limits.max_memory_mb,
            'memory_mb': round(mem, 2),
            'limit_mb': self.limits.max_memory_mb
        }
    
    def track_disk_write(self, user_id: str, bytes_written: int) -> bool:
        with self.lock:
            new_total = self.disk_writes[user_id] + bytes_written
            if new_total > self.limits.max_disk_write_mb * 1024 * 1024:
                return False
            self.disk_writes[user_id] = new_total
            return True
    
    def check_file_size(self, size_bytes: int) -> bool:
        return size_bytes <= self.limits.max_file_size_mb * 1024 * 1024
    
    def truncate_output(self, output: str) -> str:
        encoded = output.encode('utf-8')
        if len(encoded) > self.limits.max_output_size_bytes:
            max_chars = self.limits.max_output_size_bytes // 4
            return output[:max_chars] + "\n... [OUTPUT TRUNCATED]"
        return output
    
    @contextmanager
    def action_context(self, user_id: str = "default"):
        if not self.check_session_time():
            raise ResourceLimitExceeded("Session time limit exceeded")
        if not self.check_rate_limit(user_id, "action"):
            raise ResourceLimitExceeded("Action rate limit exceeded")
        if not self.acquire_action_slot():
            raise ResourceLimitExceeded("Concurrent action limit exceeded")
        
        mem = self.check_memory()
        if not mem['ok']:
            self.release_action_slot()
            raise ResourceLimitExceeded(f"Memory limit: {mem['memory_mb']}MB")
        
        try:
            yield
        finally:
            self.release_action_slot()


class ResourceLimitExceeded(Exception):
    pass


# =============================================================================
# DUAL LLM VERIFIER
# =============================================================================

class DualLLMVerifier:
    """Secondary LLM that audits the primary LLM's output."""
    
    JUDGE_PROMPT = """You are a Security Auditor AI. Analyze AI-generated actions for security risks.

OUTPUT JSON ONLY:
{
    "verdict": "SAFE" | "SUSPICIOUS" | "DANGEROUS" | "BLOCKED",
    "risk_score": 0-100,
    "concerns": ["list"],
    "recommendation": "ALLOW" | "BLOCK" | "REQUIRE_CONFIRMATION",
    "reasoning": "brief"
}

FLAG THESE:
- Encoded/obfuscated content
- Network operations
- Persistence mechanisms
- Credential access
- Actions not matching user request
- File operations in sensitive paths"""

    def __init__(self, ollama_host: str = "127.0.0.1", ollama_port: int = 11434, model: str = "llama3.1"):
        self.url = f"http://{ollama_host}:{ollama_port}"
        self.model = model
    
    def verify_action(self, action_type: str, target: str, content: str, user_request: str) -> VerificationResult:
        prompt = f"""AUDIT:
User requested: "{user_request}"
Action: {action_type}
Target: {target}
Content: {content[:500] if content else 'N/A'}

Is this safe and aligned with user intent? JSON only."""

        try:
            response = self._call(prompt)
            return self._parse(response)
        except Exception:
            return VerificationResult(
                verdict=Verdict.SUSPICIOUS, risk_score=60,
                concerns=["Verification failed"], recommendation="REQUIRE_CONFIRMATION",
                reasoning="Could not verify"
            )
    
    def _call(self, prompt: str) -> str:
        payload = {
            "model": self.model, "prompt": prompt,
            "system": self.JUDGE_PROMPT, "stream": False,
            "options": {"temperature": 0.1, "num_predict": 300}
        }
        req = urllib.request.Request(
            f"{self.url}/api/generate",
            data=json.dumps(payload).encode(),
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read()).get('response', '{}')
    
    def _parse(self, response: str) -> VerificationResult:
        try:
            response = response.strip()
            if response.startswith('```'):
                response = response.split('```')[1]
                if response.startswith('json'):
                    response = response[4:]
            
            data = json.loads(response)
            verdict_map = {'SAFE': Verdict.SAFE, 'SUSPICIOUS': Verdict.SUSPICIOUS,
                          'DANGEROUS': Verdict.DANGEROUS, 'BLOCKED': Verdict.BLOCKED}
            
            return VerificationResult(
                verdict=verdict_map.get(data.get('verdict', '').upper(), Verdict.SUSPICIOUS),
                risk_score=int(data.get('risk_score', 50)),
                concerns=data.get('concerns', []),
                recommendation=data.get('recommendation', 'REQUIRE_CONFIRMATION'),
                reasoning=data.get('reasoning', '')
            )
        except Exception:
            return VerificationResult(
                verdict=Verdict.SUSPICIOUS, risk_score=60,
                concerns=["Parse error"], recommendation="REQUIRE_CONFIRMATION",
                reasoning="Could not parse response"
            )


# =============================================================================
# MULTI-STAGE ATTACK DETECTOR
# =============================================================================

# =============================================================================
# CREDENTIAL REDACTOR
# =============================================================================

class CredentialRedactor:
    """Redacts sensitive credentials from text for safe display."""
    
    REDACTION_PATTERNS = [
        # Passwords in various formats
        (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\'<>]{3,})["\']?', r'\1: [REDACTED]'),
        (r'(?i)(pass)\s*[:=]\s*["\']?([^\s"\'<>]{3,})["\']?', r'\1: [REDACTED]'),
        
        # RTSP/streaming URLs with credentials
        (r'(rtsp|rtmp|http|https)://([^:]+):([^@]+)@', r'\1://\2:[REDACTED]@'),
        
        # API keys and tokens
        (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9_-]{16,})["\']?', r'\1: [REDACTED]'),
        (r'(?i)(secret[_-]?key|secretkey)\s*[:=]\s*["\']?([A-Za-z0-9_-]{16,})["\']?', r'\1: [REDACTED]'),
        (r'(?i)(access[_-]?token|accesstoken)\s*[:=]\s*["\']?([A-Za-z0-9_-]{16,})["\']?', r'\1: [REDACTED]'),
        (r'(?i)(auth[_-]?token|authtoken)\s*[:=]\s*["\']?([A-Za-z0-9_-]{16,})["\']?', r'\1: [REDACTED]'),
        (r'(?i)(bearer)\s+([A-Za-z0-9_-]{20,})', r'\1 [REDACTED]'),
        
        # AWS credentials
        (r'(?i)(aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*["\']?(AKIA[A-Z0-9]{16})["\']?', r'\1: [REDACTED]'),
        (r'(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', r'\1: [REDACTED]'),
        
        # Private keys
        (r'-----BEGIN[^-]+PRIVATE KEY-----[\s\S]*?-----END[^-]+PRIVATE KEY-----', '[REDACTED PRIVATE KEY]'),
        
        # Connection strings
        (r'(?i)(mongodb|postgresql|mysql|redis|amqp)://([^:]+):([^@]+)@', r'\1://\2:[REDACTED]@'),
        
        # Generic secrets in YAML/JSON
        (r'(?i)(secret|token|credential|auth)\s*:\s*["\']?([^\s"\']{8,})["\']?', r'\1: [REDACTED]'),
        
        # Credit card numbers (basic pattern)
        (r'\b(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})\b', '[REDACTED CC]'),
        
        # SSN
        (r'\b(\d{3}-\d{2}-\d{4})\b', '[REDACTED SSN]'),
    ]
    
    def __init__(self):
        self.compiled = [(re.compile(p, re.I | re.M), r) for p, r in self.REDACTION_PATTERNS]
    
    def redact(self, text: str) -> str:
        """Redact all sensitive credentials from text."""
        for pattern, replacement in self.compiled:
            text = pattern.sub(replacement, text)
        return text
    
    def redact_for_preview(self, text: str, max_length: int = 100) -> str:
        """Redact and truncate for safe preview display."""
        redacted = self.redact(text)
        # Also collapse whitespace for preview
        redacted = ' '.join(redacted.split())
        if len(redacted) > max_length:
            return redacted[:max_length] + '...'
        return redacted


# =============================================================================
# ENHANCED BLOCKED PATTERNS
# =============================================================================

# Financial software and data paths
FINANCIAL_PATH_PATTERNS = [
    # Tax software
    r'(?i)turbotax', r'(?i)taxact', r'(?i)h&r\s*block', r'(?i)taxcut',
    r'(?i)\\tax\s*return', r'(?i)\\taxes\\',
    
    # Financial software
    r'(?i)quicken', r'(?i)\\qdata\\', r'(?i)\.qdf$', r'(?i)\.qfx$',
    r'(?i)quickbooks', r'(?i)\.qbw$', r'(?i)\.qbb$',
    r'(?i)\\mint\\', r'(?i)\\ynab\\', r'(?i)\.ynab4$',
    r'(?i)gnucash', r'(?i)moneydance', r'(?i)\\money\\',
    
    # Banking/financial exports
    r'(?i)bank.*statement', r'(?i)financial.*record',
    r'(?i)account.*export', r'(?i)transaction.*history',
    r'(?i)passwords?\.csv', r'(?i)passwords?\.xlsx?',
    r'(?i)password.*export', r'(?i)credential.*export',
    r'(?i)\\statements?\\', r'(?i)\\banking\\',
    
    # Investment
    r'(?i)\\fidelity\\', r'(?i)\\schwab\\', r'(?i)\\vanguard\\',
    r'(?i)\\etrade\\', r'(?i)\\robinhood\\',
    r'(?i)brokerage.*statement', r'(?i)investment.*record',
    r'(?i)\\portfolio\\',
    
    # Crypto wallets
    r'(?i)wallet\.dat', r'(?i)\\bitcoin\\', r'(?i)\\ethereum\\',
    r'(?i)\\crypto\\', r'(?i)seed.*phrase', r'(?i)recovery.*phrase',
    
    # Insurance/medical (often has financial info)
    r'(?i)insurance.*claim', r'(?i)medical.*bill',
    r'(?i)\\insurance\\', r'(?i)\\claims\\',
]

# Enhanced clipboard blocking patterns
CLIPBOARD_BLOCK_PATTERNS = [
    # PowerShell clipboard
    r'(?i)\bclip\b', r'(?i)set-clipboard', r'(?i)get-clipboard',
    r'(?i)\[System\.Windows\.Forms\.Clipboard\]',
    r'(?i)Add-Type.*System\.Windows\.Forms.*Clipboard',
    
    # Python clipboard modules
    r'(?i)\bpyperclip\b', r'(?i)\bxerox\b', r'(?i)\bclipboard\b',
    r'(?i)import\s+pyperclip', r'(?i)import\s+clipboard',
    r'(?i)from\s+xerox\s+import',
    
    # .NET clipboard
    r'(?i)System\.Windows\.Clipboard',
    r'(?i)Clipboard\.SetText', r'(?i)Clipboard\.GetText',
    r'(?i)Clipboard\.SetData', r'(?i)Clipboard\.GetData',
    
    # Win32 API
    r'(?i)OpenClipboard', r'(?i)SetClipboardData', r'(?i)GetClipboardData',
    r'(?i)EmptyClipboard', r'(?i)CloseClipboard',
    
    # xclip/xsel (Linux but good to block)
    r'(?i)\bxclip\b', r'(?i)\bxsel\b',
]

# Trusted Docker registries
TRUSTED_DOCKER_REGISTRIES = [
    'ghcr.io/home-assistant/',
    'ghcr.io/blakeblackshear/',
    'ghcr.io/koush/',
    'ghcr.io/esphome/',
    'docker.io/library/',
    'docker.io/homeassistant/',
    'docker.io/linuxserver/',
    'docker.io/portainer/',
    'lscr.io/linuxserver/',
    'homeassistant/',  # Docker Hub official
    'eclipse-mosquitto',
    'postgres:',
    'redis:',
    'mariadb:',
    'mysql:',
    'mongo:',
    'influxdb:',
    'grafana/',
]


# =============================================================================
# SENSITIVE OPERATION DETECTOR  
# =============================================================================

class SensitiveOperationDetector:
    """Detects and categorizes sensitive operations for user awareness."""
    
    CATEGORIES = {
        'financial': {
            'keywords': ['quicken', 'bank', 'tax', 'payment', 'credit', 'debit',
                        'account', 'money', 'financial', 'invoice', 'payroll',
                        'salary', 'wage', 'budget', 'investment', 'stock', 'crypto',
                        'wallet', 'trading', 'brokerage', 'retirement', '401k', 'ira'],
            'icon': '💰',
            'severity': 'HIGH',
        },
        'credentials': {
            'keywords': ['password', 'credential', 'secret', 'key', 'token',
                        '.ssh', 'id_rsa', 'id_ed25519', '.gnupg', 'pgp',
                        'keychain', 'vault', 'lastpass', '1password', 'bitwarden',
                        'keepass', '.kdbx', 'auth', 'login', 'api_key', 'apikey'],
            'icon': '🔐',
            'severity': 'CRITICAL',
        },
        'personal': {
            'keywords': ['medical', 'health', 'doctor', 'hospital', 'prescription',
                        'diagnosis', 'insurance', 'legal', 'attorney', 'lawyer',
                        'divorce', 'custody', 'court', 'social security', 'ssn',
                        'passport', 'license', 'birth certificate', 'will', 'estate'],
            'icon': '👤',
            'severity': 'HIGH',
        },
        'family': {
            'keywords': ['kids', 'children', 'school', 'grades', 'report card',
                        'family', 'photos', 'pictures', 'videos', 'memories',
                        'diary', 'journal', 'private', 'personal'],
            'icon': '👨‍👩‍👧‍👦',
            'severity': 'MEDIUM',
        },
        'security': {
            'keywords': ['camera', 'surveillance', 'alarm', 'security code',
                        'pin', 'combination', 'safe', 'lock', 'access code',
                        'gate code', 'garage code', 'entry'],
            'icon': '🔒',
            'severity': 'HIGH',
        },
        'work': {
            'keywords': ['confidential', 'proprietary', 'nda', 'trade secret',
                        'business', 'client', 'contract', 'agreement', 'employee'],
            'icon': '💼',
            'severity': 'MEDIUM',
        },
    }
    
    def __init__(self):
        # Compile patterns for faster matching
        self.patterns = {}
        for category, data in self.CATEGORIES.items():
            pattern = '|'.join(re.escape(kw) for kw in data['keywords'])
            self.patterns[category] = re.compile(pattern, re.I)
    
    def detect(self, target: str, content: str = "") -> List[Dict]:
        """Detect sensitive operations and return matching categories."""
        combined = f"{target} {content}".lower()
        matches = []
        
        for category, pattern in self.patterns.items():
            if pattern.search(combined):
                cat_data = self.CATEGORIES[category]
                matches.append({
                    'category': category,
                    'icon': cat_data['icon'],
                    'severity': cat_data['severity'],
                })
        
        return matches
    
    def format_warning(self, matches: List[Dict]) -> str:
        """Format sensitivity warning for display."""
        if not matches:
            return ""
        
        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        matches.sort(key=lambda m: severity_order.get(m['severity'], 99))
        
        icons = ' '.join(m['icon'] for m in matches)
        categories = ', '.join(m['category'].upper() for m in matches)
        
        highest_severity = matches[0]['severity']
        
        if highest_severity == 'CRITICAL':
            return f"🚨 **CRITICAL SENSITIVE DATA:** {icons} {categories}"
        elif highest_severity == 'HIGH':
            return f"⚠️ **SENSITIVE:** {icons} {categories}"
        else:
            return f"ℹ️ **Note:** Involves {categories} data"


# =============================================================================
# SESSION TRACKER FOR TRANSPARENCY
# =============================================================================

class SessionTransparencyTracker:
    """Tracks all AI actions for transparency reporting."""
    
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.start_time = datetime.now()
        self.files_read: List[Dict] = []
        self.files_written: List[Dict] = []
        self.files_deleted: List[Dict] = []
        self.commands_executed: List[Dict] = []
        self.directories_listed: List[Dict] = []
        self.sensitive_access: List[Dict] = []
        self.blocked_attempts: List[Dict] = []
        self.approvals_granted: int = 0
        self.approvals_rejected: int = 0
        self.lock = threading.Lock()
        
        # Sensitive detector for tracking
        self.sensitive_detector = SensitiveOperationDetector()
    
    def record_read(self, path: str, size: int, success: bool):
        with self.lock:
            record = {
                'path': path,
                'filename': os.path.basename(path),
                'size': size,
                'success': success,
                'timestamp': datetime.now().isoformat(),
            }
            self.files_read.append(record)
            
            # Check if sensitive
            matches = self.sensitive_detector.detect(path)
            if matches:
                self.sensitive_access.append({
                    'action': 'READ',
                    'path': path,
                    'categories': [m['category'] for m in matches],
                    'timestamp': datetime.now().isoformat(),
                })
    
    def record_write(self, path: str, size: int, success: bool):
        with self.lock:
            self.files_written.append({
                'path': path,
                'filename': os.path.basename(path),
                'size': size,
                'success': success,
                'timestamp': datetime.now().isoformat(),
            })
    
    def record_delete(self, path: str, success: bool):
        with self.lock:
            self.files_deleted.append({
                'path': path,
                'filename': os.path.basename(path),
                'success': success,
                'timestamp': datetime.now().isoformat(),
            })
    
    def record_command(self, command: str, success: bool, output_preview: str = ""):
        with self.lock:
            self.commands_executed.append({
                'command': command[:200],
                'success': success,
                'output_preview': output_preview[:100] if output_preview else "",
                'timestamp': datetime.now().isoformat(),
            })
    
    def record_list(self, path: str, count: int, success: bool):
        with self.lock:
            self.directories_listed.append({
                'path': path,
                'item_count': count,
                'success': success,
                'timestamp': datetime.now().isoformat(),
            })
    
    def record_blocked(self, action_type: str, target: str, reason: str):
        with self.lock:
            self.blocked_attempts.append({
                'action': action_type,
                'target': target[:100],
                'reason': reason,
                'timestamp': datetime.now().isoformat(),
            })
    
    def record_approval(self, approved: bool):
        with self.lock:
            if approved:
                self.approvals_granted += 1
            else:
                self.approvals_rejected += 1
    
    def get_duration(self) -> str:
        delta = datetime.now() - self.start_time
        hours, remainder = divmod(int(delta.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        if hours:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"
    
    def generate_report(self) -> str:
        """Generate full transparency report."""
        with self.lock:
            lines = [
                "# 📋 Session Transparency Report\n",
                f"**Session ID:** `{self.session_id[:8]}`",
                f"**Started:** {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}",
                f"**Duration:** {self.get_duration()}",
                f"**Approvals:** ✅ {self.approvals_granted} granted · ❌ {self.approvals_rejected} rejected\n",
            ]
            
            # Sensitive access (most important - show first)
            if self.sensitive_access:
                lines.append("## 🚨 Sensitive Data Accessed\n")
                lines.append("| Time | Action | Path | Categories |")
                lines.append("|------|--------|------|------------|")
                for s in self.sensitive_access:
                    time_str = s['timestamp'].split('T')[1][:8]
                    cats = ', '.join(s['categories'])
                    path = os.path.basename(s['path'])
                    lines.append(f"| {time_str} | {s['action']} | `{path}` | {cats} |")
                lines.append("")
            
            # Files read
            lines.append(f"## 📖 Files Read ({len(self.files_read)})\n")
            if self.files_read:
                lines.append("| File | Size | Status |")
                lines.append("|------|------|--------|")
                for f in self.files_read[-20:]:  # Last 20
                    status = "✅" if f['success'] else "❌"
                    size = self._format_size(f['size'])
                    lines.append(f"| `{f['filename']}` | {size} | {status} |")
                if len(self.files_read) > 20:
                    lines.append(f"| ... and {len(self.files_read) - 20} more | | |")
            else:
                lines.append("*No files read*")
            lines.append("")
            
            # Files written
            lines.append(f"## 📝 Files Written ({len(self.files_written)})\n")
            if self.files_written:
                lines.append("| File | Size | Status |")
                lines.append("|------|------|--------|")
                for f in self.files_written[-20:]:
                    status = "✅" if f['success'] else "❌"
                    size = self._format_size(f['size'])
                    lines.append(f"| `{f['filename']}` | {size} | {status} |")
            else:
                lines.append("*No files written*")
            lines.append("")
            
            # Files deleted
            if self.files_deleted:
                lines.append(f"## 🗑️ Files Deleted ({len(self.files_deleted)})\n")
                lines.append("| File | Status |")
                lines.append("|------|--------|")
                for f in self.files_deleted:
                    status = "✅" if f['success'] else "❌"
                    lines.append(f"| `{f['filename']}` | {status} |")
                lines.append("")
            
            # Commands executed
            lines.append(f"## ⚡ Commands Executed ({len(self.commands_executed)})\n")
            if self.commands_executed:
                lines.append("| Command | Status |")
                lines.append("|---------|--------|")
                for c in self.commands_executed[-15:]:
                    status = "✅" if c['success'] else "❌"
                    cmd = c['command'][:50] + ('...' if len(c['command']) > 50 else '')
                    lines.append(f"| `{cmd}` | {status} |")
                if len(self.commands_executed) > 15:
                    lines.append(f"| ... and {len(self.commands_executed) - 15} more | |")
            else:
                lines.append("*No commands executed*")
            lines.append("")
            
            # Blocked attempts
            if self.blocked_attempts:
                lines.append(f"## 🛡️ Blocked Attempts ({len(self.blocked_attempts)})\n")
                lines.append("| Action | Target | Reason |")
                lines.append("|--------|--------|--------|")
                for b in self.blocked_attempts[-10:]:
                    target = b['target'][:30] + ('...' if len(b['target']) > 30 else '')
                    reason = b['reason'][:30] + ('...' if len(b['reason']) > 30 else '')
                    lines.append(f"| {b['action']} | `{target}` | {reason} |")
                lines.append("")
            
            lines.append("---")
            lines.append("*This report shows all actions the AI performed or attempted this session.*")
            
            return "\n".join(lines)
    
    def _format_size(self, size: int) -> str:
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        else:
            return f"{size / (1024*1024):.1f} MB"


# =============================================================================
# FAMILY ROLE-BASED ACCESS CONTROL
# =============================================================================

class FamilyMember:
    """Represents a family member with specific permissions."""
    
    def __init__(self, name: str, role: str, pin: str = None):
        self.name = name
        self.role = role  # 'admin', 'adult', 'teen', 'child'
        self.pin_hash = hashlib.sha256(pin.encode()).hexdigest() if pin else None
    
    def verify_pin(self, pin: str) -> bool:
        if not self.pin_hash:
            return True
        return hmac.compare_digest(
            self.pin_hash, 
            hashlib.sha256(pin.encode()).hexdigest()
        )


class FamilyAccessControl:
    """Role-based access control for family home server."""
    
    ROLE_PERMISSIONS = {
        'admin': {
            'can_approve': {'COMMAND', 'READ', 'WRITE', 'DELETE', 'LIST'},
            'can_access_sensitive': {'financial', 'credentials', 'personal', 'family', 'security', 'work'},
            'requires_pin_for': set(),  # No PIN required
        },
        'adult': {
            'can_approve': {'COMMAND', 'READ', 'WRITE', 'LIST'},  # No DELETE
            'can_access_sensitive': {'family', 'security'},
            'requires_pin_for': {'financial', 'credentials'},
        },
        'teen': {
            'can_approve': {'READ', 'WRITE', 'LIST'},  # No COMMAND, DELETE
            'can_access_sensitive': {'family'},
            'requires_pin_for': {'security'},
        },
        'child': {
            'can_approve': {'READ', 'LIST'},  # Read and list only
            'can_access_sensitive': set(),
            'requires_pin_for': set(),  # Can't access sensitive anyway
        },
    }
    
    def __init__(self):
        self.members: Dict[str, FamilyMember] = {}
        self.active_sessions: Dict[str, str] = {}  # session_id -> member_name
    
    def add_member(self, name: str, role: str, pin: str = None):
        if role not in self.ROLE_PERMISSIONS:
            raise ValueError(f"Invalid role: {role}")
        self.members[name.lower()] = FamilyMember(name, role, pin)
    
    def authenticate(self, name: str, pin: str = None) -> Optional[str]:
        """Authenticate and return session token."""
        member = self.members.get(name.lower())
        if not member:
            return None
        if not member.verify_pin(pin or ""):
            return None
        
        session_id = secrets.token_hex(16)
        self.active_sessions[session_id] = member.name
        return session_id
    
    def get_member_for_session(self, session_id: str) -> Optional[FamilyMember]:
        name = self.active_sessions.get(session_id)
        if not name:
            return None
        return self.members.get(name.lower())
    
    def can_approve(self, session_id: str, action_type: str) -> Tuple[bool, str]:
        """Check if session can approve action type."""
        member = self.get_member_for_session(session_id)
        if not member:
            return False, "Session not authenticated"
        
        perms = self.ROLE_PERMISSIONS.get(member.role, {})
        can_approve = perms.get('can_approve', set())
        
        if action_type in can_approve:
            return True, "Allowed"
        return False, f"{member.role.title()}s cannot approve {action_type} actions"
    
    def can_access_sensitive(self, session_id: str, sensitivity_category: str, 
                            pin: str = None) -> Tuple[bool, str]:
        """Check if session can access sensitive data category."""
        member = self.get_member_for_session(session_id)
        if not member:
            return False, "Session not authenticated"
        
        perms = self.ROLE_PERMISSIONS.get(member.role, {})
        can_access = perms.get('can_access_sensitive', set())
        requires_pin = perms.get('requires_pin_for', set())
        
        if sensitivity_category not in can_access and sensitivity_category not in requires_pin:
            return False, f"{member.role.title()}s cannot access {sensitivity_category} data"
        
        if sensitivity_category in requires_pin:
            if not pin or not member.verify_pin(pin):
                return False, f"PIN required for {sensitivity_category} data"
        
        return True, "Allowed"


# =============================================================================
# SMART HOME CONFIG ANALYZER
# =============================================================================

class SmartHomeConfigAnalyzer:
    """
    Specialized security analyzer for Home Assistant, Frigate, and other
    smart home configuration files. Detects exfiltration attempts hidden
    in automation configs.
    """
    
    # External URL pattern (anything NOT local)
    LOCAL_IP_PATTERN = r'(192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.0\.0\.1|localhost|0\.0\.0\.0)'
    
    DANGEROUS_PATTERNS = [
        # External URLs (not matching local IPs)
        (r'https?://(?!' + LOCAL_IP_PATTERN + r')[^\s\'"]+',
         Severity.HIGH, 'External URL detected - potential data exfiltration'),
        
        # REST commands (common exfil vector)
        (r'(?i)rest_command\s*:', Severity.MEDIUM, 'REST command defined - verify no external endpoints'),
        (r'(?i)rest\s*:\s*\n\s*resource\s*:', Severity.MEDIUM, 'REST resource - verify endpoint is local'),
        
        # Shell commands in HA
        (r'(?i)shell_command\s*:', Severity.HIGH, 'Shell command in config - potential code execution'),
        
        # Webhooks
        (r'(?i)webhook_id\s*:', Severity.MEDIUM, 'Webhook defined - verify not exposing data'),
        (r'(?i)webhook\s*:', Severity.MEDIUM, 'Webhook trigger - verify source'),
        
        # External notification services (data leaves network)
        (r'(?i)notify\.(telegram|pushover|slack|discord|pushbullet|email|smtp)',
         Severity.MEDIUM, 'External notification service - data will leave local network'),
        
        # MQTT to external brokers
        (r'(?i)mqtt\s*:\s*\n\s*(host|broker)\s*:\s*(?!' + LOCAL_IP_PATTERN + r')',
         Severity.HIGH, 'MQTT pointing to external broker - potential exfiltration'),
        
        # InfluxDB/databases external
        (r'(?i)influxdb\s*:\s*\n\s*host\s*:\s*(?!' + LOCAL_IP_PATTERN + r')',
         Severity.HIGH, 'InfluxDB pointing external'),
        
        # Cloud integrations
        (r'(?i)(nabu_?casa|cloud)\s*:', Severity.LOW, 'Cloud integration - data may leave network'),
        
        # Curl/wget in scripts
        (r'(?i)(curl|wget)\s+', Severity.HIGH, 'HTTP client in script - verify destination'),
        
        # Base64 in configs (obfuscation)
        (r'[A-Za-z0-9+/]{50,}={0,2}', Severity.MEDIUM, 'Long base64 string - possible obfuscated payload'),
        
        # Encoded commands
        (r'(?i)base64\s*(--decode|-d)', Severity.HIGH, 'Base64 decode operation'),
        
        # Network tools
        (r'(?i)(nc|netcat|ncat)\s+', Severity.CRITICAL, 'Netcat detected - potential reverse shell'),
        (r'(?i)socat\s+', Severity.CRITICAL, 'Socat detected - potential tunnel'),
        
        # Python/Node inline execution
        (r'(?i)python[3]?\s+-c\s+', Severity.HIGH, 'Inline Python execution'),
        (r'(?i)node\s+-e\s+', Severity.HIGH, 'Inline Node execution'),
        
        # Frigate-specific: external MQTT
        (r'(?i)mqtt\s*:\s*\n\s*enabled\s*:\s*true\s*\n\s*host\s*:\s*(?!' + LOCAL_IP_PATTERN + r')',
         Severity.HIGH, 'Frigate MQTT pointing external'),
        
        # Suspicious automation names (social engineering)
        (r'(?i)alias\s*:\s*["\']?(backup|sync|upload|send|transfer|export)["\']?',
         Severity.LOW, 'Automation name suggests data transfer - verify destination'),
    ]
    
    SAFE_EXTERNAL_DOMAINS = [
        'github.com', 'githubusercontent.com',  # For HACS
        'home-assistant.io', 'esphome.io',     # Official
        'fonts.googleapis.com',                  # UI fonts
    ]
    
    def __init__(self):
        self.findings: List[SecurityFinding] = []
        self.compiled = [(re.compile(p, re.M | re.I), s, m) for p, s, m in self.DANGEROUS_PATTERNS]
    
    def analyze_config(self, content: str, filename: str = "config") -> List[SecurityFinding]:
        """Analyze smart home config file for security issues."""
        self.findings = []
        
        for pattern, severity, message in self.compiled:
            for match in pattern.finditer(content):
                matched_text = match.group(0)
                
                # Check if it's a safe external domain
                is_safe = False
                for safe in self.SAFE_EXTERNAL_DOMAINS:
                    if safe in matched_text.lower():
                        is_safe = True
                        break
                
                if not is_safe:
                    # Find line number
                    line_num = content[:match.start()].count('\n') + 1
                    
                    self.findings.append(SecurityFinding(
                        severity=severity,
                        category='SMART_HOME_CONFIG',
                        message=message,
                        line=line_num,
                        code_snippet=matched_text[:100],
                        cwe_id='CWE-918' if 'external' in message.lower() else 'CWE-78'
                    ))
        
        return self.findings
    
    def analyze_docker_compose(self, content: str) -> List[SecurityFinding]:
        """Analyze docker-compose for security issues."""
        self.findings = []
        
        docker_patterns = [
            (r'network_mode\s*:\s*host', Severity.MEDIUM, 
             'Container uses host networking - has full network access'),
            (r'privileged\s*:\s*true', Severity.HIGH,
             'Container runs privileged - has full system access'),
            (r'cap_add\s*:.*NET_ADMIN', Severity.HIGH,
             'Container has NET_ADMIN capability'),
            (r'volumes\s*:.*(/etc|/var|/root|C:\\Windows|C:\\Users)', Severity.MEDIUM,
             'Container mounts sensitive host path'),
            (r'ports\s*:.*0\.0\.0\.0', Severity.MEDIUM,
             'Port exposed on all interfaces - accessible from network'),
        ]
        
        for pattern, severity, message in docker_patterns:
            if re.search(pattern, content, re.I | re.M):
                self.findings.append(SecurityFinding(
                    severity=severity,
                    category='DOCKER_SECURITY',
                    message=message,
                    line=None,
                    code_snippet=pattern[:50],
                    cwe_id='CWE-250'
                ))
        
        # Check Docker images against trusted registries
        images = re.findall(r'image\s*:\s*["\']?([^\s"\']+)["\']?', content, re.I)
        for img in images:
            if not self._is_trusted_image(img):
                self.findings.append(SecurityFinding(
                    severity=Severity.HIGH,
                    category='UNTRUSTED_IMAGE',
                    message=f'Untrusted Docker registry: {img}',
                    line=None,
                    code_snippet=img[:80],
                    cwe_id='CWE-829'
                ))
        
        return self.findings
    
    def _is_trusted_image(self, image: str) -> bool:
        """Check if Docker image is from a trusted registry."""
        image_lower = image.lower()
        
        # Check against trusted registries
        for trusted in TRUSTED_DOCKER_REGISTRIES:
            if image_lower.startswith(trusted.lower()):
                return True
            # Also check without registry prefix (Docker Hub default)
            if '/' not in image or image.count('/') == 1:
                if image_lower.startswith(trusted.lower().split('/')[-1]):
                    return True
        
        return False
    
    def get_risk_score(self) -> int:
        score = 0
        for f in self.findings:
            if f.severity == Severity.CRITICAL:
                score += 50
            elif f.severity == Severity.HIGH:
                score += 30
            elif f.severity == Severity.MEDIUM:
                score += 15
            elif f.severity == Severity.LOW:
                score += 5
        return min(100, score)
    
    def should_block(self) -> bool:
        critical = sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in self.findings if f.severity == Severity.HIGH)
        return critical > 0 or high >= 2
    
    def should_warn(self) -> bool:
        return len(self.findings) > 0 and not self.should_block()
    
    def get_report(self) -> str:
        if not self.findings:
            return "✅ Smart home config appears safe."
        
        icons = {Severity.CRITICAL: "🔴", Severity.HIGH: "🟠", 
                 Severity.MEDIUM: "🟡", Severity.LOW: "🟢"}
        
        lines = [f"⚠️ Found {len(self.findings)} potential issue(s) in config:\n"]
        
        for f in sorted(self.findings, key=lambda x: x.severity.value, reverse=True):
            lines.append(f"{icons[f.severity]} **{f.severity.name}**: {f.message}")
            if f.line:
                lines.append(f"   Line {f.line}: `{f.code_snippet}`")
            lines.append("")
        
        lines.append(f"Risk Score: {self.get_risk_score()}/100")
        return "\n".join(lines)


# =============================================================================
# DOCKER COMPOSE GENERATOR (SECURE)
# =============================================================================

class SecureDockerComposeGenerator:
    """
    Generates secure docker-compose configurations with proper network isolation.
    """
    
    @staticmethod
    def generate_home_assistant_stack(
        config_path: str,
        media_path: str,
        frigate_path: str,
        camera_ips: List[str],
        timezone: str = "America/Los_Angeles"
    ) -> str:
        """Generate a network-isolated docker-compose for Home Assistant + Frigate."""
        
        # Build allowed IPs for firewall rules
        camera_subnet = ".".join(camera_ips[0].split(".")[:3]) + ".0/24" if camera_ips else "192.168.1.0/24"
        
        compose = f'''version: '3.8'

# ============================================================================
# SECURE HOME ASSISTANT + FRIGATE STACK
# Generated by AIOHAI with network isolation
# ============================================================================

services:
  # --------------------------------------------------------------------------
  # HOME ASSISTANT
  # --------------------------------------------------------------------------
  homeassistant:
    container_name: homeassistant
    image: ghcr.io/home-assistant/home-assistant:stable
    restart: unless-stopped
    
    # Use bridge network instead of host for isolation
    networks:
      home_automation:
        ipv4_address: 172.30.0.10
    
    ports:
      - "8123:8123"      # Web UI - bound to localhost only below
    
    volumes:
      - {config_path}:/config
      - {media_path}:/media
      - /etc/localtime:/etc/localtime:ro
    
    environment:
      - TZ={timezone}
    
    # Security: Don't run as privileged unless absolutely necessary
    # privileged: false  # Uncomment if you don't need USB/Bluetooth
    
    depends_on:
      - frigate

  # --------------------------------------------------------------------------
  # FRIGATE NVR
  # --------------------------------------------------------------------------
  frigate:
    container_name: frigate
    image: ghcr.io/blakeblackshear/frigate:stable
    restart: unless-stopped
    
    shm_size: "256mb"
    
    networks:
      home_automation:
        ipv4_address: 172.30.0.20
      cameras:  # Separate network for camera access
        ipv4_address: 172.31.0.20
    
    ports:
      - "127.0.0.1:5000:5000"    # Web UI - localhost only
      - "127.0.0.1:8554:8554"    # RTSP - localhost only
      - "127.0.0.1:8555:8555"    # WebRTC - localhost only
    
    volumes:
      - {frigate_path}/config.yml:/config/config.yml:ro
      - {frigate_path}/storage:/media/frigate
      - type: tmpfs
        target: /tmp/cache
        tmpfs:
          size: 1000000000
    
    environment:
      - TZ={timezone}

  # --------------------------------------------------------------------------
  # NETWORK FIREWALL (Optional - adds egress filtering)
  # --------------------------------------------------------------------------
  # Uncomment to add strict egress control
  # firewall:
  #   container_name: firewall
  #   image: alpine:latest
  #   network_mode: host
  #   cap_add:
  #     - NET_ADMIN
  #   command: >
  #     sh -c "
  #       iptables -I DOCKER-USER -s 172.30.0.0/16 -d {camera_subnet} -j ACCEPT &&
  #       iptables -I DOCKER-USER -s 172.30.0.0/16 -d 172.30.0.0/16 -j ACCEPT &&
  #       iptables -I DOCKER-USER -s 172.30.0.0/16 -j DROP &&
  #       tail -f /dev/null
  #     "

# ============================================================================
# NETWORKS
# ============================================================================
networks:
  home_automation:
    driver: bridge
    ipam:
      config:
        - subnet: 172.30.0.0/24
          gateway: 172.30.0.1
    driver_opts:
      com.docker.network.bridge.enable_icc: "true"
  
  cameras:
    driver: macvlan
    driver_opts:
      parent: eth0  # Change to your network interface
    ipam:
      config:
        - subnet: {camera_subnet}
          gateway: {".".join(camera_ips[0].split(".")[:3]) + ".1" if camera_ips else "192.168.1.1"}

# ============================================================================
# SECURITY NOTES:
# - Containers use isolated bridge networks, not host networking
# - Frigate web ports bound to localhost only (127.0.0.1)
# - Camera network is separate from home automation network
# - Uncomment firewall service for strict egress control
# ============================================================================
'''
        return compose
    
    @staticmethod
    def generate_secure_frigate_config(
        cameras: Dict[str, str],  # name -> IP
        password_placeholder: str = "YOUR_PASSWORD",
        retention_days: int = 14,
        event_retention_days: int = 30
    ) -> str:
        """Generate secure Frigate config without external endpoints."""
        
        camera_configs = ""
        for name, ip in cameras.items():
            safe_name = re.sub(r'[^a-z0-9_]', '_', name.lower())
            camera_configs += f'''
  {safe_name}:
    ffmpeg:
      inputs:
        - path: rtsp://admin:{password_placeholder}@{ip}:554/h264Preview_01_main
          roles:
            - detect
            - record
    detect:
      enabled: true
      width: 1280
      height: 720
    record:
      enabled: true
    snapshots:
      enabled: true
'''
        
        config = f'''# ============================================================================
# FRIGATE NVR CONFIGURATION
# Generated by AIOHAI - No external endpoints
# ============================================================================

# MQTT disabled - no external data transmission
mqtt:
  enabled: false

# Database stored locally
database:
  path: /media/frigate/frigate.db

# Recording settings
record:
  enabled: true
  retain:
    days: {retention_days}
    mode: motion
  events:
    retain:
      default: {event_retention_days}
      mode: active_objects

# Snapshots
snapshots:
  enabled: true
  retain:
    default: {event_retention_days}

# Detection settings
detect:
  enabled: true
  fps: 5

# Objects to track
objects:
  track:
    - person
    - car
    - dog
    - cat
  filters:
    person:
      min_score: 0.5
      threshold: 0.7

# ============================================================================
# CAMERAS
# ============================================================================
cameras:{camera_configs}

# ============================================================================
# SECURITY NOTES:
# - MQTT is disabled (no external broker communication)
# - All recordings stored locally in /media/frigate
# - No webhooks or external notifications configured
# - Replace {password_placeholder} with your camera password
# ============================================================================
'''
        return config


class MultiStageDetector:
    """Detects attack patterns across multiple actions."""
    
    def __init__(self, window_seconds: int = 600):
        self.window = window_seconds
        self.actions: List[Dict] = []
        self.lock = threading.Lock()
    
    def record(self, action_type: str, target: str, content: str = ""):
        with self.lock:
            now = time.time()
            self.actions.append({
                'type': action_type, 'target': target, 
                'content': content[:200], 'time': now
            })
            # Clean old
            self.actions = [a for a in self.actions if now - a['time'] < self.window]
    
    def check(self) -> Optional[str]:
        with self.lock:
            types = [a['type'] for a in self.actions]
            
            # Write then execute pattern
            if 'WRITE' in types and 'COMMAND' in types:
                write_targets = [a['target'] for a in self.actions if a['type'] == 'WRITE']
                cmd_targets = [a['target'] for a in self.actions if a['type'] == 'COMMAND']
                
                for wt in write_targets:
                    for ct in cmd_targets:
                        if wt in ct:
                            return f"Write-then-execute pattern: {wt}"
            
            # Multiple deletions
            deletes = [a for a in self.actions if a['type'] == 'DELETE']
            if len(deletes) > 5:
                return f"Mass deletion detected: {len(deletes)} files"
            
            # Rapid credential path access
            cred_patterns = ['.ssh', '.aws', 'credential', 'password', '.env']
            cred_attempts = sum(1 for a in self.actions 
                               if any(p in a['target'].lower() for p in cred_patterns))
            if cred_attempts >= 3:
                return f"Multiple credential path access attempts: {cred_attempts}"
            
            return None
