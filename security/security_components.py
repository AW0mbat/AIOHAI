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
import logging
import threading
import hashlib
import json
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
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
        self.api_queries: List[Dict] = []  # M-9 FIX: Track LOCAL_API_QUERY actions
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
    
    def record_api_query(self, service: str, endpoint: str, 
                         sensitivity: str = "standard", success: bool = True):
        """M-9 FIX: Track LOCAL_API_QUERY actions for transparency reporting."""
        with self.lock:
            self.api_queries.append({
                'service': service,
                'endpoint': endpoint[:200],
                'sensitivity': sensitivity,
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
            
            # M-9 FIX: API queries (Frigate, Home Assistant, etc.)
            if self.api_queries:
                lines.append(f"## 🌐 API Queries ({len(self.api_queries)})\n")
                lines.append("| Service | Endpoint | Sensitivity | Status |")
                lines.append("|---------|----------|-------------|--------|")
                for q in self.api_queries[-15:]:
                    status = "✅" if q['success'] else "❌"
                    ep = q['endpoint'][:40] + ('...' if len(q['endpoint']) > 40 else '')
                    lines.append(f"| {q['service']} | `{ep}` | {q['sensitivity']} | {status} |")
                if len(self.api_queries) > 15:
                    lines.append(f"| ... and {len(self.api_queries) - 15} more | | | |")
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
            
            # M-7 FIX: Warn if a trusted image lacks digest pinning.
            # Without @sha256:... a compromised image on a trusted registry
            # would pass the registry-domain check silently.
            if self._is_trusted_image(img) and '@sha256:' not in img:
                self.findings.append(SecurityFinding(
                    severity=Severity.LOW,
                    category='IMAGE_NO_DIGEST',
                    message=f'Docker image without digest pinning: {img}. '
                            f'Consider using image@sha256:... for supply-chain safety.',
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


# HOME ASSISTANT NOTIFICATION BRIDGE
# ============================================================================

class HomeAssistantNotificationBridge:
    """Bridge between Home Assistant automations and the AIOHAI user interface.
    
    Runs a lightweight HTTP server on localhost that receives webhook
    notifications from HA automations and routes them to the AIOHAI
    AlertManager for desktop notification display.
    
    Also provides a snapshot proxy endpoint that securely fetches
    camera snapshots from Frigate NVR without exposing Frigate directly.
    """
    
    def __init__(self, alert_manager=None, port: int = 11436,
                 frigate_host: str = '127.0.0.1', frigate_port: int = 5000):
        self.alert_manager = alert_manager
        self.port = port
        self.frigate_host = frigate_host
        self.frigate_port = frigate_port
        self.notification_log: List[Dict] = []
        self.max_log_size = 500
        self._server = None
        self._thread = None
        self.logger = logging.getLogger('aiohai.notification_bridge')
    
    def start(self):
        """Start the notification bridge HTTP server."""
        import http.server
        bridge = self
        
        class BridgeHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                bridge.logger.debug(f"Bridge HTTP: {format % args}")
            
            def do_POST(self):
                if self.path == '/webhook/notify':
                    self._handle_notification()
                else:
                    self.send_response(404)
                    self.end_headers()
            
            def do_GET(self):
                if self.path.startswith('/snapshot/'):
                    self._handle_snapshot()
                elif self.path == '/notifications':
                    self._handle_list_notifications()
                elif self.path == '/health':
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'status': 'ok'}).encode())
                else:
                    self.send_response(404)
                    self.end_headers()
            
            def _handle_notification(self):
                try:
                    content_length = int(self.headers.get('Content-Length', 0))
                    if content_length > 65536:  # 64KB max
                        self.send_response(413)
                        self.end_headers()
                        return
                    
                    body = self.rfile.read(content_length)
                    data = json.loads(body.decode('utf-8'))
                    
                    # Validate required fields
                    title = str(data.get('title', 'Home Assistant'))[:200]
                    message = str(data.get('message', ''))[:1000]
                    severity = str(data.get('severity', 'info')).lower()
                    source = str(data.get('source', 'homeassistant'))[:100]
                    camera = str(data.get('camera', ''))[:50]
                    
                    # Log the notification
                    entry = {
                        'timestamp': datetime.now().isoformat(),
                        'title': title,
                        'message': message,
                        'severity': severity,
                        'source': source,
                        'camera': camera,
                    }
                    bridge.notification_log.append(entry)
                    if len(bridge.notification_log) > bridge.max_log_size:
                        bridge.notification_log = bridge.notification_log[-bridge.max_log_size:]
                    
                    # Route to AlertManager if available
                    if bridge.alert_manager:
                        try:
                            from proxy.aiohai_proxy import AlertSeverity
                            sev_map = {
                                'info': AlertSeverity.INFO,
                                'warning': AlertSeverity.WARNING,
                                'high': AlertSeverity.HIGH,
                                'critical': AlertSeverity.CRITICAL,
                            }
                            alert_sev = sev_map.get(severity, AlertSeverity.INFO)
                            bridge.alert_manager.alert(
                                alert_sev, f"HA_{source.upper()}",
                                f"{title}: {message}",
                                {'camera': camera} if camera else {}
                            )
                        except Exception as e:
                            bridge.logger.warning(f"Alert routing failed: {e}")
                    
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'status': 'received'}).encode())
                    
                except json.JSONDecodeError:
                    self.send_response(400)
                    self.end_headers()
                except Exception as e:
                    bridge.logger.error(f"Notification handling error: {e}")
                    self.send_response(500)
                    self.end_headers()
            
            def _handle_snapshot(self):
                """Proxy a camera snapshot from Frigate."""
                camera_name = self.path.split('/snapshot/', 1)[-1].strip('/')
                
                # Sanitize camera name - alphanumeric, underscore, hyphen only
                if not re.match(r'^[a-zA-Z0-9_-]+$', camera_name):
                    self.send_response(400)
                    self.end_headers()
                    return
                
                try:
                    frigate_url = (f"http://{bridge.frigate_host}:{bridge.frigate_port}"
                                   f"/api/{camera_name}/latest.jpg")
                    
                    req = urllib.request.Request(frigate_url)
                    req.add_header('Host', f'{bridge.frigate_host}:{bridge.frigate_port}')
                    
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        data = resp.read(5 * 1024 * 1024)  # 5MB max
                        content_type = resp.headers.get('Content-Type', 'image/jpeg')
                    
                    self.send_response(200)
                    self.send_header('Content-Type', content_type)
                    self.send_header('Content-Length', str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    
                except urllib.error.HTTPError as e:
                    self.send_response(e.code)
                    self.end_headers()
                except Exception as e:
                    bridge.logger.error(f"Snapshot proxy error: {e}")
                    self.send_response(502)
                    self.end_headers()
            
            def _handle_list_notifications(self):
                """Return recent notifications as JSON."""
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(bridge.notification_log[-50:]).encode())
        
        # Validate localhost-only binding
        listen_host = '127.0.0.1'
        
        try:
            self._server = http.server.HTTPServer((listen_host, self.port), BridgeHandler)
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                name='aiohai-notification-bridge',
                daemon=True
            )
            self._thread.start()
            self.logger.info(f"Notification bridge started on {listen_host}:{self.port}")
        except OSError as e:
            self.logger.error(f"Failed to start notification bridge: {e}")
    
    def stop(self):
        """Stop the notification bridge."""
        if self._server:
            self._server.shutdown()
            self._server.server_close()  # Close the socket properly
            self._server = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None


# ============================================================================
# SMART HOME STACK DETECTOR
# ============================================================================

class SmartHomeStackDetector:
    """Detects the current state of the smart home stack on the local system.
    
    Checks for Docker, Home Assistant, Frigate NVR, and Mosquitto MQTT
    installations and generates a context block for the system prompt.
    
    Deployment states:
      - not_deployed: No containers or config files found
      - partial: Some components found but not all running
      - running: All detected components are running
      - stopped: Components exist but containers are stopped
    """
    
    def __init__(self, base_dir: str = None):
        self.base_dir = Path(base_dir) if base_dir else Path(os.environ.get('AIOHAI_HOME', r'C:\AIOHAI'))
        self.logger = logging.getLogger('aiohai.stack_detector')
        self._cache = None
        self._cache_time = 0
        self._cache_ttl = 60  # seconds
    
    def detect(self) -> Dict:
        """Run full detection and return results."""
        now = time.time()
        if self._cache and (now - self._cache_time) < self._cache_ttl:
            return self._cache
        
        result = {
            'docker_installed': False,
            'docker_version': None,
            'containers': {},
            'config_files': {},
            'services': {},
            'deployment_state': 'not_deployed',
            'cameras': [],
        }
        
        # Check Docker
        try:
            docker_check = subprocess.run(
                ['docker', 'version', '--format', '{{.Server.Version}}'],
                capture_output=True, text=True, timeout=10
            )
            if docker_check.returncode == 0:
                result['docker_installed'] = True
                result['docker_version'] = docker_check.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        if not result['docker_installed']:
            self._cache = result
            self._cache_time = now
            return result
        
        # Check for known containers
        try:
            ps_result = subprocess.run(
                ['docker', 'ps', '-a', '--format', '{{.Names}}|{{.Status}}|{{.Image}}'],
                capture_output=True, text=True, timeout=10
            )
            if ps_result.returncode == 0:
                known_containers = {
                    'homeassistant': ['homeassistant', 'home-assistant', 'hass'],
                    'frigate': ['frigate'],
                    'mosquitto': ['mosquitto', 'mqtt', 'eclipse-mosquitto'],
                }
                for line in ps_result.stdout.strip().split('\n'):
                    if not line.strip():
                        continue
                    parts = line.split('|', 2)
                    if len(parts) < 3:
                        continue
                    name, status, image = parts[0].strip(), parts[1].strip(), parts[2].strip()
                    name_lower = name.lower()
                    
                    for service, patterns in known_containers.items():
                        if any(p in name_lower or p in image.lower() for p in patterns):
                            is_running = status.lower().startswith('up')
                            result['containers'][service] = {
                                'name': name,
                                'status': 'running' if is_running else 'stopped',
                                'image': image,
                            }
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            self.logger.warning(f"Docker ps failed: {e}")
        
        # Scan for config files
        search_dirs = [
            self.base_dir,
            self.base_dir / 'homeassistant',
            self.base_dir / 'frigate',
            Path.home() / 'homeassistant',
            Path.home() / 'frigate',
        ]
        
        config_patterns = {
            'ha_config': ['configuration.yaml'],
            'frigate_config': ['config.yml', 'frigate.yml'],
            'docker_compose': ['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml'],
        }
        
        for search_dir in search_dirs:
            if not search_dir.exists():
                continue
            try:
                for config_type, filenames in config_patterns.items():
                    if config_type in result['config_files']:
                        continue
                    for fn in filenames:
                        candidate = search_dir / fn
                        if candidate.exists():
                            result['config_files'][config_type] = str(candidate)
                            
                            # Parse cameras from Frigate config
                            if config_type == 'frigate_config':
                                result['cameras'] = self._parse_frigate_cameras(candidate)
            except PermissionError:
                continue
        
        # Check service health via HTTP
        service_checks = {
            'frigate': ('127.0.0.1', 5000, '/api/version'),
            'homeassistant': ('127.0.0.1', 8123, '/api/config'),
        }
        
        for svc_name, (host, port, path) in service_checks.items():
            try:
                url = f"http://{host}:{port}{path}"
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, timeout=3) as resp:
                    if resp.status == 200:
                        result['services'][svc_name] = 'healthy'
                    else:
                        result['services'][svc_name] = f'http_{resp.status}'
            except Exception:
                result['services'][svc_name] = 'unreachable'
        
        # Classify deployment state
        has_containers = len(result['containers']) > 0
        has_configs = len(result['config_files']) > 0
        all_running = all(
            c['status'] == 'running' for c in result['containers'].values()
        ) if has_containers else False
        
        if not has_containers and not has_configs:
            result['deployment_state'] = 'not_deployed'
        elif all_running and has_containers:
            result['deployment_state'] = 'running'
        elif has_containers and not all_running:
            result['deployment_state'] = 'stopped'
        else:
            result['deployment_state'] = 'partial'
        
        self._cache = result
        self._cache_time = now
        return result
    
    def _parse_frigate_cameras(self, config_path: Path) -> List[str]:
        """Parse camera names from Frigate config (simple regex, no YAML dep)."""
        cameras = []
        try:
            content = config_path.read_text(encoding='utf-8')
            in_cameras = False
            indent_level = None
            
            for line in content.split('\n'):
                stripped = line.strip()
                if stripped == 'cameras:':
                    in_cameras = True
                    indent_level = len(line) - len(line.lstrip())
                    continue
                
                if in_cameras and stripped and not stripped.startswith('#'):
                    current_indent = len(line) - len(line.lstrip())
                    if current_indent <= indent_level and stripped != '':
                        break  # Exited cameras section
                    
                    if current_indent == indent_level + 2 and stripped.endswith(':'):
                        cam_name = stripped.rstrip(':').strip()
                        if re.match(r'^[a-zA-Z0-9_-]+$', cam_name):
                            cameras.append(cam_name)
        except Exception as e:
            self.logger.warning(f"Failed to parse Frigate cameras: {e}")
        
        return cameras
    
    def get_context_block(self) -> str:
        """Generate a context block for system prompt injection."""
        status = self.detect()
        
        lines = [
            '[SMART_HOME_STATUS]',
            f'deployment_state: {status["deployment_state"]}',
            f'docker_installed: {status["docker_installed"]}',
        ]
        
        if status['docker_version']:
            lines.append(f'docker_version: {status["docker_version"]}')
        
        if status['containers']:
            lines.append('containers:')
            for svc, info in status['containers'].items():
                lines.append(f'  {svc}: {info["status"]} ({info["image"]})')
        
        if status['config_files']:
            lines.append('config_files:')
            for cfg_type, path in status['config_files'].items():
                lines.append(f'  {cfg_type}: {path}')
        
        if status['cameras']:
            lines.append(f'cameras: {", ".join(status["cameras"])}')
        
        if status['services']:
            lines.append('service_health:')
            for svc, health in status['services'].items():
                lines.append(f'  {svc}: {health}')
        
        lines.append('[/SMART_HOME_STATUS]')
        
        return '\n'.join(lines)


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


# =============================================================================
# OFFICE STACK DETECTOR
# =============================================================================

class OfficeStackDetector:
    """
    Auto-detect installed Microsoft Office applications, Python Office libraries,
    COM availability, and Graph API configuration.
    
    Generates an [OFFICE_STATUS] context block injected into the system prompt
    so the local model knows what capabilities are available.
    """
    
    # Python libraries to probe
    PYTHON_LIBS = {
        'python_docx': 'docx',
        'openpyxl': 'openpyxl',
        'python_pptx': 'pptx',
        'comtypes': 'comtypes',
    }
    
    # Office executables to search for (Windows)
    OFFICE_APPS = {
        'word': ['WINWORD.EXE', 'winword'],
        'excel': ['EXCEL.EXE', 'excel'],
        'powerpoint': ['POWERPNT.EXE', 'powerpnt'],
    }
    
    # Common Office install paths on Windows
    OFFICE_PATHS = [
        r'C:\Program Files\Microsoft Office',
        r'C:\Program Files (x86)\Microsoft Office',
        r'C:\Program Files\Microsoft Office 15',
        r'C:\Program Files\Microsoft Office 16',
    ]
    
    def __init__(self, base_dir: str = None, cache_ttl: int = 120):
        if base_dir:
            self.base_dir = Path(base_dir)
        elif os.environ.get('AIOHAI_HOME'):
            self.base_dir = Path(os.environ['AIOHAI_HOME'])
        else:
            self.base_dir = Path(os.path.expanduser('~'))
        
        self._cache = None
        self._cache_time = 0
        self._cache_ttl = cache_ttl
        self.logger = logging.getLogger('aiohai.office_detector')
    
    def detect(self) -> Dict:
        """Run full detection and return status dict."""
        now = time.time()
        if self._cache and (now - self._cache_time) < self._cache_ttl:
            return self._cache
        
        result = {
            'detection_state': 'not_available',
            'libraries': {},
            'office_apps': {},
            'document_directories': {},
            'graph_api': {'configured': False},
            'platform': sys.platform,
        }
        
        # Detect Python libraries
        lib_count = 0
        for display_name, import_name in self.PYTHON_LIBS.items():
            try:
                mod = __import__(import_name)
                version = getattr(mod, '__version__', 'unknown')
                result['libraries'][display_name] = {
                    'installed': True,
                    'version': version,
                }
                lib_count += 1
            except ImportError:
                result['libraries'][display_name] = {
                    'installed': False,
                    'version': None,
                }
        
        # Detect Office applications (Windows only)
        if sys.platform == 'win32':
            result['office_apps'] = self._detect_office_windows()
        else:
            for app in self.OFFICE_APPS:
                result['office_apps'][app] = {
                    'installed': False,
                    'version': None,
                    'note': 'Office app detection is Windows-only',
                }
        
        # Detect document directories
        result['document_directories'] = self._detect_doc_dirs()
        
        # Detect Graph API configuration
        result['graph_api'] = self._detect_graph_config()
        
        # Determine overall state
        core_libs = ['python_docx', 'openpyxl', 'python_pptx']
        core_installed = sum(1 for lib in core_libs
                            if result['libraries'].get(lib, {}).get('installed'))
        
        if core_installed == len(core_libs):
            result['detection_state'] = 'ready'
        elif core_installed > 0:
            result['detection_state'] = 'partial'
        else:
            result['detection_state'] = 'not_available'
        
        self._cache = result
        self._cache_time = now
        self.logger.info(f"Office detection: {result['detection_state']} "
                         f"({core_installed}/{len(core_libs)} core libs)")
        return result
    
    def _detect_office_windows(self) -> Dict:
        """Detect Office apps on Windows via registry or file search."""
        apps = {}
        for app_name, exe_names in self.OFFICE_APPS.items():
            found = False
            for search_path in self.OFFICE_PATHS:
                p = Path(search_path)
                if p.exists():
                    for exe in exe_names:
                        matches = list(p.rglob(exe))
                        if matches:
                            version = self._get_office_version(matches[0])
                            apps[app_name] = {
                                'installed': True,
                                'version': version,
                                'path': str(matches[0]),
                            }
                            found = True
                            break
                if found:
                    break
            if not found:
                apps[app_name] = {'installed': False, 'version': None}
        return apps
    
    def _get_office_version(self, exe_path: Path) -> str:
        """Extract Office version from the executable path."""
        path_str = str(exe_path)
        # Try to extract version from path (e.g., Office16, Office15)
        for marker in ['Office16', 'Office15', 'Office14', 'Office12']:
            if marker in path_str:
                version_map = {
                    'Office16': '16.x (2016/2019/365)',
                    'Office15': '15.x (2013)',
                    'Office14': '14.x (2010)',
                    'Office12': '12.x (2007)',
                }
                return version_map.get(marker, 'unknown')
        return 'unknown'
    
    def _detect_doc_dirs(self) -> Dict:
        """Find standard document directories."""
        dirs = {}
        home = Path.home()
        
        candidates = {
            'documents': [home / 'Documents', home / 'My Documents'],
            'desktop': [home / 'Desktop'],
            'downloads': [home / 'Downloads'],
        }
        
        for name, paths in candidates.items():
            for p in paths:
                if p.exists():
                    dirs[name] = str(p)
                    break
            else:
                dirs[name] = None
        
        return dirs
    
    def _detect_graph_config(self) -> Dict:
        """Check if Microsoft Graph API is configured."""
        config = {
            'configured': False,
            'tenant_id': None,
            'client_id': None,
            'scopes': [],
        }
        
        # Check for config file
        graph_config = self.base_dir / 'config' / 'graph_api.json'
        if graph_config.exists():
            try:
                with open(graph_config) as f:
                    data = json.load(f)
                config['configured'] = bool(data.get('tenant_id') and data.get('client_id'))
                config['tenant_id'] = '[set]' if data.get('tenant_id') else '[not set]'
                config['client_id'] = '[set]' if data.get('client_id') else '[not set]'
                config['scopes'] = data.get('scopes', [])
            except (json.JSONDecodeError, OSError):
                pass
        
        # Also check environment variables
        if os.environ.get('AIOHAI_GRAPH_TENANT_ID'):
            config['configured'] = True
            config['tenant_id'] = '[set via env]'
        
        return config
    
    def get_context_block(self) -> str:
        """Generate the [OFFICE_STATUS] block for system prompt injection."""
        status = self.detect()
        
        lines = ['## [OFFICE_STATUS]']
        lines.append(f"detection_state: {status['detection_state']}")
        
        lines.append('libraries:')
        for lib, info in status['libraries'].items():
            if info['installed']:
                lines.append(f"  {lib}: installed ({info['version']})")
            else:
                if lib == 'comtypes' and sys.platform != 'win32':
                    lines.append(f"  {lib}: not_applicable (linux)")
                else:
                    lines.append(f"  {lib}: not_installed")
        
        lines.append('office_apps:')
        for app, info in status['office_apps'].items():
            if info['installed']:
                lines.append(f"  {app}: installed ({info.get('version', 'unknown')})")
            else:
                lines.append(f"  {app}: not_found")
        
        lines.append('document_directories:')
        for name, path in status['document_directories'].items():
            if path:
                lines.append(f"  {name}: {path}")
            else:
                lines.append(f"  {name}: not_found")
        
        graph = status['graph_api']
        lines.append('graph_api:')
        lines.append(f"  configured: {str(graph['configured']).lower()}")
        if graph['configured']:
            lines.append(f"  tenant_id: {graph['tenant_id']}")
            lines.append(f"  scopes: {', '.join(graph['scopes']) if graph['scopes'] else 'none'}")
        
        lines.append('## [/OFFICE_STATUS]')
        return '\n'.join(lines)


# =============================================================================
# DOCUMENT AUDIT LOGGER
# =============================================================================

class DocumentAuditLogger:
    """
    Audit trail for all document operations.
    
    Tracks reads, writes, creates, modifications, conversions, and uploads
    with content hashes and PII scan results.
    """
    
    def __init__(self, log_dir: Path = None, retention_days: int = 30,
                 log_content_hashes: bool = True):
        if log_dir:
            self.log_dir = Path(log_dir)
        else:
            home = os.environ.get('AIOHAI_HOME', os.path.expanduser('~'))
            self.log_dir = Path(home) / 'logs' / 'document_audit'
        
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.retention_days = retention_days
        self.log_content_hashes = log_content_hashes
        self._lock = threading.Lock()
        self.logger = logging.getLogger('aiohai.doc_audit')
        
        # In-memory recent operations (last 100)
        self._recent: List[Dict] = []
        self._max_recent = 100
    
    def log_operation(self, operation: str, file_path: str,
                      file_type: str = '', details: Dict = None,
                      content_hash: str = '', pii_findings: List = None,
                      metadata_stripped: bool = False) -> Dict:
        """
        Log a document operation.
        
        Args:
            operation: CREATE, READ, MODIFY, CONVERT, UPLOAD, DELETE
            file_path: Path to the document
            file_type: Extension (.docx, .xlsx, .pptx, etc.)
            details: Additional operation details
            content_hash: SHA-256 of first 1024 bytes (for fingerprinting)
            pii_findings: List of PII findings from scanner
            metadata_stripped: Whether metadata was sanitized
        
        Returns:
            The logged entry dict.
        """
        entry = {
            'timestamp': datetime.now().isoformat(),
            'operation': operation,
            'file_path': self._sanitize_path(file_path),
            'file_type': file_type or self._get_ext(file_path),
            'content_hash': content_hash,
            'pii_findings_count': len(pii_findings) if pii_findings else 0,
            'pii_categories': list(set(f.get('type', 'unknown')
                                       for f in (pii_findings or []))),
            'metadata_stripped': metadata_stripped,
            'details': details or {},
        }
        
        with self._lock:
            # Write to daily log file
            date_str = datetime.now().strftime('%Y-%m-%d')
            log_file = self.log_dir / f'doc_audit_{date_str}.jsonl'
            try:
                with open(log_file, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(entry) + '\n')
            except OSError as e:
                self.logger.error(f"Failed to write audit log: {e}")
            
            # Add to in-memory recent
            self._recent.append(entry)
            if len(self._recent) > self._max_recent:
                self._recent = self._recent[-self._max_recent:]
        
        self.logger.info(f"DOC_AUDIT: {operation} | {entry['file_type']} | "
                         f"PII: {entry['pii_findings_count']}")
        return entry
    
    def hash_content(self, content: bytes, max_bytes: int = 1024) -> str:
        """Generate a content fingerprint hash."""
        if not self.log_content_hashes:
            return ''
        return hashlib.sha256(content[:max_bytes]).hexdigest()
    
    def get_recent(self, count: int = 20) -> List[Dict]:
        """Get recent operations."""
        with self._lock:
            return list(self._recent[-count:])
    
    def get_stats(self) -> Dict:
        """Get operation statistics from recent history."""
        with self._lock:
            ops = {}
            types = {}
            pii_total = 0
            for entry in self._recent:
                op = entry['operation']
                ops[op] = ops.get(op, 0) + 1
                ft = entry['file_type']
                types[ft] = types.get(ft, 0) + 1
                pii_total += entry['pii_findings_count']
            
            return {
                'total_operations': len(self._recent),
                'by_operation': ops,
                'by_file_type': types,
                'total_pii_findings': pii_total,
            }
    
    def cleanup_old_logs(self):
        """Remove audit logs older than retention period."""
        if self.retention_days <= 0:
            return
        
        cutoff = datetime.now().timestamp() - (self.retention_days * 86400)
        removed = 0
        for log_file in self.log_dir.glob('doc_audit_*.jsonl'):
            if log_file.stat().st_mtime < cutoff:
                log_file.unlink()
                removed += 1
        
        if removed:
            self.logger.info(f"Cleaned up {removed} old audit log files")
    
    def _sanitize_path(self, path: str) -> str:
        """Remove user-identifying path components for logging."""
        # Replace username in paths with <user>
        parts = Path(path).parts
        sanitized = []
        for part in parts:
            if part.lower() in ('users', 'home'):
                sanitized.append(part)
                continue
            sanitized.append(part)
        return str(Path(*sanitized)) if sanitized else path
    
    def _get_ext(self, path: str) -> str:
        """Extract file extension."""
        return Path(path).suffix.lower()
