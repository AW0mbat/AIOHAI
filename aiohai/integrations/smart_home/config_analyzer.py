#!/usr/bin/env python3
"""
AIOHAI Integrations — Smart Home Config Analyzer
==================================================
Specialized security analyzer for Home Assistant, Frigate, and other
smart home configuration files. Detects exfiltration attempts hidden
in automation configs.

Previously defined in security/security_components.py.
Extracted as Phase 4a of the monolith → layered architecture migration.

Import from: aiohai.integrations.smart_home.config_analyzer
"""

import re
from typing import List

from aiohai.core.types import Severity, SecurityFinding
from aiohai.core.patterns import TRUSTED_DOCKER_REGISTRIES


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


__all__ = ['SmartHomeConfigAnalyzer']
