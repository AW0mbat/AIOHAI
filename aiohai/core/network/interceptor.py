#!/usr/bin/env python3
"""
AIOHAI Core Network — Network Interceptor
===========================================
Socket-level network interception with:
- Hooks on socket.connect, getaddrinfo, gethostbyname
- Strict allowlist enforcement (localhost only by default)
- Blocks private IPs (including 100.64.0.0/10 Tailscale/CGNAT)
- Blocks DNS-over-HTTPS servers
- DNS tunneling/exfiltration detection via entropy analysis

Previously defined inline in proxy/aiohai_proxy.py.
Extracted as Phase 2a of the monolith → layered architecture migration.

Import from: aiohai.core.network.interceptor
"""

import re
import math
import socket
from typing import Tuple
from collections import defaultdict

from aiohai.core.types import AlertSeverity, NetworkSecurityError
from aiohai.core.patterns import DOH_SERVERS


class NetworkInterceptor:
    """Socket-level network interception with DoH blocking."""

    _instance = None
    _installed = False

    def __init__(self, config, logger, alerts):
        self.config = config
        self.logger = logger
        self.alerts = alerts
        self._original_connect = None
        self._original_getaddrinfo = None
        self._original_gethostbyname = None
        NetworkInterceptor._instance = self

    def install_hooks(self) -> None:
        if NetworkInterceptor._installed:
            return

        self._original_connect = socket.socket.connect
        self._original_getaddrinfo = socket.getaddrinfo
        self._original_gethostbyname = socket.gethostbyname

        socket.socket.connect = self._hooked_connect
        socket.getaddrinfo = self._hooked_getaddrinfo
        socket.gethostbyname = self._hooked_gethostbyname

        NetworkInterceptor._installed = True
        self.logger.log_event("NETWORK_HOOKS_INSTALLED", AlertSeverity.INFO, {})

    @staticmethod
    def _hooked_connect(sock_self, address):
        inst = NetworkInterceptor._instance
        try:
            host = address[0] if isinstance(address, tuple) else str(address)
            port = address[1] if isinstance(address, tuple) and len(address) > 1 else 0

            # Always allow localhost and Ollama
            if host in ('127.0.0.1', 'localhost', '::1'):
                pass
            elif inst.config.enforce_network_allowlist:
                # Check DoH servers
                if inst._is_doh_server(host):
                    inst.logger.log_network(host, "DOH_BLOCKED", {'port': port})
                    inst.alerts.alert(AlertSeverity.HIGH, "DOH_BLOCKED", f"DNS-over-HTTPS blocked: {host}")
                    raise NetworkSecurityError(f"DoH server blocked: {host}")

                allowed, reason = inst._check_connection(host, port)
                if not allowed:
                    inst.logger.log_network(host, "BLOCKED", {'port': port, 'reason': reason})
                    inst.alerts.alert(AlertSeverity.HIGH, "NETWORK_BLOCKED", f"Blocked: {host}:{port}")
                    raise NetworkSecurityError(f"Connection blocked: {reason}")

            inst.logger.log_network(host, "ALLOWED", {'port': port})
        except NetworkSecurityError:
            raise
        except Exception as e:
            inst.logger.logger.debug(f"Connection check error: {e}")

        return inst._original_connect(sock_self, address)

    @staticmethod
    def _hooked_getaddrinfo(host, port, *args, **kwargs):
        inst = NetworkInterceptor._instance

        # Check DoH
        if inst._is_doh_server(host):
            inst.logger.log_network(host, "DOH_DNS_BLOCKED", {})
            raise NetworkSecurityError(f"DoH DNS lookup blocked: {host}")

        if inst._is_dns_exfiltration(host):
            inst.logger.log_network(host, "DNS_EXFIL_BLOCKED", {})
            inst.alerts.alert(AlertSeverity.HIGH, "DNS_EXFILTRATION", f"Blocked: {host[:50]}")
            raise NetworkSecurityError("DNS exfiltration blocked")

        return inst._original_getaddrinfo(host, port, *args, **kwargs)

    @staticmethod
    def _hooked_gethostbyname(hostname):
        inst = NetworkInterceptor._instance

        if inst._is_doh_server(hostname):
            raise NetworkSecurityError(f"DoH blocked: {hostname}")

        if inst._is_dns_exfiltration(hostname):
            raise NetworkSecurityError("DNS exfiltration blocked")

        return inst._original_gethostbyname(hostname)

    def _is_doh_server(self, host: str) -> bool:
        """Check if host is a DNS-over-HTTPS server."""
        # SECURITY FIX (F-003): Exact or suffix match instead of substring
        host_lower = host.lower()
        for doh in DOH_SERVERS:
            doh_lower = doh.lower()
            if host_lower == doh_lower or host_lower.endswith('.' + doh_lower):
                return True
        return False

    def _check_connection(self, host: str, port: int) -> Tuple[bool, str]:
        # SECURITY FIX (F-003): Exact or suffix match instead of substring
        host_lower = host.lower()
        for allowed in self.config.network_allowlist:
            allowed_lower = allowed.lower()
            if host_lower == allowed_lower or host_lower.endswith('.' + allowed_lower):
                return True, "Allowlisted"

        # Block private IPs
        private = [r'^10\.', r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
                   r'^192\.168\.', r'^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.']
        for pattern in private:
            if re.match(pattern, host):
                return False, f"Private IP: {host}"

        return False, f"Not allowlisted: {host}"

    def _is_dns_exfiltration(self, hostname: str) -> bool:
        if not hostname:
            return False
        if len(hostname) > self.config.max_dns_query_length:
            return True

        parts = hostname.split('.')
        if len(parts) > 10:
            return True

        for part in parts[:-2]:
            if len(part) > 20:
                entropy = self._entropy(part)
                if entropy > self.config.max_dns_entropy:
                    return True
        return False

    def _entropy(self, text: str) -> float:
        if not text:
            return 0.0
        freq = defaultdict(int)
        for c in text:
            freq[c] += 1
        entropy = 0.0
        for count in freq.values():
            p = count / len(text)
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy


__all__ = ['NetworkInterceptor']
