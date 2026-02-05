#!/usr/bin/env python3
"""
AIOHAI Integrations — Smart Home Service Registry
===================================================
Allowlist of queryable local services with port verification.

Registry for local services the model can query (Frigate, HA, etc.).
Validates that API requests target only registered localhost services
with explicitly allowed paths. Prevents the model from querying
arbitrary endpoints.

Previously defined in proxy/aiohai_proxy.py.
Extracted as Phase 4a of the monolith → layered architecture migration.

Import from: aiohai.integrations.smart_home.service_registry
"""

import socket
import urllib.parse
from typing import Dict, List, Tuple

from aiohai.core.types import AlertSeverity
from aiohai.core.audit.logger import SecurityLogger


class LocalServiceRegistry:
    """Registry for local services the model can query (Frigate, HA, etc.).

    Validates that API requests target only registered localhost services
    with explicitly allowed paths. Prevents the model from querying
    arbitrary endpoints.
    """

    def __init__(self, logger: SecurityLogger):
        self.logger = logger
        self._services: Dict[str, Dict] = {}

    def register(self, name: str, host: str, port: int,
                 allowed_paths: List[str], max_response_bytes: int = 1048576,
                 description: str = ''):
        """Register a local service.

        L-7 FIX: Verifies the service is actually listening on the port
        before registration to prevent fake service injection via config.
        """
        # Validate host is localhost
        if host not in ('127.0.0.1', 'localhost', '::1'):
            self.logger.log_event("LOCAL_SERVICE_REJECTED", AlertSeverity.WARNING,
                                  {'service': name, 'host': host, 'reason': 'Non-local host'})
            return

        # L-7 FIX: Verify service is actually listening
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(('127.0.0.1' if host == 'localhost' else host, port))
            sock.close()
            if result != 0:
                self.logger.log_event("LOCAL_SERVICE_NOT_LISTENING", AlertSeverity.WARNING,
                                      {'service': name, 'port': port,
                                       'reason': 'No service responding on port'})
                return
        except Exception as e:
            self.logger.log_event("LOCAL_SERVICE_VERIFY_FAILED", AlertSeverity.WARNING,
                                  {'service': name, 'port': port, 'error': str(e)})
            return

        self._services[name] = {
            'host': host,
            'port': port,
            'allowed_paths': allowed_paths,
            'max_response_bytes': max_response_bytes,
            'description': description,
        }
        self.logger.log_event("LOCAL_SERVICE_REGISTERED", AlertSeverity.INFO,
                              {'service': name, 'endpoint': f'{host}:{port}',
                               'paths': len(allowed_paths)})

    def validate_request(self, url: str) -> Tuple[bool, str]:
        """Validate a URL against registered services."""
        try:
            parsed = urllib.parse.urlparse(url)
        except Exception:
            return False, "Invalid URL"

        # Must be HTTP to localhost
        if parsed.scheme not in ('http', 'https'):
            return False, f"Scheme not allowed: {parsed.scheme}"

        host = parsed.hostname or ''
        if host not in ('127.0.0.1', 'localhost', '::1'):
            return False, f"Non-local host: {host}"

        port = parsed.port
        path = parsed.path or '/'

        # Find matching service
        for svc_name, svc in self._services.items():
            if svc['port'] == port:
                # Check if path is allowed
                for allowed in svc['allowed_paths']:
                    if allowed.endswith('*'):
                        if path.startswith(allowed[:-1]):
                            return True, svc_name
                    elif path == allowed:
                        return True, svc_name

                return False, f"Path '{path}' not allowed for {svc_name}"

        return False, f"No registered service on port {port}"

    def get_max_response(self, service_name: str) -> int:
        """Get max response size for a service."""
        svc = self._services.get(service_name, {})
        return svc.get('max_response_bytes', 1048576)

    def load_from_config(self, config_data: dict):
        """Load additional services from config.json local_services section."""
        local_services = config_data.get('local_services', {})
        for name, svc_cfg in local_services.items():
            host = svc_cfg.get('host', '127.0.0.1')
            if host not in ('127.0.0.1', 'localhost', '::1'):
                self.logger.log_event("LOCAL_SERVICE_CONFIG_REJECTED", AlertSeverity.WARNING,
                                      {'service': name, 'host': host, 'reason': 'Non-local host in config'})
                continue
            self.register(
                name=name,
                host=host,
                port=svc_cfg.get('port', 80),
                allowed_paths=svc_cfg.get('allowed_paths', []),
                max_response_bytes=svc_cfg.get('max_response_bytes', 1048576),
                description=svc_cfg.get('description', ''),
            )


__all__ = ['LocalServiceRegistry']
