#!/usr/bin/env python3
"""
AIOHAI Integrations — Smart Home Query Executor
=================================================
Executes validated API queries against local services.

All queries must pass through LocalServiceRegistry validation first.
Responses are PII-redacted before being returned to the model.

Previously defined in proxy/aiohai_proxy.py.
Extracted as Phase 4a of the monolith → layered architecture migration.

Import from: aiohai.integrations.smart_home.query_executor
"""

import urllib.request
import urllib.error
from typing import Tuple

from aiohai.core.audit.logger import SecurityLogger
from aiohai.integrations.smart_home.service_registry import LocalServiceRegistry


class LocalAPIQueryExecutor:
    """Executes validated API queries against local services.

    All queries must pass through LocalServiceRegistry validation first.
    Responses are PII-redacted before being returned to the model.
    """

    def __init__(self, service_registry: LocalServiceRegistry,
                 logger: SecurityLogger, pii_protector=None,
                 transparency_tracker=None):
        self.registry = service_registry
        self.logger = logger
        self.pii_protector = pii_protector
        self.transparency_tracker = transparency_tracker  # M-9 FIX

    def execute(self, url: str, method: str = 'GET',
                headers: dict = None, timeout: int = 10) -> Tuple[bool, str]:
        """Execute a validated API query."""
        # Validate through registry
        is_valid, svc_or_reason = self.registry.validate_request(url)
        if not is_valid:
            self.logger.log_blocked("LOCAL_API_QUERY", url, svc_or_reason)
            return False, f"Query blocked: {svc_or_reason}"

        service_name = svc_or_reason
        max_bytes = self.registry.get_max_response(service_name)

        try:
            req = urllib.request.Request(url, method=method.upper())
            if headers:
                for k, v in headers.items():
                    req.add_header(k, v)

            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read(max_bytes)
                content_type = resp.headers.get('Content-Type', '')

                # If JSON/text, decode and optionally redact PII
                if 'json' in content_type or 'text' in content_type:
                    text = data.decode('utf-8', errors='replace')
                    if self.pii_protector:
                        text = self.pii_protector.redact(text)

                    self.logger.log_action("LOCAL_API_QUERY", url, "SUCCESS",
                                           {'service': service_name, 'bytes': len(data)})
                    # M-9 FIX: Record in transparency tracker
                    if self.transparency_tracker:
                        self.transparency_tracker.record_api_query(
                            service_name, url, success=True)
                    return True, text
                else:
                    # Binary (images etc) - return info, not raw data
                    self.logger.log_action("LOCAL_API_QUERY", url, "SUCCESS",
                                           {'type': 'binary', 'bytes': len(data),
                                            'content_type': content_type})
                    if self.transparency_tracker:
                        self.transparency_tracker.record_api_query(
                            service_name, url, success=True)
                    return True, f"[Binary response: {len(data)} bytes, type: {content_type}]"

        except urllib.error.HTTPError as e:
            self.logger.log_action("LOCAL_API_QUERY", url, "HTTP_ERROR",
                                   {'status': e.code})
            if self.transparency_tracker:
                self.transparency_tracker.record_api_query(
                    service_name, url, success=False)
            return False, f"HTTP {e.code}"
        except urllib.error.URLError as e:
            self.logger.log_action("LOCAL_API_QUERY", url, "CONNECTION_ERROR",
                                   {'reason': str(e.reason)})
            if self.transparency_tracker:
                self.transparency_tracker.record_api_query(
                    service_name, url, success=False)
            return False, f"Connection failed: {e.reason}"
        except Exception as e:
            self.logger.log_action("LOCAL_API_QUERY", url, "ERROR",
                                   {'error': str(e)})
            if self.transparency_tracker:
                self.transparency_tracker.record_api_query(
                    service_name, url, success=False)
            return False, f"Query error: {e}"


__all__ = ['LocalAPIQueryExecutor']
