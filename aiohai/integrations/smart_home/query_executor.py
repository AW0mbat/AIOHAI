#!/usr/bin/env python3
"""
AIOHAI Integrations — Smart Home Query Executor

Execute queries against registered services with PII protection.
"""

import logging
logger = logging.getLogger("aiohai.integrations.smart_home")

try:
    from proxy.aiohai_proxy import LocalAPIQueryExecutor
    _EXECUTOR_AVAILABLE = True
except ImportError:
    _EXECUTOR_AVAILABLE = False
    class LocalAPIQueryExecutor:
        def __init__(self, registry, pii_protector, logger):
            raise ImportError("Requires proxy module")

__all__ = ['LocalAPIQueryExecutor']
