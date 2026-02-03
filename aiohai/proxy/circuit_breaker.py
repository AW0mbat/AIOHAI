#!/usr/bin/env python3
"""Circuit Breaker - Prevent thread exhaustion when Ollama is down."""
import logging
logger = logging.getLogger("aiohai.proxy.circuit")

try:
    from proxy.aiohai_proxy import OllamaCircuitBreaker
except ImportError:
    class OllamaCircuitBreaker:
        def __init__(self, failure_threshold=3, reset_timeout=60): 
            raise ImportError("Requires proxy module")

__all__ = ['OllamaCircuitBreaker']
