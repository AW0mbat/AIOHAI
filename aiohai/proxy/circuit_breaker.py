#!/usr/bin/env python3
"""
Ollama Circuit Breaker — Prevent thread exhaustion when Ollama is down.

After `failure_threshold` consecutive failures, the breaker opens and
immediately rejects requests for `reset_timeout` seconds instead of
waiting the full 300s Ollama timeout per request.

Phase 5 extraction from proxy/aiohai_proxy.py.
"""

import threading
import time

__all__ = ['OllamaCircuitBreaker']


class OllamaCircuitBreaker:
    """Prevents thread exhaustion when Ollama is down or slow.

    After `failure_threshold` consecutive failures, the breaker opens and
    immediately rejects requests for `reset_timeout` seconds instead of
    waiting the full 300s Ollama timeout per request.
    """

    def __init__(self, failure_threshold: int = 3, reset_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.failures = 0
        self.last_failure_time: float = 0
        self.state = 'closed'  # closed=normal, open=blocking, half-open=testing
        self.lock = threading.Lock()

    def can_request(self) -> bool:
        """Check if a request should be allowed through."""
        with self.lock:
            if self.state == 'closed':
                return True
            if self.state == 'open':
                # Check if enough time has passed to try again
                if time.time() - self.last_failure_time > self.reset_timeout:
                    self.state = 'half-open'
                    return True
                return False
            # half-open: allow one request to test
            return True

    def record_success(self):
        """Record a successful Ollama call. Resets the breaker."""
        with self.lock:
            self.failures = 0
            self.state = 'closed'

    def record_failure(self):
        """Record a failed Ollama call. May trip the breaker."""
        with self.lock:
            self.failures += 1
            self.last_failure_time = time.time()
            if self.failures >= self.failure_threshold:
                self.state = 'open'

    def is_open(self) -> bool:
        with self.lock:
            return self.state == 'open'
