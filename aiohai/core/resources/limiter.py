#!/usr/bin/env python3
"""
AIOHAI Core Resources — Resource Limiter
==========================================
DoS protection via resource limits:
- Session time limits
- Request and action rate limiting
- Concurrent action caps
- Memory monitoring (via psutil)
- Disk write tracking, file size limits, output truncation

Previously defined inline in security/security_components.py.
Extracted as Phase 2b of the monolith → layered architecture migration.

Import from: aiohai.core.resources.limiter
"""

import os
import time
import threading
from typing import Dict
from contextlib import contextmanager
from collections import defaultdict

from aiohai.core.types import ResourceLimits, ResourceLimitExceeded

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False


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

        if _PSUTIL_AVAILABLE:
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


__all__ = ['ResourceLimiter', 'ResourceLimits', 'ResourceLimitExceeded']
