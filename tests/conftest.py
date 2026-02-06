"""
Shared pytest fixtures for AIOHAI v3.0 test suite.

Provides mock objects for SecurityLogger, AlertManager, UnifiedConfig,
and HSM/FIDO2 components so unit tests run without real hardware or
filesystem side effects.
"""

import os
import sys
import json
import hashlib
import tempfile
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch
from dataclasses import dataclass, field
from typing import Set, List

import pytest

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Import after path fix
from aiohai.core.types import AlertSeverity, TrustLevel, SecurityError
from aiohai.core.config import UnifiedConfig
from aiohai.core.audit.logger import SecurityLogger
from aiohai.core.audit.alerts import AlertManager
from aiohai.core.audit.integrity import IntegrityVerifier
from aiohai.core.access.path_validator import PathValidator
from aiohai.core.access.command_validator import CommandValidator
from aiohai.core.analysis.sanitizer import ContentSanitizer
from aiohai.core.network.interceptor import NetworkInterceptor
from aiohai.core.patterns import (
    BLOCKED_PATH_PATTERNS, BLOCKED_COMMAND_PATTERNS, TIER3_PATH_PATTERNS,
    INJECTION_PATTERNS, INVISIBLE_CHARS, HOMOGLYPHS,
)
from aiohai.core.constants import SESSION_ID_BYTES, HASH_CHUNK_SIZE
from aiohai.proxy.executor import SecureExecutor
from aiohai.proxy.approval import ApprovalManager
from aiohai.proxy.action_parser import ActionParser


# ---------------------------------------------------------------------------
# Config fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_base(tmp_path):
    """Create a temporary AIOHAI base directory with policy and logs."""
    (tmp_path / "policy").mkdir()
    (tmp_path / "logs").mkdir()
    (tmp_path / "temp").mkdir()
    (tmp_path / "data" / "ssl").mkdir(parents=True)
    (tmp_path / "data" / "fido2").mkdir(parents=True)
    
    # Write a minimal policy file
    policy = tmp_path / "policy" / "aiohai_security_policy_v3.0.md"
    policy.write_text("# AIOHAI Policy v3.0\nDo not harm the user.\n")
    
    # Write a policy signature placeholder
    sig = tmp_path / "policy" / "policy.sig"
    sig.write_bytes(b"\x00" * 64)
    
    return tmp_path


@pytest.fixture
def config(tmp_base):
    """A UnifiedConfig pointing at the temp directory."""
    cfg = UnifiedConfig()
    cfg.base_dir = tmp_base
    cfg.policy_file = tmp_base / "policy" / "aiohai_security_policy_v3.0.md"
    cfg.policy_signature_file = tmp_base / "policy" / "policy.sig"
    cfg.log_dir = tmp_base / "logs"
    cfg.secure_temp_dir = tmp_base / "temp"
    cfg.listen_host = "127.0.0.1"
    cfg.listen_port = 11435
    cfg.ollama_host = "127.0.0.1"
    cfg.ollama_port = 11434
    cfg.hsm_enabled = False
    cfg.hsm_required = False
    cfg.fido2_enabled = False
    return cfg


# ---------------------------------------------------------------------------
# Logger / alerts fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_logger(config):
    """A real SecurityLogger writing to temp logs."""
    logger = SecurityLogger(config)
    return logger


@pytest.fixture
def mock_alerts(config, mock_logger):
    """A real AlertManager backed by the mock logger."""
    alerts = AlertManager(config, mock_logger)
    return alerts


@pytest.fixture
def silent_logger():
    """A fully-mocked logger that records calls but writes nothing."""
    logger = MagicMock(spec=SecurityLogger)
    logger.session_id = "test-session-0000"
    return logger


@pytest.fixture
def silent_alerts():
    """A fully-mocked AlertManager."""
    return MagicMock(spec=AlertManager)


# ---------------------------------------------------------------------------
# Component fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def path_validator(config, mock_logger, mock_alerts):
    return PathValidator(config, mock_logger)


@pytest.fixture
def command_validator(config, mock_logger, mock_alerts):
    return CommandValidator(config, mock_logger)


@pytest.fixture
def sanitizer(mock_logger, mock_alerts):
    return ContentSanitizer(mock_logger, mock_alerts)


@pytest.fixture
def integrity(config, mock_logger, mock_alerts):
    return IntegrityVerifier(config, mock_logger, mock_alerts)


@pytest.fixture
def approval_mgr(config, mock_logger, mock_alerts):
    return ApprovalManager(config, mock_logger)
