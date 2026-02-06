# AIOHAI v5.0.0 — Clean Architecture

**Release Date:** February 2026

## Overview

AIOHAI v5.0.0 completes the architectural transformation started in v4.0.0. The monolithic codebase has been fully decomposed into a clean layered package, with every class extracted, all legacy directories removed, and a single canonical entry point.

This is a **breaking change** from v4.0.0: the `proxy/` and `security/` directories no longer exist. All code now lives exclusively in the `aiohai/` package.

```
┌─────────────────────────────────────────────────────────────┐
│  Companion Apps          Open WebUI         CLI Tools       │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     AIOHAI Proxy Layer                      │
│     (Action parsing, AI-specific validation, execution)     │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   AIOHAI Integrations Layer                 │
│     (Home Assistant, Office/Graph adapters)                 │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                       AIOHAI Core                           │
│     (Access control, Crypto, Audit, Analysis, Network)      │
└─────────────────────────────────────────────────────────────┘
```

## Breaking Changes

### Removed directories

The following directories have been deleted. All code they contained now lives in `aiohai/`:

- `proxy/` — `aiohai_proxy.py` (4,208 lines) → extracted into `aiohai/proxy/` and `aiohai/core/`
- `security/` — `security_components.py` (2,274 lines), `fido2_approval.py` (1,328 lines), `hsm_integration.py` → extracted into `aiohai/core/` subsystems

### Removed import paths

These import paths no longer work:

```python
# These will raise ImportError in v5.0.0
from proxy.aiohai_proxy import ...
from security.security_components import ...
from security.fido2_approval import ...
from security.hsm_integration import ...
```

### New canonical imports

```python
# All imports now come from the aiohai package
from aiohai.core.types import SecurityLevel, ActionType, ApprovalTier
from aiohai.core.config import UnifiedConfig
from aiohai.core.access.path_validator import PathValidator
from aiohai.core.analysis.pii_protector import PIIProtector
from aiohai.core.crypto.fido_gate import FIDO2ApprovalServer
from aiohai.core.crypto.hsm_bridge import get_hsm_manager
from aiohai.proxy.orchestrator import UnifiedSecureProxy, main
from aiohai.integrations.smart_home.service_registry import LocalServiceRegistry
```

### Entry point

The only entry point is now:

```bash
python -m aiohai
```

The old `python proxy/aiohai_proxy.py` no longer exists.

## What Changed

### Extraction summary (7 phases)

| Phase | What moved | Classes | Lines |
|-------|-----------|---------|-------|
| 1 | Core foundation (Config, Logger, Alerts) | 3 | 312 |
| 2a | Security classes from proxy | 6 | 787 |
| 2b | Security classes from security_components | 7 | 997 |
| 3 | FIDO2/Crypto layer | 4 | ~1,030 |
| 4a | Smart home integration adapters | 5 | ~820 |
| 4b | Office integration adapters | 6 | ~905 |
| 5 | Proxy layer (handler, executor, orchestrator) | 8 | 2,922 |
| 6 | Facade conversion (monolith → thin re-exports) | — | -7,409 |
| 7 | Test/tool migration + monolith removal | — | — |
| **Total** | | **35 classes** | **~10,865 lines** |

### Codebase metrics

| Metric | v4.0.0 | v5.0.0 | Change |
|--------|--------|--------|--------|
| Monolith files | 7,810 lines | 0 | -100% |
| Stub/facade files | 2,764 lines | 0 | -100% |
| `aiohai/` package | ~2,764 (stubs) | ~10,865 (real code) | Real implementations |
| Total Python | ~18,675 lines | ~10,865 lines | -42% |
| Entry points | 2 | 1 | Simplified |

### Fixes included

- Removed ghost framework entries (`ha_framework_v4.md`, `office_framework_v4.md`) from `ALLOWED_FRAMEWORK_NAMES` — these files never existed on disk
- Updated `config.json` to reference `aiohai/core/constants.py` instead of deleted `proxy/aiohai_proxy.py`
- Updated `setup/Setup.ps1` to use `python -m aiohai` entry point
- Removed obsolete backward-compatibility extraction tests (P4, P5)
- Updated all test and tool imports to canonical `aiohai.*` paths

### Files changed

**Deleted:**
- `proxy/` directory (entire)
- `security/` directory (entire)
- `tests/test_extraction_verify_p4.py`
- `tests/test_extraction_verify_p5.py`

**Updated:**
- `aiohai/core/version.py` — Version bumped to 5.0.0, ghost entries removed
- `aiohai/__main__.py` — Cleaned up stale transition comments
- `aiohai/core/__init__.py` — Removed extraction phase references
- `config/config.json` — Updated path references
- `setup/Setup.ps1` — Updated to use `python -m aiohai`
- `.gitignore` — Added desktop build artifacts
- `requirements.txt` — Updated header
- `README.md` — Full rewrite for v5.0.0
- All test files — Imports migrated to `aiohai.*`
- All tool files — Imports migrated to `aiohai.*`

**Added:**
- `CHANGELOG_5.0.0.md` (this file)
- `tests/test_extraction_verify_p7.py` — Authoritative verification test

## Migration Guide

### For Users

Update the proxy start command:

```powershell
# Old (no longer works)
python proxy\aiohai_proxy.py

# New
python -m aiohai

# With options
python -m aiohai --no-hsm --no-fido2
python -m aiohai --hsm-pin YOUR_PIN
```

If you have a scheduled task, update it:

```powershell
$action = New-ScheduledTaskAction -Execute "python" -Argument "-m aiohai"
```

### For Developers

Update all imports:

```python
# Types and enums
from aiohai.core.types import SecurityLevel, ActionType

# Configuration
from aiohai.core.config import UnifiedConfig

# Security components
from aiohai.core.access.path_validator import PathValidator
from aiohai.core.access.command_validator import CommandValidator
from aiohai.core.analysis.sanitizer import ContentSanitizer
from aiohai.core.analysis.pii_protector import PIIProtector
from aiohai.core.audit.logger import SecurityLogger
from aiohai.core.network.interceptor import NetworkInterceptor

# Proxy layer
from aiohai.proxy.orchestrator import UnifiedSecureProxy
from aiohai.proxy.executor import SecureExecutor
```

## Known Remaining Work

1. **~30 pre-existing test failures** — API method name mismatches from v3→v4 refactoring. Not caused by extraction.
2. **Package installability** — Adding `pyproject.toml` would enable `pip install -e .` for development.
3. **Agent layer** — `aiohai/agent/` contains placeholder modules only.
4. **Desktop companion app** — Phase 1 ChatPanel complete; FIDO2 approval modal and log viewer pending.
