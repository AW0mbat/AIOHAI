# AIOHAI v4.0.0 — Layered Architecture Refactoring

**Release Date:** February 2026

## Overview

This release transforms AIOHAI from a monolithic architecture into a layered system with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────────┐
│  Companion Apps          Open WebUI         CLI Tools       │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     AIOHAI Agent Layer                      │
│     (Placeholder: Screen capture, supervised browsing)      │
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

## New Package Structure

```
aiohai/
├── __init__.py              # Package root (version 4.0.0)
├── __main__.py              # Entry point: python -m aiohai
│
├── core/                    # Layer 1: Trust Infrastructure
│   ├── types.py             # 24 shared types (enums, dataclasses, exceptions)
│   ├── config.py            # Configuration management
│   ├── access/              # PathValidator, CommandValidator, SessionManager
│   ├── crypto/              # HSM, FIDO2, credentials
│   ├── audit/               # Logger, IntegrityVerifier, TransparencyTracker
│   ├── analysis/            # Sanitizer, PIIProtector, StaticAnalyzer
│   ├── network/             # NetworkInterceptor
│   └── resources/           # ResourceLimiter
│
├── integrations/            # Layer 2: Domain Adapters
│   ├── smart_home/          # Home Assistant, Frigate
│   └── office/              # Office, Graph API
│
├── proxy/                   # Layer 3: AI Enforcement
│   ├── orchestrator.py      # UnifiedSecureProxy
│   ├── handler.py           # UnifiedProxyHandler
│   ├── action_parser.py     # ActionParser
│   └── executor.py          # SecureExecutor
│
└── agent/                   # Layer 4: Future AI Assistant (placeholder)
    ├── screen_capture.py
    ├── browser_supervisor.py
    ├── trust_manager.py
    └── vault_accessor.py
```

## Key Changes

### Type Consolidation
- All 24 shared types (11 enums, 10 dataclasses, 3 exceptions) now live in `aiohai/core/types.py`
- Original files import from the new location with fallback for backward compatibility

### HSM Integration
- Full implementation moved to `aiohai/core/crypto/hsm_bridge.py`
- `security/hsm_integration.py` is now a backward-compatible facade

### Backward Compatibility
- All original import paths continue to work
- `from security.security_components import PIIProtector` still works
- `from proxy.aiohai_proxy import PathValidator` still works
- Facade modules re-export from the new canonical locations

### Entry Points
- New canonical: `python -m aiohai`
- Old (still works): `python proxy/aiohai_proxy.py`

## Migration Guide

### For Users
No action required. The proxy works exactly as before.

### For Developers
Prefer the new import paths:
```python
# Old (still works)
from security.security_components import PIIProtector

# New (preferred)
from aiohai.core.analysis import PIIProtector
```

## Statistics

- **55 new Python files** in the `aiohai/` package
- **Types consolidated:** 24 types from 4 files into 1
- **Backward compatibility:** 100% — all original imports work
- **Test suite:** 257 tests (14 failures are pre-existing, unrelated to refactoring)

## What's Next

- Phase 9: Update test imports to use new paths
- Move implementations from facade modules to canonical locations
- Expand Agent layer capabilities
