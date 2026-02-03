# AIOHAI — AI-Operated Home & Office Intelligence Proxy

**Version 4.0.0** · Layered Security Architecture for Local AI Agents

---

## What Is This?

AIOHAI is a security proxy that sits between [Open WebUI](https://github.com/open-webui/open-webui) (or any chat frontend) and a local [Ollama](https://ollama.com) instance. It intercepts every request the LLM makes — file reads, file writes, command execution, API calls, network access — and enforces a comprehensive security policy before anything touches your system.

The proxy was designed for a specific threat model: you're running a capable local LLM with tool-use (agentic) capabilities on the same machine where you live and work. The LLM can read your documents, run commands, query your smart home, and interact with Office files. AIOHAI ensures it can only do what you've explicitly approved, and that every action is logged, auditable, and tamper-evident.

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
│  ┌─────────────────┐ ┌─────────────────┐ ┌──────────────┐  │
│  │ Access Control  │ │ Crypto Layer    │ │ Audit Layer  │  │
│  │ - PathValidator │ │ - HSM Bridge    │ │ - Logger     │  │
│  │ - CommandValid. │ │ - FIDO2 Gate    │ │ - Integrity  │  │
│  │ - SessionMgr    │ │ - Credentials   │ │ - Alerts     │  │
│  └─────────────────┘ └─────────────────┘ └──────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## What's New in v4.0.0

This release transforms AIOHAI from a monolithic architecture into a layered system:

- **AIOHAI Core** — Accessor-agnostic trust infrastructure (types, access control, crypto, audit, analysis, network, resources)
- **AIOHAI Integrations** — Domain-specific adapters (Home Assistant, Office/Graph API)
- **AIOHAI Proxy** — AI-specific enforcement layer
- **AIOHAI Agent** — Placeholder for future capabilities (screen capture, supervised browsing)

All 24 shared types (11 enums, 10 dataclasses, 3 exceptions) now live in `aiohai/core/types.py`. The original files (`proxy/aiohai_proxy.py`, `security/*`) still work — they import from the new locations with fallbacks for backward compatibility.

**New entry point:** `python -m aiohai` (the old `python proxy/aiohai_proxy.py` still works)

---

## File Layout

```
C:\AIOHAI\                          (or $AIOHAI_HOME)
├── aiohai/                         NEW: Layered package (v4.0.0)
│   ├── __init__.py                 Package root (version 4.0.0)
│   ├── __main__.py                 Entry point: python -m aiohai
│   ├── core/                       Layer 1: Trust Infrastructure
│   │   ├── types.py                24 consolidated types
│   │   ├── access/                 PathValidator, CommandValidator, SessionManager
│   │   ├── crypto/                 HSM bridge, FIDO2 gate, credentials
│   │   ├── audit/                  Logger, integrity, transparency, alerts
│   │   ├── analysis/               Sanitizer, PII, static analysis
│   │   ├── network/                NetworkInterceptor
│   │   └── resources/              ResourceLimiter
│   ├── integrations/               Layer 2: Domain Adapters
│   │   ├── smart_home/             Home Assistant, Frigate
│   │   └── office/                 Office, Graph API
│   ├── proxy/                      Layer 3: AI Enforcement
│   │   └── (orchestrator, handler, executor, etc.)
│   └── agent/                      Layer 4: Future (placeholder)
│       └── (screen_capture, browser_supervisor, etc.)
│
├── proxy/
│   └── aiohai_proxy.py             Original proxy (facade imports from aiohai.core)
├── security/
│   ├── security_components.py      Analysis engines (facade imports from aiohai.core)
│   ├── fido2_approval.py           FIDO2/WebAuthn (facade imports from aiohai.core)
│   └── hsm_integration.py          HSM facade (full impl moved to aiohai.core.crypto)
├── config/
│   └── config.json                 Central configuration
├── policy/
│   ├── aiohai_security_policy_v3.0.md   Security policy (injected into LLM context)
│   ├── ha_framework_v3.md               Home Assistant framework prompt
│   └── office_framework_v3.md           Office framework prompt
├── tests/
│   ├── conftest.py                 Shared fixtures
│   ├── test_security.py            Security unit tests
│   ├── test_startup.py             Integration tests
│   ├── test_e2e.py                 End-to-end pipeline tests
│   ├── test_ha_framework.py        Smart home framework tests
│   └── test_office_framework.py    Office framework tests
├── tools/
│   ├── aiohai_cli.py               Management CLI
│   ├── register_devices.py         FIDO2 device registration wizard
│   └── hsm_setup.py                HSM initialization tool
├── docs/
│   └── ARCHITECTURE.md             Architecture documentation
├── web/
│   └── templates/                  FIDO2 approval UI
├── desktop/                        Desktop companion app (Electron)
│   ├── package.json                Node.js dependencies and scripts
│   ├── src/main/                   Electron main process (TypeScript)
│   ├── src/renderer/               React UI (TypeScript + CSS)
│   ├── start-aiohai.bat            One-click startup (Windows)
│   └── FIRST_RUN_GUIDE.md          Setup walkthrough
└── logs/                           Runtime logs (created automatically)
```

---

## Security Layers (11 Total)

| Layer | Component | Function |
|-------|-----------|----------|
| 1 | StartupSecurityVerifier | Blocks admin/root execution, checks env vars |
| 2 | IntegrityVerifier | Hashes policy + framework files, lockdown on tampering |
| 3 | NetworkInterceptor | Socket hooks, blocks private IPs, DoH, DNS tunneling |
| 4 | ContentSanitizer | Strips invisible chars, detects injection patterns |
| 5 | StaticSecurityAnalyzer + PIIProtector | Bandit-style analysis, PII/credential redaction |
| 6 | ResourceLimiter | DoS protection (processes, file ops, session limits) |
| 7 | PathValidator + CommandValidator | Blocks credential stores, obfuscation detection |
| 8 | ApprovalManager + SecureExecutor | HMAC tokens, sandboxed execution |
| 9 | Nitrokey HSM + FIDO2/WebAuthn | Hardware signing, physical key approval |
| 10 | SessionTransparencyTracker + AlertManager | Action logging, desktop notifications |
| 11 | OllamaCircuitBreaker | Prevents thread exhaustion |

---

## Quick Start

1. Clone this repository
2. Install Python 3.10+
3. Install dependencies: `pip install -r requirements.txt`
4. Configure `config/config.json` for your environment
5. Start the proxy:
   ```bash
   # New canonical entry point (v4.0.0)
   python -m aiohai

   # Or the original way (still works)
   python proxy/aiohai_proxy.py

   # Minimal (no hardware security)
   python -m aiohai --no-hsm --no-fido2

   # Full (with Nitrokey HSM + FIDO2 key)
   python -m aiohai --hsm-pin YOUR_PIN
   ```
6. Point Open WebUI's `OLLAMA_BASE_URL` to `http://localhost:11435`
7. Chat normally — the proxy intercepts and secures everything transparently

---

## In-Chat Commands

| Command | What It Does |
|---|---|
| `CONFIRM <id>` | Approve a pending action |
| `REJECT <id>` | Deny a pending action |
| `CONFIRM ALL` | Approve all pending actions |
| `EXPLAIN <id>` | Show details about a pending action |
| `PENDING` | List all pending actions |
| `REPORT` | Show full session transparency report |
| `STATUS` | Show proxy and component health |
| `HELP` | Show available commands |
| `STOP` | Emergency stop — reject all pending actions |

---

## Desktop Companion App

The `desktop/` directory contains an Electron app that serves as a single pane of glass for AIOHAI — chat, approvals, health monitoring, log viewing, and configuration in one window.

**Status:** Phase 1 in progress. Scaffold validated on Windows. Connection to Open WebUI tested and working.

See `desktop/FIRST_RUN_GUIDE.md` for setup instructions.

---

## Domain Integrations

### Smart Home (Home Assistant + Frigate)
- `LocalServiceRegistry` — Allowlist of queryable local services
- `LocalAPIQueryExecutor` — Execute queries with PII protection
- `SmartHomeStackDetector` — Auto-discover Docker-based stack
- `HomeAssistantNotificationBridge` — Forward alerts to HA dashboard

### Microsoft Office (Graph API)
- `DocumentContentScanner` — Scan Office docs for PII/credentials
- `MacroBlocker` — Block macro-enabled formats
- `MetadataSanitizer` — Strip author/revision metadata
- `GraphAPIRegistry` — Security gateway for Graph API

---

## Dependencies

| Package | Required? | Purpose |
|---|---|---|
| Python 3.10+ | Yes | Runtime |
| `psutil` | Recommended | Process/resource monitoring |
| `pywin32` | Optional (Windows) | DLL integrity, file locking |
| `fido2` | Optional | FIDO2/WebAuthn hardware approval |
| `flask` + `flask-cors` | Optional | FIDO2 approval web server |
| `cryptography` | Optional | TLS certificates, FIDO2 crypto |
| `PyKCS11` | Optional | Nitrokey HSM integration |
| `python-docx` | Optional | Word document metadata sanitization |
| `openpyxl` | Optional | Excel document metadata sanitization |
| `python-pptx` | Optional | PowerPoint document metadata sanitization |

---

## Platform Support

Primary: **Windows 10/11 Pro**. Linux partially supported (network interception works, path/command validation is Windows-centric). FIDO2 and HSM subsystems are cross-platform.

---

## Version History

### v4.0.0 (Current)

**Layered Architecture Refactoring**

- Transformed from monolithic (~9,400 lines across 4 files) to layered package structure
- Created `aiohai/` package with Core, Integrations, Proxy, and Agent layers
- Consolidated 24 types (11 enums, 10 dataclasses, 3 exceptions) into `aiohai/core/types.py`
- Full HSM implementation moved to `aiohai/core/crypto/hsm_bridge.py`
- All original import paths continue to work (facade pattern)
- New entry point: `python -m aiohai`

### v3.0.2

4 validation fixes: API_QUERY action routing, framework integrity verification, config cleanup, requirements.txt update.

### v3.0.1

8 security fixes, 1 bug fix, 4 optimizations. Net: +234 / -88 lines.

---

## License

See individual source files for license information.
