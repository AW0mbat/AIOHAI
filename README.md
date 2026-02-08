# AIOHAI — AI-Operated Home & Office Intelligence Proxy

**Version 5.1.0** · Security-Hardened Layered Architecture for Local AI Agents

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

## What's New in v5.1.0

v5.1.0 is a security-first maintenance release produced by a full code audit of the v5.0.0 codebase. It closes 5 security vulnerabilities, fixes 4 correctness bugs, and applies targeted structural optimization — all with zero behavior changes to intended functionality.

**Security fixes:**

- FIDO2 server endpoints (`/api/pending`, `/api/users`) now require authentication — LAN clients can no longer enumerate pending operations or registered users
- Admin FIDO2 registration gated after bootstrap — first user is admin, subsequent admin registrations require API secret authorization
- HSM PIN no longer accepted via command-line argument by default — use `AIOHAI_HSM_PIN` environment variable or interactive prompt instead (`--hsm-pin` still works but prints a deprecation warning)
- Request body size capped at 10 MB (returns HTTP 413), response reads capped at 50 MB
- Dead `"pin"` field removed from `config.json` to prevent accidental plaintext PIN storage

**Correctness fixes:**

- HSM signatures now use `CKM_RSA_PKCS` (no double-hash), making them interoperable with standard tooling
- FIDO2 approval audit log now records the actual key used, not always the first registered key
- Approval content hash includes action type and target, preventing cross-action substitution
- Docker image matching uses exact name comparison instead of prefix matching

**Structural optimization:**

- Handler uses `HandlerContext` dataclass + `_ACTION_DISPATCH` table (replaces 20 class attributes and if/elif chains)
- Orchestrator `start()` decomposed into individually testable `_step_*` methods
- FIDO2 HTML templates extracted to `fido2_templates.py` (−122 lines from `fido_gate.py`)
- CLI interactive menus consolidated via generic `_interactive_dispatch()`
- `__init__.py` re-exports trimmed: 513 → 90 lines across 13 files

See `CHANGELOG_5.1.0.md` for full details on all 15 steps.

---

## File Layout

```
C:\AIOHAI\                          (or $AIOHAI_HOME)
├── aiohai/                         All code (~10,350 lines, 65 files)
│   ├── __init__.py                 Package root (version 5.1.0)
│   ├── __main__.py                 Entry point: python -m aiohai
│   ├── core/                       Layer 1: Trust Infrastructure
│   │   ├── types.py                24 consolidated types (enums, dataclasses, exceptions)
│   │   ├── version.py              Version constants (single source of truth)
│   │   ├── patterns.py             All regex patterns (deduplicated)
│   │   ├── constants.py            Numeric constants, frozen sets
│   │   ├── templates.py            LLM instruction templates
│   │   ├── config.py               UnifiedConfig
│   │   ├── access/                 PathValidator, CommandValidator, SessionManager
│   │   ├── crypto/                 HSM bridge, FIDO2 gate, credentials, fido2_templates
│   │   ├── audit/                  Logger, integrity, transparency, alerts
│   │   ├── analysis/               Sanitizer, PII, static analysis
│   │   ├── network/                NetworkInterceptor
│   │   └── resources/              ResourceLimiter
│   ├── integrations/               Layer 2: Domain Adapters
│   │   ├── smart_home/             Home Assistant, Frigate (5 classes)
│   │   └── office/                 Office, Graph API (6 classes)
│   ├── proxy/                      Layer 3: AI Enforcement
│   │   ├── orchestrator.py         UnifiedSecureProxy + main() (step-decomposed)
│   │   ├── handler.py              UnifiedProxyHandler + HandlerContext
│   │   ├── executor.py             SecureExecutor
│   │   ├── action_parser.py        ActionParser
│   │   ├── approval.py             ApprovalManager
│   │   ├── circuit_breaker.py      OllamaCircuitBreaker
│   │   ├── dual_llm.py             DualLLMVerifier
│   │   └── server.py               ThreadedHTTPServer
│   └── agent/                      Layer 4: Future (placeholder)
├── config/
│   └── config.json                 Central configuration (~300 lines)
├── policy/
│   ├── aiohai_security_policy_v3.0.md   Security policy (injected into LLM context)
│   ├── ha_framework_v3.md               Home Assistant framework prompt
│   └── office_framework_v3.md           Office framework prompt
├── tests/                          Test suite
│   ├── conftest.py                 Shared fixtures
│   ├── test_security.py            96 security unit tests
│   ├── test_startup.py             16 integration tests
│   ├── test_e2e.py                 37 end-to-end pipeline tests
│   ├── test_ha_framework.py        99 smart home framework tests
│   ├── test_office_framework.py    155 Office framework tests
│   ├── test_extraction_verify_p7.py  Architecture verification tests
│   └── test_v510_optimization.py   46 v5.1.0 optimization tests
├── tools/
│   ├── aiohai_cli.py               Management CLI (~1,776 lines)
│   ├── register_devices.py         FIDO2 device registration wizard
│   └── hsm_setup.py                HSM initialization tool
├── web/
│   └── templates/                  FIDO2 approval UI (index.html, register.html)
├── desktop/                        Desktop companion app (Electron + React)
│   ├── package.json                Node.js dependencies and scripts
│   ├── src/main/                   Electron main process (TypeScript)
│   ├── src/renderer/               React UI (TypeScript + CSS)
│   ├── start-aiohai.bat            One-click startup (Windows)
│   └── FIRST_RUN_GUIDE.md          Setup walkthrough
├── setup/
│   └── Setup.ps1                   Windows setup and firewall configuration
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
| 8 | ApprovalManager + SecureExecutor | HMAC tokens, sandboxed execution, input size limits |
| 9 | Nitrokey HSM + FIDO2/WebAuthn | Hardware signing, physical key approval, authenticated endpoints |
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
   # Standard
   python -m aiohai

   # Minimal (no hardware security)
   python -m aiohai --no-hsm --no-fido2

   # Full (with Nitrokey HSM + FIDO2 key)
   # Recommended: use environment variable for PIN
   export AIOHAI_HSM_PIN=YOUR_PIN    # Linux/Mac
   $env:AIOHAI_HSM_PIN = "YOUR_PIN"  # PowerShell
   python -m aiohai --hsm

   # Or interactive prompt (will ask for PIN at startup)
   python -m aiohai --hsm
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

## Server Stack

| Service | Port | URL | Started by |
|---------|------|-----|-----------|
| Open WebUI | 3000 | `http://SERVER_IP:3000` | Docker (auto) |
| AIOHAI Proxy | 11435 | `http://localhost:11435` | `python -m aiohai` |
| Ollama | 11434 | `http://localhost:11434` | Windows service (auto) |
| FIDO2 Approval UI | 8443 | `https://localhost:8443` | AIOHAI proxy (when configured) |

---

## Desktop Companion App

The `desktop/` directory contains an Electron app that serves as a single pane of glass for AIOHAI — chat, approvals, health monitoring, log viewing, and configuration in one window.

**Status:** Phase 1 ChatPanel complete with SSE streaming, markdown rendering, and action card display.

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

### v5.1.0 (Current)

**Security Hardening & Structural Optimization**

- 5 security vulnerabilities closed (FIDO2 endpoint auth, admin registration gating, HSM PIN exposure, input bounds, dead config field)
- 4 correctness bugs fixed (HSM double-hash, authenticator tracking, approval hash, Docker image matching)
- Handler refactored: `HandlerContext` dataclass + `_ACTION_DISPATCH` table
- Orchestrator `start()` decomposed into `_step_*` methods
- `__init__.py` re-exports trimmed: 513 → 90 lines
- 46 new tests covering all changes

### v5.0.0

**Clean Architecture — Monolith Fully Removed**

- All 35 classes extracted into `aiohai/` package (~10,865 lines of real code)
- `proxy/` and `security/` directories deleted — all code in `aiohai/` exclusively
- 42% reduction in total Python lines through deduplication
- Single entry point: `python -m aiohai`
- All tests and tools use canonical `aiohai.*` imports
- Ghost framework entries removed from `ALLOWED_FRAMEWORK_NAMES`

### v4.0.0

**Layered Architecture Refactoring**

- Created `aiohai/` package with Core, Integrations, Proxy, and Agent layers
- Consolidated 24 types into `aiohai/core/types.py`
- Full HSM implementation moved to `aiohai/core/crypto/hsm_bridge.py`
- Original monolith files converted to facade/re-export stubs
- Desktop companion app Phase 1 (ChatPanel with SSE streaming)

### v3.0.2

4 validation fixes: API_QUERY action routing, framework integrity verification, config cleanup, requirements.txt update.

### v3.0.1

8 security fixes, 1 bug fix, 4 optimizations. Net: +234 / -88 lines.

---

## License

See individual source files for license information.
