# AIOHAI v4.0.0 — Architecture Documentation

## Overview

AIOHAI is a layered security architecture for local AI agents. It sits between a user-facing chat interface (Open WebUI) and a local LLM backend (Ollama), intercepting all traffic to enforce multi-layered security: input sanitization, action approval, execution sandboxing, output filtering, and tamper-evident logging.

The system is designed for a home/small-office deployment where a local LLM agent has real access to the host filesystem, network, and shell — making it a high-value target for prompt injection and privilege escalation.

## Layered Architecture (v4.0.0)

```
┌─────────────────────────────────────────────────────────────┐
│  Companion Apps          Open WebUI         CLI Tools       │
│  (Electron, iOS)         (Browser)          (aiohai_cli)    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     AIOHAI Agent Layer                      │
│     (Future: Screen capture, supervised browsing,           │
│      progressive trust automation)                          │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     AIOHAI Proxy Layer                      │
│     (Action parsing, AI-specific validation,                │
│      approval flow, LLM context injection, execution)       │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   AIOHAI Integrations Layer                 │
│     (Home Assistant, Office/Graph, Frigate adapters)        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                       AIOHAI Core                           │
│  ┌─────────────────┐ ┌─────────────────┐ ┌──────────────┐  │
│  │ Access Control  │ │ Crypto Layer    │ │ Audit Layer  │  │
│  │ - PathValidator │ │ - HSMBridge     │ │ - AccessLog  │  │
│  │ - CommandValid. │ │ - FIDOGate      │ │ - Integrity  │  │
│  │ - SessionMgr    │ │ - Credentials   │ │ - AlertBridge│  │
│  └─────────────────┘ └─────────────────┘ └──────────────┘  │
│  ┌─────────────────┐ ┌─────────────────┐ ┌──────────────┐  │
│  │ Analysis Layer  │ │ Network Layer   │ │ Resources    │  │
│  │ - Sanitizer     │ │ - Interceptor   │ │ - Limiter    │  │
│  │ - PIIProtector  │ │                 │ │              │  │
│  │ - StaticAnalyzer│ │                 │ │              │  │
│  └─────────────────┘ └─────────────────┘ └──────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Package Structure

```
aiohai/
├── __init__.py              # Package root (version 4.0.0)
├── __main__.py              # Entry point: python -m aiohai
│
├── core/                    # Layer 1: Accessor-Agnostic Trust Infrastructure
│   ├── types.py             # 24 consolidated types (enums, dataclasses, exceptions)
│   ├── config.py            # Configuration management
│   │
│   ├── access/              # Access Control
│   │   ├── path_validator.py    # Two-tier path validation
│   │   ├── command_validator.py # Shell command validation
│   │   └── session_manager.py   # Approval queue (ApprovalManager)
│   │
│   ├── crypto/              # Cryptographic Layer
│   │   ├── hsm_bridge.py        # Nitrokey HSM PKCS#11 (FULL IMPLEMENTATION)
│   │   ├── fido_gate.py         # FIDO2/WebAuthn approval
│   │   └── credentials.py       # Credential storage and redaction
│   │
│   ├── audit/               # Audit Layer
│   │   ├── logger.py            # SecurityLogger with chain hashing
│   │   ├── integrity.py         # IntegrityVerifier
│   │   ├── transparency.py      # SessionTransparencyTracker
│   │   └── alerts.py            # AlertManager
│   │
│   ├── analysis/            # Content Analysis
│   │   ├── sanitizer.py         # ContentSanitizer
│   │   ├── pii_protector.py     # PIIProtector
│   │   ├── static_analyzer.py   # StaticSecurityAnalyzer
│   │   └── multi_stage.py       # MultiStageDetector
│   │
│   ├── network/             # Network Security
│   │   └── interceptor.py       # NetworkInterceptor (socket hooks)
│   │
│   └── resources/           # Resource Management
│       └── limiter.py           # ResourceLimiter
│
├── integrations/            # Layer 2: Domain-Specific Adapters
│   ├── smart_home/          # Home Assistant + Frigate
│   │   ├── service_registry.py     # LocalServiceRegistry
│   │   ├── query_executor.py       # LocalAPIQueryExecutor
│   │   ├── config_analyzer.py      # SmartHomeConfigAnalyzer
│   │   ├── stack_detector.py       # SmartHomeStackDetector
│   │   └── notification.py         # HomeAssistantNotificationBridge
│   │
│   └── office/              # Microsoft Office + Graph API
│       ├── document_scanner.py     # DocumentContentScanner
│       ├── macro_blocker.py        # MacroBlocker
│       ├── metadata_sanitizer.py   # MetadataSanitizer
│       ├── graph_registry.py       # GraphAPIRegistry
│       ├── stack_detector.py       # OfficeStackDetector
│       └── audit_logger.py         # DocumentAuditLogger
│
├── proxy/                   # Layer 3: AI-Specific Enforcement
│   ├── orchestrator.py          # UnifiedSecureProxy (main startup)
│   ├── handler.py               # UnifiedProxyHandler (HTTP)
│   ├── action_parser.py         # ActionParser (<action> XML parsing)
│   ├── executor.py              # SecureExecutor
│   ├── circuit_breaker.py       # OllamaCircuitBreaker
│   ├── startup.py               # StartupSecurityVerifier
│   └── dual_llm.py              # DualLLMVerifier
│
└── agent/                   # Layer 4: Future AI Assistant (PLACEHOLDER)
    ├── screen_capture.py        # Screen capture + OCR pipeline
    ├── browser_supervisor.py    # Supervised browsing
    ├── trust_manager.py         # Progressive trust allowlists
    └── vault_accessor.py        # Secure credential retrieval
```

## Component Map

### Core Types (`aiohai/core/types.py`)

All shared types consolidated in one location:

**Exceptions:**
- `SecurityError` — Base exception for security errors
- `NetworkSecurityError` — Network policy violations
- `ResourceLimitExceeded` — Resource limit violations

**Enums:**
- `SecurityLevel` — BLOCKED, CRITICAL, ELEVATED, STANDARD, ALLOWED
- `ActionType` — FILE_READ, FILE_WRITE, FILE_DELETE, COMMAND_EXEC, etc.
- `AlertSeverity` — INFO, WARNING, HIGH, CRITICAL
- `TrustLevel` — TRUSTED, UNTRUSTED, HOSTILE
- `Severity` — LOW, MEDIUM, HIGH, CRITICAL (for static analysis)
- `PIIType` — EMAIL, PHONE, SSN, CREDIT_CARD, etc.
- `Verdict` — SAFE, SUSPICIOUS, DANGEROUS, BLOCKED
- `ApprovalTier` — TIER_1 through TIER_4
- `ApprovalStatus` — PENDING, APPROVED, REJECTED, EXPIRED, CANCELLED
- `UserRole` — ADMIN, TRUSTED_ADULT, RESTRICTED, GUEST
- `HSMStatus` — NOT_INITIALIZED, CONNECTED, DISCONNECTED, etc.

**Dataclasses:**
- `SecurityFinding`, `PIIFinding`, `VerificationResult`, `ResourceLimits`
- `RegisteredCredential`, `RegisteredUser`, `HardwareApprovalRequest`
- `HSMKeyInfo`, `SignedLogEntry`, `PolicyVerificationResult`

### Core Crypto (`aiohai/core/crypto/`)

**`hsm_bridge.py`** — Full implementation of Nitrokey HSM integration:
- `NitrokeyHSMManager` — PKCS#11 interface for signing, verification, random generation
- `MockHSMManager` — Software mock for testing (NO SECURITY)
- `get_hsm_manager()` — Factory function

**`fido_gate.py`** — FIDO2/WebAuthn hardware approval:
- `OperationClassifier` — Classifies operations into Tier 1-4
- `CredentialStore` — On-disk JSON storage of WebAuthn credentials
- `FIDO2ApprovalServer` — Flask HTTPS server
- `FIDO2ApprovalClient` — Client with retry logic

**`credentials.py`** — Credential management:
- `CredentialRedactor` — Strip API keys, passwords from text

### Legacy Files (Facades)

The original files now import from the new locations:

- `proxy/aiohai_proxy.py` — Imports types from `aiohai.core.types`
- `security/security_components.py` — Imports types from `aiohai.core.types`
- `security/fido2_approval.py` — Imports types from `aiohai.core.types`
- `security/hsm_integration.py` — Full facade, reimports from `aiohai.core.crypto.hsm_bridge`

All original import paths continue to work:
```python
# Old (still works)
from security.security_components import PIIProtector

# New (preferred)
from aiohai.core.analysis import PIIProtector
```

## Request Flow

When a POST hits `/api/chat`:

```
1. LOCKDOWN CHECK
   └─ If integrity_verifier.is_locked_down → 503 "Service locked down"

2. PARSE REQUEST
   └─ Read JSON body, extract user message

3. CONTROL COMMAND CHECK
   └─ CONFIRM/REJECT/PENDING/REPORT/STATUS/HELP/STOP/EXPLAIN
   └─ If match → handle internally, don't forward to Ollama

4. INPUT SANITIZATION (ContentSanitizer)
   ├─ Strip invisible Unicode characters
   ├─ Normalize homoglyphs and fullwidth chars
   ├─ Scan for injection patterns
   └─ Assign trust level

5. CIRCUIT BREAKER CHECK
   └─ If breaker open → 503 "Ollama unavailable"

6. FORWARD TO OLLAMA
   └─ Inject policy + framework prompts into system message
   └─ Stream response tokens back

7. RESPONSE PROCESSING (ActionParser)
   └─ Parse <action> blocks from LLM response
   └─ For each action: pre-validate, create approval request

8. APPROVAL FLOW
   └─ Display action cards to user
   └─ Wait for CONFIRM/REJECT (or FIDO2 for Tier 3)

9. EXECUTION (SecureExecutor)
   └─ Static analysis, resource limits, sandboxed subprocess
   └─ Log all actions to SessionTransparencyTracker

10. OUTPUT FILTERING
    └─ PII redaction, credential stripping
    └─ Return result to user
```

## Configuration

### config.json

Located at `config/config.json`. Key settings:

| Setting | Type | Default | Purpose |
|---------|------|---------|---------|
| `listen_port` | int | 11435 | Proxy listen port |
| `ollama_port` | int | 11434 | Ollama backend port |
| `allowed_drives` | list | ["C:"] | Allowed Windows drives |
| `hsm_enabled` | bool | true | Enable HSM integration |
| `fido2_enabled` | bool | true | Enable FIDO2 approval |
| `command_timeout` | int | 30 | Max seconds for command execution |

### CLI Flags

| Flag | Effect |
|------|--------|
| `--listen-port PORT` | Override proxy listen port |
| `--ollama-port PORT` | Override Ollama backend port |
| `--no-hsm` | Disable HSM integration |
| `--no-fido2` | Disable FIDO2/WebAuthn |
| `--hsm-pin PIN` | Provide HSM PIN |
| `--allow-degraded` | Allow startup without security_components |

## Entry Points

**New canonical (v4.0.0):**
```bash
python -m aiohai [OPTIONS]
```

**Old (still works):**
```bash
python proxy/aiohai_proxy.py [OPTIONS]
```

## File Layout

```
AIOHAI/
├── aiohai/                      # NEW: Layered package (55 Python files)
│   ├── core/                    # Trust infrastructure
│   ├── integrations/            # Domain adapters
│   ├── proxy/                   # AI enforcement
│   └── agent/                   # Future capabilities
├── proxy/
│   └── aiohai_proxy.py          # Original proxy (facade)
├── security/
│   ├── security_components.py   # Analysis engines (facade)
│   ├── fido2_approval.py        # FIDO2 (facade)
│   └── hsm_integration.py       # HSM (facade)
├── policy/
│   ├── aiohai_security_policy_v3.0.md
│   ├── ha_framework_v3.md
│   └── office_framework_v3.md
├── config/
│   └── config.json
├── tools/
│   ├── aiohai_cli.py
│   ├── register_devices.py
│   └── hsm_setup.py
├── tests/
├── docs/
│   └── ARCHITECTURE.md          # This file
├── web/
│   └── templates/
├── desktop/                     # Electron companion app
└── README.md
```

## Audit History

| Date | Version | Changes |
|------|---------|---------|
| 2026-01-31 | v3.0.0 | Initial release, 4 phases of security hardening |
| 2026-02-01 | v3.0.1 | 8 security fixes, 1 bug fix, 4 optimizations |
| 2026-02-01 | v3.0.2 | API_QUERY routing, framework integrity, config cleanup |
| 2026-02-03 | v4.0.0 | **Layered architecture refactoring** — Core/Integrations/Proxy/Agent layers, type consolidation, HSM full move, backward-compatible facades |
