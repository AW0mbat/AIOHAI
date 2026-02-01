# AIOHAI v3.0.1 — Architecture Documentation

## Overview

AIOHAI is a security proxy that sits between a user-facing chat interface (Open WebUI) and a local LLM backend (Ollama). Every request and response passes through the proxy, which enforces a multi-layered security policy: input sanitization, action approval, execution sandboxing, output filtering, and tamper-evident logging.

The system is designed for a home/small-office deployment where a local LLM agent has real access to the host filesystem, network, and shell — making it a high-value target for prompt injection and privilege escalation.

```
┌─────────────┐     ┌──────────────────────────┐     ┌────────────┐
│  Open WebUI  │────▶│  AIOHAI Proxy v3.0.1  │────▶│   Ollama   │
│  (Browser)   │◀────│   localhost:11435         │◀────│   :11434   │
└─────────────┘     └────────────┬─────────────┘     └────────────┘
                                 │
                    ┌────────────┼────────────┐
                    ▼            ▼            ▼
              ┌──────────┐ ┌──────────┐ ┌──────────┐
              │   HSM    │ │  FIDO2   │ │  Policy  │
              │ Nitrokey │ │  Server  │ │  Engine  │
              └──────────┘ └──────────┘ └──────────┘
```


## Component Map

### Core Proxy (`proxy/aiohai_proxy.py`)

This is the main file (~4,580 lines). It contains all proxy logic in a single file for deployment simplicity.

| Class | Purpose | Key Methods |
|-------|---------|-------------|
| `UnifiedConfig` | Dataclass with all configuration fields, defaults, and `__post_init__` path derivation | — |
| `SecurityLogger` | Tamper-evident logging with PII redaction, chain hashing, and optional HSM signing | `log_event()`, `log_action()`, `log_blocked()`, `log_network()` |
| `AlertManager` | Desktop notifications and alert routing | `alert()` |
| `IntegrityVerifier` | SHA-256 policy file monitoring with lockdown on tampering | `verify_policy()`, `start_monitoring()`, `is_locked_down` |
| `PathValidator` | Two-tier path validation: hard blocks attack infrastructure (~33 patterns), gates sensitive personal data behind Tier 3 (~39 patterns) | `validate(path) → (safe, resolved, reason)` |
| `CommandValidator` | Validates shell commands against blocked patterns, executable whitelist, and obfuscation detection | `validate(cmd) → (safe, reason)` |
| `ContentSanitizer` | Injection scanning: invisible chars, homoglyphs, fullwidth normalization, 40+ injection patterns | `sanitize(content) → (cleaned, warnings, trust_level)` |
| `NetworkInterceptor` | Socket-level hooks on `connect`, `getaddrinfo`, `gethostbyname` with DoH blocking | `install_hooks()` |
| `SecureExecutor` | Sandboxed file/command execution with static analysis, resource limits, and multi-stage detection | `read_file()`, `write_file()`, `execute_command()`, `delete_file()` |
| `ApprovalManager` | Human-in-the-loop approval queue with rate limiting and expiry | `create_request()`, `approve()`, `reject()` |
| `ActionParser` | Parses `<ACTION>` blocks from LLM responses | `parse()`, `strip_actions()` |
| `OllamaCircuitBreaker` | Prevents thread exhaustion when Ollama is down (opens after 3 failures for 60s) | `can_request()`, `record_success()`, `record_failure()` |
| `LocalServiceRegistry` | Allowlist of queryable local services with port verification on registration | `register()`, `lookup()`, `load_from_config()` |
| `LocalAPIQueryExecutor` | Executes queries against registered services with PII protection and transparency tracking | `execute()` |
| `DocumentContentScanner` | Scans Office documents for PII, credentials, and dangerous formulas | `scan()`, `get_scan_summary()` |
| `MacroBlocker` | Blocks creation/modification of macro-enabled Office formats | `check_extension()`, `scan_content_for_vba()` |
| `MetadataSanitizer` | Strips author, revision, and tracking metadata from documents | `sanitize()` |
| `UnifiedProxyHandler` | HTTP request handler (extends `BaseHTTPRequestHandler`) | `do_POST()`, `_handle_chat()` |
| `UnifiedSecureProxy` | Main orchestrator: wires components, runs 8-step startup | `start()`, `__init__()` |

### Security Components (`security/security_components.py`)

| Class | Purpose |
|-------|---------|
| `StaticSecurityAnalyzer` | Bandit-style static analysis of code in file writes |
| `ResourceLimiter` | Tracks concurrent processes, file ops, session duration |
| `MultiStageDetector` | Detects reconnaissance → weaponization → execution chains |
| `PIIProtector` | Redacts emails, SSNs, phone numbers, IPs from log entries |
| `DualLLMVerifier` | Sends actions to a second LLM for independent safety assessment |
| `CredentialRedactor` | Strips API keys, passwords, private keys, connection strings from previews |
| `SensitiveOperationDetector` | Flags operations on sensitive targets (financial, personal) |
| `SessionTransparencyTracker` | Records all actions (including API queries) for the `REPORT` command |
| `SmartHomeConfigAnalyzer` | Validates Home Assistant / Frigate YAML configs |
| `HomeAssistantNotificationBridge` | Forwards security alerts to Home Assistant dashboard |
| `SmartHomeStackDetector` | Auto-discovers Docker-based smart home stack |
| `OfficeStackDetector` | Detects installed Office components |
| `DocumentAuditLogger` | Maintains a separate audit trail for document operations |

### FIDO2/WebAuthn (`security/fido2_approval.py`)

| Class | Purpose |
|-------|---------|
| `CredentialStore` | On-disk JSON storage of WebAuthn credentials per user |
| `FIDO2ApprovalServer` | Flask HTTPS server for phone-based approval via Face ID / Nitrokey NFC |
| `FIDO2ApprovalClient` | Client with retry logic and SSL cert pinning for proxy ↔ server communication |
| `OperationClassifier` | Classifies operations into Tier 1 (auto) / Tier 2 (software) / Tier 3 (hardware) |

### HSM Integration (`security/hsm_integration.py`)

| Class | Purpose |
|-------|---------|
| `NitrokeyHSMManager` | PKCS#11 interface to Nitrokey HSM for signing and verification |
| `MockHSMManager` | Software mock for testing (no actual security) |
| `get_hsm_manager()` | Factory function returning the appropriate manager |


## Request Flow

When a POST hits `/api/chat`, here is what happens step by step:

```
1. LOCKDOWN CHECK
   └─ If integrity_verifier.is_locked_down → 503 "Service locked down"

2. PARSE REQUEST
   └─ Read Content-Length, parse JSON body
   └─ Extract user message from data['prompt'] or data['messages'][-1]

3. CONTROL COMMAND CHECK
   └─ Check for CONFIRM/REJECT/PENDING/REPORT/STATUS/HELP/STOP
   └─ If match → handle internally, return without forwarding to Ollama

4. INPUT SANITIZATION (ContentSanitizer)
   ├─ Strip invisible Unicode characters (zero-width spaces, BOM, etc.)
   ├─ Normalize Cyrillic homoglyphs → Latin equivalents
   ├─ Normalize fullwidth Unicode → ASCII
   ├─ Scan for 40+ injection patterns
   ├─ Detect obfuscation (base64, hex escapes, decode functions)
   └─ Assign trust level: TRUSTED / UNTRUSTED / HOSTILE
       └─ If HOSTILE → log + wrap input with injection warning frame

5. SYSTEM PROMPT INJECTION
   └─ Prepend security policy to the conversation context
   └─ Inject AGENTIC_INSTRUCTIONS for action format

6. FORWARD TO OLLAMA
   └─ HTTP POST to localhost:11434 with modified body
   └─ Stream response back

7. RESPONSE PROCESSING (ActionParser + Pre-Approval Validation)
   ├─ Parse <ACTION type="..." target="..."> blocks
   ├─ For each action:
   │   ├─ PRE-APPROVAL PATH VALIDATION:
   │   │   ├─ Hard blocked (SSH, .env, system) → immediate "🚫 Blocked" to user
   │   │   ├─ Tier 3 required (financial, passwords) → flag for FIDO2 hardware approval
   │   │   └─ Normal → standard tier classification
   │   ├─ PRE-APPROVAL COMMAND VALIDATION:
   │   │   └─ Blocked patterns → immediate "🚫 Blocked" to user
   │   ├─ Create approval request (ApprovalManager)
   │   ├─ Check sensitivity (SensitiveOperationDetector)
   │   ├─ Check credentials in content (CredentialRedactor)
   │   ├─ Format action card with CONFIRM/REJECT/EXPLAIN
   │   └─ If TIER 3 (DELETE, financial, passwords) → show "🔐 Hardware Approval Required"
   └─ Append summary table if multiple actions

8. APPROVAL EXECUTION (on CONFIRM)
   ├─ PathValidator.validate() → redundant safety check (defense in depth)
   ├─ CommandValidator.validate() → whitelist check, pattern check, obfuscation check
   ├─ StaticSecurityAnalyzer.analyze() → Bandit-style scan of code being written
   ├─ ResourceLimiter.check() → enforce concurrency and size limits
   ├─ MultiStageDetector.record() → track for reconnaissance patterns
   ├─ Execute via SecureExecutor
   ├─ Log result (SecurityLogger with chain hash + optional HSM signature)
   └─ Return result to user
```


## Startup Sequence

The `start()` method runs 8 numbered steps. The proxy refuses to start if critical components fail.

| Step | Component | Failure Behavior |
|------|-----------|------------------|
| Pre-check | Security components import | `sys.exit(1)` unless `--allow-degraded` |
| 0 | HSM initialization | `SecurityError` if `hsm_required=True` and unavailable |
| 1 | Logging setup | Always succeeds (creates directories) |
| 2 | Policy loading (SHA-256 hash) | Warning if missing, continues |
| 3 | Policy HSM verification | `sys.exit(1)` if HSM required and verification fails |
| 4 | Network interceptor hooks | Always succeeds |
| 5 | Integrity monitoring (10s) | Always succeeds; HSM health monitor starts here if HSM active |
| 6 | FIDO2 server + credentials | Warning if init fails, continues without hardware approval |
| 7 | Handler configuration | Wires all components to the HTTP handler class attributes |
| 8 | HTTP server bind + listen | `serve_forever()` — blocks until Ctrl+C |


## Security Layers

Each layer mitigates a specific class of attack:

| # | Layer | Mitigates | Component |
|---|-------|-----------|-----------|
| 1 | Input sanitization | Prompt injection, invisible char attacks, homoglyph substitution | `ContentSanitizer` |
| 2 | Path validation | Hard blocks attack infrastructure; gates sensitive personal data behind Tier 3 hardware approval | `PathValidator` + `BLOCKED_PATH_PATTERNS` + `TIER3_PATH_PATTERNS` |
| 3 | Command validation | Arbitrary code execution, encoded payloads, persistence mechanisms | `CommandValidator` + `BLOCKED_COMMAND_PATTERNS` |
| 4 | Static analysis | Malicious code in file writes (eval, exec, subprocess, network) | `StaticSecurityAnalyzer` |
| 5 | Network hooks | Data exfiltration, C2 callbacks, DNS tunneling, DoH bypass | `NetworkInterceptor` |
| 6 | Human approval | All destructive actions require explicit human confirmation | `ApprovalManager` + `UnifiedProxyHandler` |
| 7 | FIDO2 hardware | Tier 3 ops (DELETE, financial data, password vaults, admin) require physical device tap | `FIDO2ApprovalServer` + WebAuthn |
| 8 | HSM signing | Policy integrity, log tamper evidence, secure random generation | `NitrokeyHSMManager` |
| 9 | Integrity monitoring | Runtime policy tampering → automatic lockdown (10s interval) | `IntegrityVerifier` |
| 10 | Credential redaction | Prevents secrets from appearing in action previews or logs | `CredentialRedactor` + `PIIProtector` |
| 11 | Multi-stage detection | Tracks LIST→READ→WRITE→DELETE chains as potential attacks | `MultiStageDetector` |
| 12 | Environment sanitization | Prevents env var leakage (API keys, tokens) to subprocesses | `SAFE_ENV_VARS` whitelist |


## Configuration Reference

### UnifiedConfig Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `listen_host` | str | `"127.0.0.1"` | Proxy bind address (MUST be localhost) |
| `listen_port` | int | `11435` | Proxy listen port |
| `ollama_host` | str | `"127.0.0.1"` | Ollama backend address |
| `ollama_port` | int | `11434` | Ollama backend port |
| `base_dir` | Path | `C:\AIOHAI` | Installation root |
| `policy_file` | Path | `{base_dir}/policy/...` | Security policy markdown |
| `policy_signature_file` | Path | `{base_dir}/policy/policy.sig` | HSM signature of policy |
| `refuse_admin` | bool | `True` | Refuse to run as administrator/root |
| `inject_system_prompt` | bool | `True` | Inject security policy into LLM context |
| `scan_for_injection` | bool | `True` | Enable input injection scanning |
| `enforce_network_allowlist` | bool | `True` | Enable socket-level network control |
| `scan_file_content` | bool | `True` | Enable static analysis on file writes |
| `enable_dual_llm` | bool | `False` | Enable second-LLM verification |
| `allow_degraded_security` | bool | `False` | Allow startup without security_components.py |
| `hsm_enabled` | bool | `True` | Enable HSM integration |
| `hsm_required` | bool | `True` | Refuse to start without HSM hardware |
| `hsm_use_mock` | bool | `False` | Use software mock (NO SECURITY) |
| `hsm_pin` | str | `""` | HSM PIN for auto-login |
| `fido2_enabled` | bool | `True` | Enable FIDO2 hardware approval |
| `fido2_server_port` | int | `8443` | Approval server HTTPS port |
| `fido2_server_host` | str | `"0.0.0.0"` | Approval server bind (LAN access for phones) |
| `fido2_auto_start_server` | bool | `True` | Auto-start approval server with proxy |
| `command_timeout` | int | `30` | Max seconds for command execution |
| `max_file_size_mb` | int | `100` | Max file size for read/write |
| `rate_limit_per_minute` | int | `60` | Max requests per minute |
| `max_concurrent_actions` | int | `5` | Max concurrent pending actions (×2 = max queue) |


### CLI Flags

| Flag | Effect |
|------|--------|
| `--listen-port PORT` | Override proxy listen port |
| `--ollama-port PORT` | Override Ollama backend port |
| `--base-dir PATH` | Override installation directory |
| `--policy PATH` | Override policy file path |
| `--enable-dual-llm` | Enable Dual-LLM verification |
| `--no-network-control` | Disable network interception |
| `--no-file-scan` | Disable static analysis on writes |
| `--no-hsm` | Disable HSM integration entirely |
| `--hsm-optional` | Allow startup without HSM hardware |
| `--hsm-mock` | Use software mock HSM (testing only) |
| `--hsm-pin PIN` | Provide HSM PIN (avoids interactive prompt) |
| `--no-fido2` | Disable FIDO2/WebAuthn |
| `--fido2-port PORT` | Override FIDO2 server port |
| `--no-approval-server` | Don't auto-start the approval web server |
| `--allow-degraded` | Allow startup without security_components.py |


## Known Attack Surfaces and Mitigations

Based on analysis of real-world AI agent security breaches:

### 1. Exposed Admin Panels
- **Risk**: Proxy exposed to internet without authentication
- **Mitigation**: Proxy binds `127.0.0.1` by default. FIDO2 server binds `0.0.0.0` for LAN phone access but internal API requires `X-AIOHAI-Secret` (256-bit, timing-safe comparison).

### 2. Prompt Injection via Untrusted Content
- **Risk**: Malicious instructions in documents/emails hijack the agent
- **Mitigation**: `ContentSanitizer` strips invisible chars, normalizes homoglyphs, detects 40+ injection patterns, flags obfuscation. Hostile input is framed with warnings. Trust levels (TRUSTED/UNTRUSTED/HOSTILE) propagate through the pipeline.

### 3. Reverse Proxy Authentication Bypass
- **Risk**: Misconfigured nginx/Caddy makes external traffic appear as localhost
- **Mitigation**: No `X-Forwarded-For` or `X-Real-IP` trust in the codebase. FIDO2 API authenticates via shared secret, not IP address. Timing-safe comparison via `hmac.compare_digest`.

### 4. Excessive System Privileges
- **Risk**: Full shell access allows device takeover from a single prompt
- **Mitigation**: Command whitelist (only ~35 executables), two-tier path security (~33 hard blocks + ~39 Tier 3 hardware-gated), obfuscation detection, multi-stage attack tracking, mandatory human approval for ALL actions, FIDO2 hardware approval for destructive and sensitive ops.

### 5. Credential Leakage
- **Risk**: API keys and secrets in config/memory leak to attackers
- **Mitigation**: `CredentialRedactor` strips 15+ credential patterns from previews. `PIIProtector` strips PII from logs. Environment sanitization blocks SECRET/TOKEN/KEY vars from subprocesses. Hard path blocking prevents reading infrastructure secrets (.ssh, .aws, .env, browser credential DBs). Tier 3 hardware gating protects personal sensitive data (password vaults, financial files) — accessible only with physical key tap.


## File Layout

```
AIOHAI/
├── proxy/
│   └── aiohai_proxy.py              # Main proxy (~4,580 lines)
├── security/
│   ├── __init__.py
│   ├── security_components.py       # Analysis engines (~2,280 lines)
│   ├── fido2_approval.py            # FIDO2/WebAuthn server & client (~1,290 lines)
│   └── hsm_integration.py           # Nitrokey HSM PKCS#11 interface
├── policy/
│   └── aiohai_security_policy_v3.0.md  # Security policy injected into LLM
├── config/
│   └── config.json                  # Reference configuration
├── tools/
│   ├── aiohai_cli.py                # Management CLI
│   ├── register_devices.py          # FIDO2 device registration wizard
│   └── hsm_setup.py                 # HSM initialization tool
├── tests/
│   ├── conftest.py                  # Shared fixtures
│   ├── test_security.py             # Security unit tests
│   ├── test_startup.py              # Integration tests
│   ├── test_e2e.py                  # End-to-end pipeline tests
│   ├── test_ha_framework.py         # Smart home framework tests
│   └── test_office_framework.py     # Office framework tests
├── docs/
│   └── ARCHITECTURE.md              # This file
├── web/
│   ├── __init__.py
│   └── templates/
│       ├── index.html               # FIDO2 approval UI
│       └── register.html            # Device registration UI
├── setup/
│   └── Setup.ps1                    # Windows installer script
├── README.md
└── requirements.txt
```


## Audit History

| Date | Phase | Changes |
|------|-------|---------|
| 2026-01-31 | Phase 1 | Fixed 5 blocking bugs: HSM init, missing method, undefined attrs, import error, bare excepts |
| 2026-01-31 | Phase 2 | SSL verification on FIDO2 client, integrity lockdown, HSM health monitor, fail-secure defaults, approval retry/persistence |
| 2026-01-31 | Phase 3 | Removed 879 lines dead code, extracted constants, decomposed long functions, added type hints, fixed config duplication |
| 2026-01-31 | Phase 4 | Test suite (150+ cases), integration tests, this architecture document |
| 2026-02-01 | v3.0.1 | 8 security fixes (H-4, H-5, M-6–M-9, L-6–L-8), AlertManager thread-death bug fix, 4 optimizations, README |
