# AIOHAI v3.0.2 — Architecture Documentation

## Overview

AIOHAI is a security proxy that sits between a user-facing chat interface (Open WebUI) and a local LLM backend (Ollama). Every request and response passes through the proxy, which enforces a multi-layered security policy: input sanitization, action approval, execution sandboxing, output filtering, and tamper-evident logging.

The system is designed for a home/small-office deployment where a local LLM agent has real access to the host filesystem, network, and shell — making it a high-value target for prompt injection and privilege escalation.

```
┌─────────────┐     ┌──────────────────────────┐     ┌────────────┐
│  Open WebUI  │────▶│  AIOHAI Proxy v3.0.2  │────▶│   Ollama   │
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

This is the main file (~4,760 lines). It contains all proxy logic in a single file for deployment simplicity.

| Class | Purpose | Key Methods |
|-------|---------|-------------|
| `UnifiedConfig` | Dataclass with all configuration fields, defaults, and `__post_init__` path derivation | — |
| `SecurityLogger` | Tamper-evident logging with PII redaction, chain hashing, and optional HSM signing | `log_event()`, `log_action()`, `log_blocked()`, `log_network()` |
| `AlertManager` | Desktop notifications and alert routing | `alert()` |
| `IntegrityVerifier` | SHA-256 monitoring of policy + framework files with lockdown on tampering | `verify_policy()`, `start_monitoring()`, `is_locked_down`, `_hash_frameworks()`, `_verify_frameworks()` |
| `PathValidator` | Two-tier path validation: hard blocks attack infrastructure (~33 patterns), gates sensitive personal data behind Tier 3 (~39 patterns) | `validate(path) → (safe, resolved, reason)` |
| `CommandValidator` | Validates shell commands against blocked patterns, executable whitelist, and obfuscation detection | `validate(cmd) → (safe, reason)` |
| `ContentSanitizer` | Injection scanning: invisible chars, homoglyphs, fullwidth normalization, 40+ injection patterns | `sanitize(content) → (cleaned, warnings, trust_level)` |
| `NetworkInterceptor` | Socket-level hooks on `connect`, `getaddrinfo`, `gethostbyname` with DoH blocking and private IP blocking (including 100.64.0.0/10) | `install_hooks()` |
| `SecureExecutor` | Sandboxed file/command execution with static analysis, resource limits, and multi-stage detection | `read_file()`, `write_file()`, `execute_command()`, `delete_file()` |
| `ApprovalManager` | Human-in-the-loop approval queue with rate limiting and expiry | `create_request()`, `approve()`, `reject()` |
| `ActionParser` | Parses `<action>` blocks from LLM responses | `parse()`, `strip_actions()` |
| `OllamaCircuitBreaker` | Prevents thread exhaustion when Ollama is down (opens after 3 failures for 60s) | `can_request()`, `record_success()`, `record_failure()` |
| `LocalServiceRegistry` | Allowlist of queryable local services with port verification on registration | `register()`, `validate_request()`, `load_from_config()` |
| `LocalAPIQueryExecutor` | Executes queries against registered services with PII protection and transparency tracking | `execute(url, method) → (ok, result)` |
| `DocumentContentScanner` | Scans Office documents for PII, credentials, and dangerous formulas | `scan()`, `get_scan_summary()` |
| `MacroBlocker` | Blocks creation/modification of macro-enabled Office formats | `check_extension()`, `scan_content_for_vba()` |
| `MetadataSanitizer` | Strips author, revision, and tracking metadata from documents | `sanitize()` |
| `GraphAPIRegistry` | Security gateway for Microsoft Graph API: endpoint allow/block, scope enforcement, tier classification | `validate_request(method, endpoint) → (allowed, tier, svc)` |
| `UnifiedProxyHandler` | HTTP request handler (extends `BaseHTTPRequestHandler`) | `do_POST()`, `_handle_chat()`, `_process_response()`, `_execute_approved()` |
| `UnifiedSecureProxy` | Main orchestrator: wires components, runs startup sequence | `start()`, `__init__()` |

### Module-Level Constants

| Constant | Purpose |
|----------|---------|
| `BLOCKED_PATH_PATTERNS` | ~33 regexes for hard-blocked paths (credential stores, system files) |
| `TIER3_PATH_PATTERNS` | ~39 regexes for FIDO2-gated paths (financial, personal, admin) |
| `WHITELISTED_EXECUTABLES` | Code-defined executable allowlist (~40 entries; NOT configurable via config.json) |
| `DOCKER_COMMAND_TIERS` | Docker subcommand classification: standard/elevated/critical/blocked |
| `ALLOWED_FRAMEWORK_NAMES` | Frozenset of allowed framework filenames; shared between `_load_frameworks` and `IntegrityVerifier` |
| `BLOCKED_GRAPH_ENDPOINTS` | Graph API endpoint regexes that are always blocked |
| `BLOCKED_GRAPH_SCOPES` | Graph API scopes that are always blocked (Mail.Send, Directory.ReadWrite.All, etc.) |
| `MACRO_ENABLED_EXTENSIONS` | File extensions that are always blocked for creation/write |
| `OFFICE_SCANNABLE_EXTENSIONS` | File extensions that trigger document content scanning |

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
| `OperationClassifier` | Classifies operations into Tier 1 (auto) / Tier 2 (software) / Tier 3 (hardware) / Tier 4 (admin) |

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
   └─ Check for CONFIRM/REJECT/PENDING/REPORT/STATUS/HELP/STOP/EXPLAIN
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
   └─ Append framework prompts (ha_framework_v3.md, office_framework_v3.md)

6. FORWARD TO OLLAMA
   └─ Circuit breaker check (OllamaCircuitBreaker)
   └─ HTTP POST to localhost:11434 with modified body
   └─ Stream response back

7. RESPONSE PROCESSING (ActionParser + Pre-Approval Validation)
   ├─ Parse <action type="..." target="..."> blocks
   ├─ For each action:
   │   ├─ FILE OPS (READ/WRITE/LIST/DELETE):
   │   │   ├─ PathValidator.validate() → hard blocked → "🚫 Blocked"
   │   │   ├─ Tier 3 path → flag for FIDO2 hardware approval
   │   │   ├─ WRITE: MacroBlocker.check_extension() → blocked → "🚫 Blocked"
   │   │   └─ WRITE: DocumentContentScanner.scan() → PII → escalate to Tier 3
   │   ├─ COMMAND:
   │   │   └─ CommandValidator.validate() → blocked → "🚫 Blocked"
   │   ├─ API_QUERY (local services):
   │   │   └─ LocalServiceRegistry.validate_request() → blocked → "🚫 Blocked"
   │   ├─ API_QUERY (Graph API):
   │   │   └─ GraphAPIRegistry.validate_request() → blocked/tier classification
   │   │   └─ TIER_3 Graph ops → flag for FIDO2 hardware approval
   │   ├─ Create approval request (ApprovalManager)
   │   ├─ Check sensitivity (SensitiveOperationDetector)
   │   ├─ Check credentials in content (CredentialRedactor)
   │   ├─ Format action card with CONFIRM/REJECT/EXPLAIN
   │   └─ If TIER 3 → show "🔐 Hardware Approval Required"
   └─ Append summary table if multiple actions

8. APPROVAL EXECUTION (on CONFIRM)
   ├─ FIDO2 hardware approval if tier3_required
   ├─ DualLLMVerifier check (if enabled)
   ├─ COMMAND → SecureExecutor.execute_command()
   │   ├─ CommandValidator.validate() (defense in depth)
   │   ├─ StaticSecurityAnalyzer.analyze() (for code)
   │   ├─ ResourceLimiter.check()
   │   ├─ Sanitized subprocess environment (SAFE_ENV_VARS only)
   │   └─ Timeout enforcement
   ├─ READ → SecureExecutor.read_file()
   ├─ WRITE → SecureExecutor.write_file()
   │   └─ MacroBlocker → DocumentContentScanner → MetadataSanitizer → DocumentAuditLogger
   ├─ LIST → SecureExecutor.list_directory()
   ├─ DELETE → SecureExecutor.delete_file()
   ├─ API_QUERY (local) → LocalAPIQueryExecutor.execute()
   │   └─ Registry re-validation → HTTP request → PII redaction → transparency tracking
   ├─ API_QUERY (Graph) → GraphAPIRegistry.validate_request() → HTTP request
   │   └─ Re-validation → PII redaction → transparency tracking
   ├─ MultiStageDetector.record() (track action chains)
   ├─ Log result (SecurityLogger with chain hash + optional HSM signature)
   └─ Return result to user
```


## Startup Sequence

The `start()` method runs numbered steps. The proxy refuses to start if critical components fail.

| Step | Component | Failure Behavior |
|------|-----------|------------------|
| Pre-check | Security components import | `sys.exit(1)` unless `--allow-degraded` |
| 0 | HSM initialization | `SecurityError` if `hsm_required=True` and unavailable |
| 1 | Logging setup | Always succeeds (creates directories) |
| 2 | Policy loading (SHA-256 hash) + Framework hashing | Warning if policy missing; framework files hashed via `IntegrityVerifier._hash_frameworks()` |
| 3 | Policy HSM verification | `sys.exit(1)` if HSM required and verification fails |
| 4 | Network interceptor hooks | Always succeeds |
| 5 | Integrity monitoring (10s) | Monitors policy AND framework files; lockdown on any modification or deletion |
| 6 | FIDO2 server + credentials | Warning if init fails, continues without hardware approval |
| 7 | Handler configuration | Wires all components to the HTTP handler class attributes (including `api_query_executor` and `graph_api_registry`) |
| 8 | HTTP server bind + listen | `serve_forever()` — blocks until Ctrl+C |


## Security Layers

Each layer mitigates a specific class of attack:

| # | Layer | Mitigates | Component |
|---|-------|-----------|-----------|
| 1 | Input sanitization | Prompt injection, invisible char attacks, homoglyph substitution | `ContentSanitizer` |
| 2 | Path validation | Hard blocks attack infrastructure; gates sensitive personal data behind Tier 3 hardware approval | `PathValidator` + `BLOCKED_PATH_PATTERNS` + `TIER3_PATH_PATTERNS` |
| 3 | Command validation | Arbitrary code execution, encoded payloads, persistence mechanisms | `CommandValidator` + `BLOCKED_COMMAND_PATTERNS` |
| 4 | Static analysis | Malicious code in file writes (eval, exec, subprocess, network) | `StaticSecurityAnalyzer` |
| 5 | Network hooks | Data exfiltration, C2 callbacks, DNS tunneling, DoH bypass, mesh VPN escape (Tailscale 100.64.0.0/10) | `NetworkInterceptor` |
| 6 | Human approval | All actions require explicit human confirmation | `ApprovalManager` + `UnifiedProxyHandler` |
| 7 | FIDO2 hardware | Tier 3 ops (DELETE, financial data, password vaults, critical Graph API) require physical device tap | `FIDO2ApprovalServer` + WebAuthn |
| 8 | HSM signing | Policy integrity, log tamper evidence, secure random generation | `NitrokeyHSMManager` |
| 9 | Integrity monitoring | Runtime policy/framework tampering → automatic lockdown (10s interval) | `IntegrityVerifier` (monitors policy + all `ALLOWED_FRAMEWORK_NAMES` files) |
| 10 | Credential redaction | Prevents secrets from appearing in action previews or logs | `CredentialRedactor` + `PIIProtector` |
| 11 | Multi-stage detection | Tracks LIST→READ→WRITE→DELETE chains as potential attacks | `MultiStageDetector` |
| 12 | Environment sanitization | Prevents env var leakage (API keys, tokens) to subprocesses | `SAFE_ENV_VARS` whitelist |
| 13 | API query isolation | Local service queries validated against registry; Graph API validated against scope/endpoint rules | `LocalServiceRegistry` + `GraphAPIRegistry` |
| 14 | Document security | Macro blocking, PII scanning, metadata stripping, formula safety, audit trail | `MacroBlocker` + `DocumentContentScanner` + `MetadataSanitizer` + `DocumentAuditLogger` |


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

**Note:** The executable whitelist (`WHITELISTED_EXECUTABLES`) is a code-level constant and is intentionally NOT configurable via config.json. This prevents config tampering from weakening command security.


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
- **Mitigation**: Command whitelist (only ~40 executables, PowerShell removed), two-tier path security (~33 hard blocks + ~39 Tier 3 hardware-gated), obfuscation detection, multi-stage attack tracking, mandatory human approval for ALL actions, FIDO2 hardware approval for destructive and sensitive ops.

### 5. Credential Leakage
- **Risk**: API keys and secrets in config/memory leak to attackers
- **Mitigation**: `CredentialRedactor` strips 15+ credential patterns from previews. `PIIProtector` strips PII from logs. Environment sanitization blocks SECRET/TOKEN/KEY vars from subprocesses. Hard path blocking prevents reading infrastructure secrets (.ssh, .aws, .env, browser credential DBs). Tier 3 hardware gating protects personal sensitive data (password vaults, financial files) — accessible only with physical key tap.

### 6. Framework Prompt Tampering
- **Risk**: Attacker modifies framework file to inject instructions into LLM context
- **Mitigation**: `IntegrityVerifier` hashes all framework files in `ALLOWED_FRAMEWORK_NAMES` at startup alongside the policy file. Any modification or deletion triggers lockdown (HTTP 503). `_load_frameworks` enforces the same allowlist, preventing rogue files from being loaded.

### 7. Mesh VPN Escape (Tailscale)
- **Risk**: LLM uses Tailscale to reach devices on other machines in the user's network
- **Mitigation**: `NetworkInterceptor` hard-blocks the entire 100.64.0.0/10 CGNAT range at the socket level. Security policy (Section 8.5) blocks `tailscale up/down/set` commands and config file access. `tailscale status` (read-only) is the only allowed Tailscale command.


## File Layout

```
AIOHAI/
├── proxy/
│   └── aiohai_proxy.py              # Main proxy (~4,760 lines)
├── security/
│   ├── __init__.py
│   ├── security_components.py       # Analysis engines (~2,280 lines)
│   ├── fido2_approval.py            # FIDO2/WebAuthn server & client (~1,290 lines)
│   └── hsm_integration.py           # Nitrokey HSM PKCS#11 interface (~1,045 lines)
├── policy/
│   ├── aiohai_security_policy_v3.0.md  # Security policy injected into LLM
│   ├── ha_framework_v3.md              # Home Assistant framework prompt
│   └── office_framework_v3.md          # Microsoft Office framework prompt
├── config/
│   └── config.json                  # Central configuration (~305 lines)
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
| 2026-02-01 | v3.0.2 | V-1: API_QUERY action routing (wired LocalAPIQueryExecutor + GraphAPIRegistry into pipeline). V-2: Framework integrity verification (IntegrityVerifier hashes framework files, ALLOWED_FRAMEWORK_NAMES constant). V-3: Config whitelist cleanup (removed powershell, synced to code). V-4: Optional Office dependencies documented. Framework prompts (ha_framework_v3.md, office_framework_v3.md) created and validated. README, ARCHITECTURE.md, and project context updated. |
