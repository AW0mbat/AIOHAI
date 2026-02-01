# AIOHAI — AI-Operated Home & Office Intelligence Proxy

**Version 3.0.1** · Security-First LLM Proxy for Local AI Agents

---

## What Is This?

AIOHAI is a security proxy that sits between [Open WebUI](https://github.com/open-webui/open-webui) (or any chat frontend) and a local [Ollama](https://ollama.com) instance. It intercepts every request the LLM makes — file reads, file writes, command execution, API calls, network access — and enforces a comprehensive security policy before anything touches your system.

The proxy was designed for a specific threat model: you're running a capable local LLM with tool-use (agentic) capabilities on the same machine where you live and work. The LLM can read your documents, run commands, query your smart home, and interact with Office files. AIOHAI ensures it can only do what you've explicitly approved, and that every action is logged, auditable, and tamper-evident.

```
┌─────────────┐     ┌──────────────────────────────────┐     ┌─────────┐
│  Open WebUI  │────▶│         AIOHAI Proxy (:11435)     │────▶│  Ollama  │
│  (browser)   │◀────│                                    │◀────│ (:11434) │
└─────────────┘     │  ┌─ StartupSecurityVerifier        │     └─────────┘
                    │  ├─ IntegrityVerifier               │
                    │  ├─ NetworkInterceptor (socket hooks)│
                    │  ├─ ContentSanitizer                │
                    │  ├─ StaticSecurityAnalyzer (Bandit)  │
                    │  ├─ PIIProtector                    │
                    │  ├─ ResourceLimiter (DoS)           │
                    │  ├─ MultiStageDetector              │
                    │  ├─ DualLLMVerifier (optional)      │
                    │  ├─ PathValidator                   │
                    │  ├─ CommandValidator                │
                    │  ├─ ApprovalManager (timing-safe)   │
                    │  ├─ SecureExecutor                  │
                    │  ├─ OllamaCircuitBreaker            │
                    │  └─ SessionTransparencyTracker      │
                    │                                      │
                    │  Optional Integrations:               │
                    │  ├─ Nitrokey HSM 2 (log signing)     │
                    │  ├─ FIDO2/WebAuthn (hardware approval)│
                    │  ├─ Home Assistant + Frigate NVR     │
                    │  └─ Microsoft Office / Graph API     │
                    └──────────────────────────────────────┘
```

---

## File Layout

```
C:\AIOHAI\                          (or $SECURE_LLM_HOME)
├── proxy/
│   └── aiohai_proxy.py             Main proxy (~4,580 lines)
├── security/
│   ├── __init__.py                 Package init
│   ├── security_components.py      Analysis engines (~2,280 lines)
│   └── fido2_approval.py           FIDO2/WebAuthn server & client (~1,290 lines)
├── config/
│   └── config.json                 Central configuration (~295 lines)
├── tests/
│   ├── test_ha_framework.py        Smart home framework tests
│   └── test_office_framework.py    Office framework tests
├── policy/
│   ├── aiohai_security_policy_v3.0.md   Security policy (injected into LLM context)
│   ├── ha_framework_v3.md               Home Assistant framework prompt
│   └── office_framework_v3.md           Office framework prompt
└── logs/                           Runtime logs (created automatically)
```

---

## Security Layers

### Layer 1 — Startup Verification
`StartupSecurityVerifier` runs before the proxy accepts any connections. It checks for admin/root execution (refused by default), verifies environment variables for suspicious overrides (`OLLAMA_OVERRIDE`, `SKIP_SECURITY`, etc.), and validates that the security components module loaded correctly.

### Layer 2 — Integrity Monitoring
`IntegrityVerifier` hashes the proxy source, policy file, and config at startup. A background thread re-checks periodically. If any file is modified at runtime, the proxy enters lockdown mode — all requests return HTTP 503 until restart. When an HSM is connected, the policy file's signature is verified against the hardware key.

### Layer 3 — Network Isolation
`NetworkInterceptor` hooks Python's `socket.socket` at the C level. All outgoing connections are checked against a strict allowlist (default: only `localhost` and `127.0.0.1`). DNS-over-HTTPS servers are explicitly blocked to prevent DNS-based data exfiltration. DNS queries are also checked for tunneling patterns (high entropy, excessive length, deep subdomain nesting).

### Layer 4 — Input Sanitization
`ContentSanitizer` processes every user and LLM message. It strips invisible Unicode characters, normalizes homoglyphs and fullwidth characters, detects prompt injection patterns (role manipulation, fake system tags, jailbreak attempts, anti-transparency instructions), and assigns trust levels to external content.

### Layer 5 — Code & Content Analysis
`StaticSecurityAnalyzer` performs Bandit-style AST analysis on any code the LLM generates before execution. `PIIProtector` scans for SSNs, credit cards, emails, phone numbers, and IP addresses in both inputs and outputs. `CredentialRedactor` catches API keys, tokens, and connection strings.

### Layer 6 — Resource Limiting
`ResourceLimiter` enforces per-session caps on concurrent processes, file operations, total bytes read/written, and session duration. Prevents denial-of-service from a misbehaving model.

### Layer 7 — Path & Command Validation
`PathValidator` blocks access to credential stores (`.ssh`, `.aws`, browser databases, PEM/key files, environment files, SAM/NTDS, Office persistence directories), resolves symlinks and short filenames to prevent path traversal, and blocks UNC paths, NTFS alternate data streams, and device paths. `CommandValidator` blocks encoded PowerShell, credential theft tools, persistence mechanisms, privilege escalation, obfuscated commands, clipboard access, and UAC bypass patterns. Docker commands are classified into tiers (standard/elevated/critical/blocked).

### Layer 8 — Approval & Execution
`ApprovalManager` requires explicit user approval for elevated and critical operations. Approval tokens are timing-safe (HMAC-compared), session-bound, and time-limited (5 min default). `SecureExecutor` runs approved commands in a sanitized subprocess environment (only safe env vars inherited), enforces timeouts, and captures output. Document operations go through `DocumentContentScanner`, `MacroBlocker`, and `MetadataSanitizer`.

### Layer 9 — Hardware Security (Optional)

**Nitrokey HSM 2** — Signs every log entry with a hardware key. Provides tamper-evident audit trails that can't be retroactively altered even by someone with full disk access. Verifies policy file signatures at startup.

**FIDO2/WebAuthn** — For tier-3 operations (financial data, password vaults, crypto wallets), the proxy requires a physical security key tap or biometric confirmation. A built-in HTTPS server (`FIDO2ApprovalServer` on port 8443) serves the approval UI — you can approve from your phone on the same LAN.

### Layer 10 — Transparency & Alerting
`SessionTransparencyTracker` records every action the LLM takes during a session — file reads, file writes, commands executed, API queries. The user can type `REPORT` at any time to see a full summary. `AlertManager` delivers desktop notifications for security events. `HomeAssistantNotificationBridge` can forward alerts to your smart home dashboard.

### Layer 11 — Ollama Resilience
`OllamaCircuitBreaker` prevents thread exhaustion when Ollama is down. After 3 consecutive failures the breaker opens for 60 seconds, immediately rejecting requests instead of blocking threads on the 300-second default timeout.

---

## Domain Integrations

### Smart Home (Home Assistant + Frigate)
`LocalServiceRegistry` maintains an allowlist of local services the LLM can query (Frigate NVR, Home Assistant, the AIOHAI notification bridge). Each service registration verifies the target is actually listening before accepting it. `LocalAPIQueryExecutor` executes queries with PII protection and response size limits. `SmartHomeStackDetector` auto-discovers your Docker-based smart home stack. `SmartHomeConfigAnalyzer` audits docker-compose files for security issues (privileged containers, host networking, missing digest pinning, etc.).

### Microsoft Office
`DocumentContentScanner` scans Office documents (docx, xlsx, pptx and their macro-enabled variants) for PII, credentials, and sensitive content before reads and writes. `MacroBlocker` blocks creation or modification of macro-enabled formats (xlsm, docm, dotm, etc.). `MetadataSanitizer` strips author, revision, and tracking metadata from outgoing documents. `GraphAPIRegistry` provides optional Microsoft Graph API integration with scope enforcement (dangerous scopes like `Mail.Send` are blocked). `DocumentAuditLogger` maintains a separate audit trail for all document operations. `OfficeStackDetector` detects installed Office components.

---

## Configuration

All settings live in `config/config.json`. Key sections:

| Section | What It Controls |
|---|---|
| `proxy` | Listen address, port, rate limits, prompt injection |
| `ollama` | Ollama host, port, model, timeout |
| `security` | Policy file, credential redaction, transparency |
| `hsm` | Nitrokey HSM enable/require/mock/PIN |
| `fido2` | FIDO2 server port, bind address, approval timeout |
| `network` | Socket hooks, allowlist, private IP blocking |
| `dns_security` | Exfiltration detection thresholds |
| `resource_limits` | File ops, concurrent processes, session duration |
| `command_execution` | Timeout, executable allowlist, obfuscation detection |
| `path_security` | Allowed drives, UNC/ADS/symlink/short-name handling |
| `smart_home` | Notification bridge, stack detection, Frigate |
| `office` | Document dirs, Graph API, macro blocking, audit |
| `alerting` | Desktop/sound/email/webhook alerts |
| `logging` | Log directory, chain hashing, retention |

CLI flags override `config.json`, which overrides built-in defaults.

---

## CLI Usage

```bash
python proxy/aiohai_proxy.py [OPTIONS]
```

| Flag | Effect |
|---|---|
| `--listen-port PORT` | Proxy listen port (default: 11435) |
| `--ollama-port PORT` | Ollama backend port (default: 11434) |
| `--base-dir DIR` | Base directory (default: `C:\AIOHAI`) |
| `--policy FILE` | Path to security policy markdown |
| `--enable-dual-llm` | Enable secondary LLM verification |
| `--no-network-control` | Disable socket-level network hooks |
| `--no-file-scan` | Disable file content scanning |
| `--no-hsm` | Disable HSM integration entirely |
| `--hsm-optional` | Start even if HSM is unavailable |
| `--hsm-mock` | Use mock HSM for testing (**no security**) |
| `--hsm-pin PIN` | HSM PIN (prompts interactively if omitted) |
| `--no-fido2` | Disable FIDO2 hardware approval |
| `--fido2-port PORT` | Approval server HTTPS port (default: 8443) |
| `--no-approval-server` | Don't auto-start the FIDO2 web server |
| `--allow-degraded` | Start without security components (not recommended) |

---

## Quick Start

1. Install Ollama and pull a model: `ollama pull llama3.2`
2. Install Open WebUI (or any compatible frontend)
3. Clone this repo into `C:\AIOHAI` (or set `$SECURE_LLM_HOME`)
4. Install Python dependencies: `pip install psutil` (optional, enables resource monitoring)
5. Start the proxy:
   ```bash
   # Minimal (no hardware security)
   python proxy/aiohai_proxy.py --no-hsm --no-fido2

   # Full (with Nitrokey HSM + FIDO2 key)
   python proxy/aiohai_proxy.py --hsm-pin YOUR_PIN
   ```
6. Point Open WebUI's `OLLAMA_BASE_URL` to `http://localhost:11435`
7. Chat normally — the proxy intercepts and secures everything transparently

---

## In-Chat Commands

Type these directly in your chat to interact with the proxy:

| Command | What It Does |
|---|---|
| `APPROVE <id>` | Approve a pending action |
| `DENY <id>` | Deny a pending action |
| `REPORT` | Show full session transparency report |
| `STATUS` | Show proxy and component health |

---

## v3.0.1 Changes (Latest)

This release fixes 8 security issues found in post-audit review, 1 bug, and 4 optimizations. Full details in `CHANGELOG_v3.0.1.md`. Highlights:

**Security fixes:** FIDO2 metadata injection (H-4), session binding bypass (H-5), framework file injection (M-6), Docker image digest verification (M-7), Ollama circuit breaker (M-8), API query transparency tracking (M-9), Docker tier display in approval cards (L-6), service registration port verification (L-7), HSM reconnection failure alerts (L-8).

**Bug fix:** `AlertManager._deliver()` was killing its own thread after one alert. All subsequent security alerts would silently vanish.

**Optimizations:** Duplicate document scan eliminated, duplicate Docker tier logic consolidated, inline extension sets promoted to module constants, dead code removed. Net: +234 / -88 lines across 2 files.

---

## Dependencies

| Package | Required? | Purpose |
|---|---|---|
| Python 3.10+ | Yes | Runtime |
| `psutil` | Recommended | Process/resource monitoring |
| `pywin32` | Optional (Windows) | DLL integrity, file locking |
| `fido2` | Optional | FIDO2/WebAuthn hardware approval |
| `pkcs11` | Optional | Nitrokey HSM integration |

The proxy is designed to degrade gracefully. If optional dependencies are missing, the corresponding features are disabled with a startup warning. Use `--allow-degraded` to start without `security_components.py` entirely (not recommended for production).

---

## Platform Support

Primary target: **Windows 10/11** (the codebase references Windows paths, DLL verification, PowerShell patterns, registry persistence, and Windows-specific credential stores). Linux is partially supported — network interception, content analysis, and Ollama proxying all work, but path patterns and command validation are Windows-centric. The FIDO2 and HSM subsystems are cross-platform.

---

## License

See individual source files for license information.
