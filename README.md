# AIOHAI v3.0 — All-In-One Home AI

## What Is This?

AIOHAI is a **security layer** that sits between you and a local AI assistant (like ChatGPT, but running on your own computer). It lets the AI help you with tasks on your computer — setting up smart home devices, organizing files, running commands — while **protecting your sensitive data** from being misused or leaked.

Unlike a simple chatbot, AIOHAI gives the AI *real access* to your filesystem and shell. That power is useful but dangerous, so AIOHAI wraps it in multiple layers of protection: human-in-the-loop approval, hardware security keys, tamper-evident logging, prompt injection defense, and automatic lockdown if someone tries to modify its rules.

### Why Do You Need This?

When you give an AI assistant access to your computer, it can potentially:
- Read your passwords and financial files
- Send your private data to external servers
- Delete important files
- Install malicious software
- Be hijacked by malicious instructions hidden in documents it reads

AIOHAI prevents all of this by:
- ✅ **Asking your permission** before every action (tiered by risk)
- ✅ **Requiring a physical security key tap** for destructive operations
- ✅ **Blocking access** to sensitive files (passwords, bank data, tax returns)
- ✅ **Hiding credentials** so they never appear on screen
- ✅ **Detecting prompt injection** attacks in real time
- ✅ **Cryptographically signing** every log entry with hardware
- ✅ **Locking down automatically** if its policy file is tampered with
- ✅ **Showing you exactly** what the AI accessed (transparency reports)
- ✅ **Blocking dangerous commands** and network connections automatically

---

## Who Is This For?

This is designed for **families running a home server** who want AI assistance with:
- 🏠 Smart home setup (Home Assistant, cameras, automation)
- 📁 File organization and management
- 💻 System administration tasks
- 📧 Email and document processing

**You don't need to be a programmer**, but you should be comfortable:
- Running commands in a terminal/PowerShell window
- Installing software on your computer
- Basic understanding of what a "server" is

---

## Architecture Overview

```
┌─────────────┐     ┌──────────────────────────────────┐     ┌────────────┐
│  Open WebUI  │────▶│       AIOHAI Proxy v3.0          │────▶│   Ollama   │
│  (Browser)   │◀────│       localhost:11435             │◀────│   :11434   │
└─────────────┘     └───────┬──────────┬────────────────┘     └────────────┘
                            │          │
               ┌────────────┘          └────────────┐
               ▼                                    ▼
        ┌─────────────┐                   ┌─────────────────┐
        │  Nitrokey    │                   │  FIDO2 Server   │
        │  HSM 2       │                   │  (HTTPS :8443)  │
        │  (USB)       │                   └────────┬────────┘
        │              │                            │
        │ • Log signing│                   ┌────────┴────────┐
        │ • Policy sig │                   │  Phone / Key    │
        │ • Tamper     │                   │  (Face ID,      │
        │   evidence   │                   │   Nitrokey NFC, │
        └──────────────┘                   │   YubiKey)      │
                                           └─────────────────┘
```

AIOHAI sits between your chat interface and the AI engine. Every request and response passes through it. The proxy never exposes itself to the network — it binds to `127.0.0.1` only.

Two optional hardware components add physical security:
- **Nitrokey HSM 2** — Signs log entries and the security policy. If someone modifies a log after the fact, the signature won't match. If someone modifies the policy file, the proxy detects it within 10 seconds and locks down.
- **FIDO2 Security Key / Phone** — For high-risk operations (file deletion, sensitive writes), the proxy won't proceed until you physically tap a security key or approve via Face ID on your phone over the local network.

---

## Security Layers

AIOHAI uses 12 defense layers. Each one mitigates a specific class of attack:

| # | Layer | What It Stops |
|---|-------|---------------|
| 1 | **Input Sanitization** | Prompt injection, invisible Unicode attacks, homoglyph substitution |
| 2 | **Path Validation** | Access to credentials, system files, financial data (~60 blocked patterns) |
| 3 | **Command Validation** | Arbitrary code execution, encoded payloads, persistence mechanisms |
| 4 | **Static Analysis** | Malicious code hidden in file writes (eval, exec, subprocess, network calls) |
| 5 | **Network Hooks** | Data exfiltration, C2 callbacks, DNS tunneling, DNS-over-HTTPS bypass |
| 6 | **Human Approval** | All actions require explicit confirmation before execution |
| 7 | **FIDO2 Hardware Approval** | Destructive ops (DELETE, admin commands) require physical key tap |
| 8 | **HSM Log Signing** | Tamper-evident audit trail — every log entry is cryptographically signed |
| 9 | **Integrity Monitoring** | Policy file tampering → automatic lockdown within 10 seconds |
| 10 | **Credential Redaction** | API keys, passwords, private keys never shown in action previews or logs |
| 11 | **Multi-Stage Detection** | Tracks LIST→READ→WRITE→DELETE reconnaissance chains |
| 12 | **Environment Sanitization** | Blocks SECRET/TOKEN/KEY env vars from leaking to subprocesses |

---

## Tiered Approval System

Not every action is equally dangerous. AIOHAI classifies operations into three tiers:

| Tier | Risk Level | Approval Method | Examples |
|------|------------|----------------|----------|
| **Tier 1** | Low | Automatic (no prompt) | List directory, read file metadata |
| **Tier 2** | Medium | Software approval (type CONFIRM in chat) | Read file, write non-sensitive file, run whitelisted command |
| **Tier 3** | High | Hardware approval (tap security key or Face ID) | Delete file, write to sensitive path, bulk operations, admin commands |

Tier 3 approval opens a page on the FIDO2 server (HTTPS on your LAN) where you can review the operation details and approve with your phone's biometric or a physical NFC tap on a Nitrokey / YubiKey.

---

## Prerequisites

### Required

| Component | Purpose | Install |
|-----------|---------|---------|
| **Python 3.8+** | Runtime | [python.org/downloads](https://www.python.org/downloads/) |
| **Ollama** | AI engine | [ollama.com/download](https://ollama.com/download) |
| **An AI model** | The "brain" | `ollama pull llama3.2` |

### Recommended

| Component | Purpose | Install |
|-----------|---------|---------|
| **Open WebUI** | Chat interface | `docker run -d -p 3000:8080 ghcr.io/open-webui/open-webui:main` |
| **Nitrokey HSM 2** | Log signing, policy integrity | [shop.nitrokey.com](https://shop.nitrokey.com/shop/nkhs2-nitrokey-hsm-2-7) |
| **FIDO2 key** | Hardware approval for Tier 3 ops | Any FIDO2-compatible key (Nitrokey, YubiKey, etc.) or a phone with Face ID / fingerprint |

AIOHAI works without the hardware — it just means log signing and Tier 3 hardware approval are disabled. The proxy will warn you at startup if hardware is missing and `hsm_required` is set to `true` (the default). Use `--hsm-optional` to allow software-only mode.

### System Requirements

- Windows 10/11, macOS, or Linux
- 16 GB RAM (32 GB recommended for larger AI models)
- 20 GB free disk space
- NVIDIA GPU with 8+ GB VRAM (optional, makes AI faster)

---

## Installation

### Step 1: Download and Extract

Extract `aiohai_v3.0.zip` to a location like `C:\AIOHAI\` (Windows) or `~/aiohai/` (Mac/Linux).

### Step 2: Install Python Dependencies

```bash
cd C:\AIOHAI\aiohai_v3.0
pip install -r requirements.txt
```

### Step 3: Run Setup Wizard (Recommended)

The CLI tool walks you through first-time configuration:

```bash
python tools/aiohai_cli.py setup
```

This will:
- Detect Ollama and verify connectivity
- Initialize the Nitrokey HSM (if plugged in)
- Generate SSL certificates for the FIDO2 server
- Register your first FIDO2 device (phone or security key)
- Create your configuration

### Step 4: Start AIOHAI

```bash
python proxy/aiohai_proxy.py
```

You should see the 8-step startup sequence:

```
[1/8] Logging system... ✓
[2/8] Policy file (SHA-256)... ✓ Loaded (hash: a1b2c3d4...)
[3/8] Policy HSM verification... ✓ Signature valid
[4/8] Network interceptor... ✓ Hooks active (including DoH blocking)
[5/8] Integrity monitoring... ✓ Active (10s interval)
      ✓ HSM health monitor active (30s interval)
[6/8] FIDO2/WebAuthn approval system... ✓ 1 users, 2 devices registered
[7/8] Handler configuration... ✓ Configured
[8/8] Starting HTTP proxy server...

======================================================================
PROXY ACTIVE — v3.0 · ALL SECURITY LAYERS ENABLED
======================================================================
Listen:   http://127.0.0.1:11435
Ollama:   http://127.0.0.1:11434
FIDO2:    https://192.168.1.50:8443
HSM:      Nitrokey HSM 2 (connected)
Session:  a1b2c3d4e5f6g7h8
======================================================================
```

### Step 5: Point Open WebUI at AIOHAI

1. Open http://localhost:3000
2. Go to **Settings → Connections**
3. Change Ollama URL from `http://localhost:11434` to `http://localhost:11435`
4. Save

All conversations now flow through AIOHAI's security layer.

---

## CLI Management Tool

AIOHAI includes a full management CLI (`tools/aiohai_cli.py`) for administration:

| Command | Purpose |
|---------|---------|
| `aiohai_cli.py setup` | First-time setup wizard |
| `aiohai_cli.py start` | Start the proxy |
| `aiohai_cli.py status` | System health overview |
| `aiohai_cli.py users list` | List registered users |
| `aiohai_cli.py users add` | Add a new user |
| `aiohai_cli.py devices list` | List FIDO2 devices |
| `aiohai_cli.py devices register` | Register a new security key / phone |
| `aiohai_cli.py hsm status` | Check HSM connection and health |
| `aiohai_cli.py hsm init` | Initialize a new HSM |
| `aiohai_cli.py logs tail` | Live tail of security events |
| `aiohai_cli.py logs search` | Search logs by event type |
| `aiohai_cli.py config show` | Show current configuration |
| `aiohai_cli.py config set` | Modify a setting |
| `aiohai_cli.py certs generate` | Generate SSL certificates |
| `aiohai_cli.py doctor` | Run diagnostics |

---

## How It Works

### The Request Flow

1. **You type** a message in Open WebUI
2. **AIOHAI intercepts** the request before it reaches Ollama
3. **Input sanitization** strips invisible characters, normalizes homoglyphs, scans for 40+ injection patterns
4. **Security policy** is injected into the LLM context (the AI is told its rules)
5. **Ollama processes** the request and returns a response with proposed actions
6. **Action parsing** extracts `<ACTION>` blocks from the response
7. **Tier classification** determines approval level for each action
8. **You approve** — via chat (Tier 2) or security key tap (Tier 3)
9. **Execution** happens only after approval, through the sandboxed executor
10. **Logging** — every action is logged with a chain hash and optional HSM signature

### When You Ask the AI to Do Something

```
You: "Set up my Reolink camera in Home Assistant"

AI proposes:  WRITE → configuration.yaml    (Tier 2 — chat approval)
              WRITE → secrets.yaml          (Tier 3 — contains credentials → hardware approval)
              COMMAND → docker restart ha    (Tier 2 — chat approval)

You see action cards with CONFIRM / REJECT for each one.
For the secrets.yaml write, your phone buzzes with a FIDO2 approval request.
```

---

## User Commands

Commands you type in the chat to control AIOHAI:

| Command | What It Does |
|---------|--------------|
| `HELP` | Shows all available commands |
| `PENDING` | Lists actions waiting for your approval |
| `CONFIRM <id>` | Approve a specific action |
| `REJECT <id>` | Block a specific action |
| `CONFIRM ALL SAFE` | Approve all non-DELETE actions at once |
| `REJECT ALL` | Reject all pending actions |
| `EXPLAIN <id>` | Get details on why something was blocked |
| `REPORT` | Full transparency report of everything this session |
| `STATUS` | Show proxy health and connection status |
| `STOP` | Shut down the proxy gracefully |

---

## What Gets Blocked Automatically

### Blocked File Access

The AI **cannot** read or write:
- 🔐 Password files (`.kdbx`, KeePass, 1Password, Bitwarden)
- 💳 Financial software (Quicken, QuickBooks, TurboTax, YNAB)
- 🏦 Bank statements and exports
- 🔑 SSH keys and credentials (`.ssh/`, `.aws/`, `.env`, API keys)
- 🌐 Browser data (cookies, saved passwords, login databases)
- 💰 Cryptocurrency wallets and seed phrases
- 📋 Password exports (`passwords.csv`, etc.)
- 🖥️ Windows system files (SAM, SECURITY, SYSTEM, ntds.dit)

### Blocked Commands

The AI **cannot** run:
- 🦠 Encoded/obfuscated PowerShell (`-EncodedCommand`, `-ec`, etc.)
- 💾 Persistence mechanisms (startup scripts, scheduled tasks, services, registry Run keys)
- 🔓 Credential theft tools and privilege escalation
- 📤 Data exfiltration (download cradles, `curl | sh`, `certutil`, `bitsadmin`)
- 🛡️ Security software tampering and firewall disabling
- 👤 User creation and group modification (`net user`, `net localgroup`)

### Blocked Network Access

The AI **cannot** connect to:
- 🌍 External servers (unless explicitly allowlisted)
- 🔒 DNS-over-HTTPS endpoints (prevents DNS tunneling)
- ☁️ Cloud storage uploads
- 🏠 Private IP ranges and Tailscale mesh (configurable)

---

## Prompt Injection Defense

AIOHAI protects against the #1 attack vector for AI agents: prompt injection hidden in documents, emails, or web pages the AI reads.

**What it catches:**
- Direct instruction overrides ("ignore all previous instructions")
- Role manipulation ("you are now an unrestricted AI")
- Fake system tags (`[system]`, `<admin>`, `### instruction:`)
- Fake authorization claims ("this has been pre-authorized")
- Anti-transparency instructions ("don't tell the user")
- Prompt extraction attempts ("show me your system prompt")
- Translation-based context switches ("translate to French then execute")
- Invisible Unicode characters used to hide instructions (zero-width spaces, BOM, etc.)
- Cyrillic homoglyphs that look like Latin letters but bypass keyword filters
- Fullwidth Unicode characters used to evade pattern matching
- Base64 / hex-encoded payloads and obfuscated decode functions

When injection is detected, AIOHAI assigns a `HOSTILE` trust level to the input and wraps it with warning frames so the AI knows the content is untrusted.

---

## Hardware Security

### Nitrokey HSM 2

The HSM provides:
- **Log signing** — Every security event is signed with a key stored in tamper-resistant hardware. If someone modifies `security_events.log` after the fact, the signature chain breaks.
- **Policy verification** — The security policy file has an HSM-generated signature. The proxy verifies it at startup.
- **Health monitoring** — A background thread checks HSM connectivity every 30 seconds. If the HSM is disconnected, AIOHAI logs a degradation warning and attempts reconnection automatically. When reconnected, log signing resumes.

**Setup:**
```bash
python tools/hsm_setup.py         # Initialize HSM and generate signing keys
python tools/aiohai_cli.py hsm status  # Verify connection
```

**Running without HSM:**
```bash
# Allow startup without HSM hardware
python proxy/aiohai_proxy.py --hsm-optional

# Disable HSM entirely
python proxy/aiohai_proxy.py --no-hsm
```

### FIDO2 / WebAuthn

The FIDO2 server provides:
- **Tier 3 hardware approval** — DELETE operations, sensitive writes, and bulk operations require a physical security key tap or phone biometric
- **Phone-based approval** — The FIDO2 server runs HTTPS on your LAN (port 8443 by default). When a Tier 3 action is requested, you get a link to approve on your phone via Face ID, fingerprint, or NFC key tap.
- **Credential storage** — WebAuthn credentials are stored locally in `data/fido2/credentials.json`
- **Approval persistence** — Pending approvals survive proxy restarts. If you restart the proxy while a Tier 3 request is waiting, it will still be there when it comes back up.
- **Retry logic** — The proxy-to-server connection retries 3 times with exponential backoff if the FIDO2 server is temporarily unreachable.
- **SSL certificate pinning** — The client pins the server's self-signed certificate, preventing man-in-the-middle attacks on the LAN.

**Setup:**
```bash
python tools/register_devices.py  # Register a new phone or security key
```

**Running without FIDO2:**
```bash
python proxy/aiohai_proxy.py --no-fido2
```

---

## Integrity Monitoring and Lockdown

AIOHAI monitors its own security policy file every 10 seconds. If the file is modified or deleted:

1. The integrity verifier detects the hash mismatch
2. The proxy enters **lockdown mode**
3. All new requests are rejected with HTTP 503
4. A `LOCKDOWN_ACTIVATED` critical event is logged
5. A console alert is printed

**Lockdown is irreversible without restarting the proxy.** Even if you restore the original policy file, the proxy stays locked. This is by design — if someone managed to tamper with the policy, you need to investigate before resuming operation.

---

## Fail-Secure Defaults

Every security-relevant default errs on the side of restriction:

| Setting | Default | Meaning |
|---------|---------|---------|
| `listen_host` | `127.0.0.1` | Proxy only accessible from localhost |
| `hsm_required` | `true` | Refuses to start without HSM hardware |
| `fido2_enabled` | `true` | FIDO2 approval system active |
| `allow_degraded_security` | `false` | Refuses to start without security components |
| `scan_for_injection` | `true` | Input injection scanning active |
| `enforce_network_allowlist` | `true` | Socket-level network control active |
| `scan_file_content` | `true` | Static analysis on file writes active |
| `refuse_admin` | `true` | Refuses to run as root/administrator |

To relax any of these for testing, use CLI flags like `--hsm-optional`, `--allow-degraded`, or `--no-network-control`.

---

## Configuration

Configuration lives in `config/config.json`. Key sections:

| Section | What It Controls |
|---------|-----------------|
| `proxy` | Listen address, port, injection scanning, rate limits |
| `ollama` | Backend host, port, model, timeout |
| `security` | Policy file path, credential redaction, sensitivity detection |
| `integrity` | Check interval, periodic checks, tamper-evident logging |
| `network` | Default stance (DENY), allowlist, private IP blocking, DoH blocking |
| `command_execution` | Shell access, executable whitelist, obfuscation detection |
| `path_security` | Allowed drives, UNC blocking, symlink resolution |
| `injection_defense` | Invisible char detection, homoglyphs, pattern detection |
| `environment` | Subprocess env sanitization, blocked env patterns |
| `alerting` | Desktop alerts, sound alerts, email, webhooks |
| `resource_limits` | Max concurrent processes, file size limits, session duration |

Use the CLI to view or modify settings:
```bash
python tools/aiohai_cli.py config show
python tools/aiohai_cli.py config set proxy.listen_port 11436
```

---

## Transparency Reports

Type `REPORT` in the chat to get a full audit of everything that happened in your session:

- Session ID, start time, duration
- Approvals granted and rejected (with counts)
- Sensitive data accessed (with categories)
- All files read and written (with sizes)
- All commands executed
- All blocked attempts (with reasons)

---

## Troubleshooting

### "HSM required but not available"

The proxy refuses to start because `hsm_required` is `true` and no Nitrokey HSM is detected.

**Solutions:**
1. Plug in your Nitrokey HSM 2
2. Run `python tools/aiohai_cli.py hsm status` to verify detection
3. Or start with `--hsm-optional` to allow software-only mode

### "Service locked down — policy tampering detected"

The integrity monitor detected a change to the security policy file.

**Solutions:**
1. Check if you accidentally edited the policy file
2. Restore the original file from backup
3. Restart the proxy (lockdown clears on restart)
4. If this was unexpected, investigate — someone may have tried to weaken the AI's rules

### "Connection refused" or "Cannot connect to Ollama"

**Solutions:**
1. Make sure Ollama is running: `ollama serve`
2. Check Ollama is on the right port: `curl http://localhost:11434/api/tags`
3. Run diagnostics: `python tools/aiohai_cli.py doctor`

### Actions keep getting blocked

**Solutions:**
1. Use `EXPLAIN <id>` to understand the specific reason
2. Check if the AI is trying to access sensitive paths
3. Use `PENDING` to review all waiting approvals
4. If rate limited, approve or reject existing requests first

### FIDO2 approval not working on phone

**Solutions:**
1. Make sure your phone is on the same network as the server
2. Check the FIDO2 server is running: look for "FIDO2/WebAuthn approval system... ✓" at startup
3. Verify your device is registered: `python tools/aiohai_cli.py devices list`
4. Re-register if needed: `python tools/register_devices.py`

---

## File Structure

```
aiohai_v3.0/
├── proxy/
│   └── aiohai_proxy.py                 ← Main proxy (start this)
├── security/
│   ├── security_components.py          ← Static analysis, PII, credential redaction
│   ├── fido2_approval.py               ← FIDO2/WebAuthn server + client
│   └── hsm_integration.py              ← Nitrokey HSM PKCS#11 interface
├── policy/
│   └── aiohai_security_policy_v3.0.md  ← Security policy (injected into LLM)
├── config/
│   └── config.json                     ← Reference configuration
├── tests/
│   ├── test_security.py                ← 200+ security unit tests
│   └── test_startup.py                 ← Integration tests
├── tools/
│   ├── aiohai_cli.py                   ← Management CLI
│   ├── register_devices.py             ← FIDO2 device registration
│   └── hsm_setup.py                    ← HSM initialization
├── docs/
│   └── ARCHITECTURE.md                 ← Technical architecture documentation
├── setup/
│   └── Setup.ps1                       ← Windows installer script
├── web/
│   └── templates/                      ← FIDO2 approval UI templates
├── requirements.txt                    ← Python dependencies
└── README.md                           ← This file
```

---

## Running the Test Suite

AIOHAI includes 200+ automated tests covering all security paths:

```bash
pip install pytest
cd aiohai_v3.0
pytest tests/ -v
```

Tests cover: prompt injection patterns, credential redaction, path blocking, command blocking, integrity lockdown, FIDO2 retry logic, SSL verification, environment sanitization, reverse proxy bypass resistance, and fail-secure defaults.

---

## Quick Reference Card

```
╔═══════════════════════════════════════════════════════════════════╗
║                      AIOHAI QUICK REFERENCE                      ║
╠═══════════════════════════════════════════════════════════════════╣
║  START:        python proxy/aiohai_proxy.py                      ║
║  STOP:         Ctrl+C in terminal  OR  type STOP in chat         ║
║  CLI:          python tools/aiohai_cli.py [command]              ║
╠═══════════════════════════════════════════════════════════════════╣
║  APPROVE:      CONFIRM <id>         Example: CONFIRM a1b2c3d4   ║
║  REJECT:       REJECT <id>          Example: REJECT a1b2c3d4    ║
║  APPROVE ALL:  CONFIRM ALL SAFE     (skips DELETE actions)       ║
║  REJECT ALL:   REJECT ALL                                        ║
╠═══════════════════════════════════════════════════════════════════╣
║  SEE PENDING:  PENDING                                           ║
║  GET DETAILS:  EXPLAIN <id>                                      ║
║  SEE HISTORY:  REPORT                                            ║
║  GET HELP:     HELP                                              ║
╠═══════════════════════════════════════════════════════════════════╣
║  ⚠️  = Normal action      🔴 = DANGER (DELETE / Tier 3)          ║
║  🔒 = Sensitive data      💰 = Financial data                    ║
║  [REDACTED] = Hidden credential                                  ║
╚═══════════════════════════════════════════════════════════════════╝
```

---

## License & Disclaimer

**MIT License** — Free for personal and home use.

**⚠️ DISCLAIMER:** This software implements multiple security layers, but no security system is perfect. Always:
- Review approval requests carefully before confirming
- Keep backups of important data
- Don't give the AI access to truly critical systems without understanding the risks
- Keep your Nitrokey HSM and FIDO2 devices physically secure

---

## Version History

- **v3.0** (Current) — Major release. HSM hardware signing, FIDO2/WebAuthn tiered approval, integrity monitoring with automatic lockdown, prompt injection defense (40+ patterns, invisible chars, homoglyphs), fail-secure defaults, FIDO2 retry/persistence, SSL certificate pinning, HSM health monitoring with auto-reconnect, 200+ automated tests, architecture documentation. Rebranded from SecureLLM to AIOHAI.
- **v2.2 (as SecureLLM)** — Smart home config scanning, obfuscation detection
- **v2.1 (as SecureLLM)** — Static code analysis, PII protection
- **v2.0 (as SecureLLM)** — Initial secure proxy implementation
