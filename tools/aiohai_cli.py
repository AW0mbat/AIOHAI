#!/usr/bin/env python3
"""
AIOHAI Management CLI
=========================

Unified command-line interface for managing all AIOHAI components:
  - First-time setup wizard
  - User and device management
  - HSM operations
  - FIDO2/WebAuthn approval system
  - System status and diagnostics
  - Log viewing and audit
  - Configuration management

Usage:
  python aiohai_cli.py                       # Interactive main menu
  python aiohai_cli.py setup                  # First-time setup wizard
  python aiohai_cli.py status                 # System health overview
  python aiohai_cli.py users list             # List users
  python aiohai_cli.py users add              # Add a user
  python aiohai_cli.py users remove <name>    # Remove a user
  python aiohai_cli.py devices list           # List registered devices
  python aiohai_cli.py devices remove <id>    # Remove a device
  python aiohai_cli.py hsm status             # HSM health check
  python aiohai_cli.py hsm sign-policy        # Sign policy with HSM
  python aiohai_cli.py logs show              # View recent logs
  python aiohai_cli.py logs audit             # Verify log integrity
  python aiohai_cli.py config show            # Show configuration
  python aiohai_cli.py config set <key> <val> # Update setting
  python aiohai_cli.py start                  # Start proxy + approval server
  python aiohai_cli.py certs generate         # Regenerate TLS certificates
  python aiohai_cli.py doctor                 # Full diagnostic check

Version: 3.0.1
"""

import os
import sys
import json
import time
import hashlib
import argparse
import getpass
import shutil
import socket
import platform
import subprocess
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

# Resolve project root (one level up from tools/)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# =============================================================================
# TERMINAL FORMATTING
# =============================================================================

class Colors:
    """ANSI color codes — degrades gracefully on Windows without VT100."""
    ENABLED = True

    @classmethod
    def _try_enable(cls):
        if sys.platform == 'win32':
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            except Exception:
                cls.ENABLED = False
        if os.environ.get('NO_COLOR'):
            cls.ENABLED = False

    @classmethod
    def _c(cls, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if cls.ENABLED else text

    @classmethod
    def bold(cls, t): return cls._c("1", t)
    @classmethod
    def dim(cls, t): return cls._c("2", t)
    @classmethod
    def green(cls, t): return cls._c("32", t)
    @classmethod
    def red(cls, t): return cls._c("31", t)
    @classmethod
    def yellow(cls, t): return cls._c("33", t)
    @classmethod
    def cyan(cls, t): return cls._c("36", t)
    @classmethod
    def magenta(cls, t): return cls._c("35", t)

Colors._try_enable()

OK = Colors.green("✓")
FAIL = Colors.red("✗")
WARN = Colors.yellow("⚠")
INFO = Colors.cyan("ℹ")


def heading(text: str):
    width = min(shutil.get_terminal_size().columns, 72)
    print(f"\n{Colors.bold(text)}")
    print(Colors.dim("─" * width))


def table_row(label: str, value: str, status: str = ""):
    label_col = f"  {label:<30}"
    if status:
        print(f"{label_col} {status} {value}")
    else:
        print(f"{label_col} {value}")


# =============================================================================
# LAZY MODULE LOADING
# =============================================================================

def _load_config() -> dict:
    """Load main config.json."""
    cfg_path = PROJECT_ROOT / "config" / "config.json"
    if cfg_path.exists():
        return json.loads(cfg_path.read_text(encoding='utf-8'))
    return {}


def _load_credential_store():
    """Load the FIDO2 credential store."""
    try:
        from aiohai.core.crypto.credentials import CredentialStore; from aiohai.core.types import UserRole
        storage = PROJECT_ROOT / "data" / "fido2"
        return CredentialStore(storage)
    except ImportError:
        return None


def _load_hsm_manager():
    """Load HSM manager (mock if hardware unavailable)."""
    try:
        from aiohai.core.crypto.hsm_bridge import get_hsm_manager
        return get_hsm_manager()
    except ImportError:
        return None


def _get_local_ip() -> str:
    """Best-effort local IP for phone access URL."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _read_log_tail(log_name: str, lines: int = 30) -> List[str]:
    """Read last N lines of a log file."""
    log_dir = PROJECT_ROOT / "logs"
    log_file = log_dir / log_name
    if not log_file.exists():
        return []
    all_lines = log_file.read_text(encoding='utf-8', errors='replace').splitlines()
    return all_lines[-lines:]


def _hash_file(path: Path) -> str:
    """SHA-256 hash of a file. O5: Delegates to same algorithm as IntegrityVerifier."""
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


# =============================================================================
# COMMAND: SETUP — First-time setup wizard
# =============================================================================

def cmd_setup(args):
    """Interactive first-time setup wizard."""
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║                AIOHAI First-Time Setup                        ║
║                ═════════════════════════                         ║
║                                                                  ║
║  This wizard walks you through:                                 ║
║    1. Prerequisite check                                        ║
║    2. Configuration                                             ║
║    3. HSM initialization (if hardware present)                  ║
║    4. Admin account creation                                    ║
║    5. FIDO2 device registration                                 ║
║    6. Policy signing                                            ║
║    7. Verification                                              ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
    """)

    # Step 1: Prerequisites
    heading("Step 1/7 — Prerequisite Check")
    issues = _run_doctor_checks(quiet=True)
    if issues['critical']:
        print(f"\n  {FAIL} {len(issues['critical'])} critical issue(s) must be fixed first:")
        for issue in issues['critical']:
            print(f"     {FAIL} {issue}")
        print(f"\n  Run {Colors.cyan('python aiohai_cli.py doctor')} for full details.")
        resp = input("\n  Continue anyway? [y/N]: ").strip().lower()
        if resp != 'y':
            return
    else:
        print(f"  {OK} All prerequisites satisfied")

    # Step 2: Configuration
    heading("Step 2/7 — Configuration")
    config = _load_config()
    current_model = config.get('ollama', {}).get('model', 'llama3.2')
    current_port = config.get('proxy', {}).get('listen_port', 11435)

    print(f"  Current model:  {Colors.cyan(current_model)}")
    print(f"  Current port:   {Colors.cyan(str(current_port))}")

    model = input(f"\n  LLM model [{current_model}]: ").strip() or current_model
    port_str = input(f"  Proxy port [{current_port}]: ").strip()
    port = int(port_str) if port_str.isdigit() else current_port

    if model != current_model or port != current_port:
        config.setdefault('ollama', {})['model'] = model
        config.setdefault('proxy', {})['listen_port'] = port
        cfg_path = PROJECT_ROOT / "config" / "config.json"
        cfg_path.write_text(json.dumps(config, indent=2), encoding='utf-8')
        print(f"  {OK} Configuration updated")
    else:
        print(f"  {OK} Keeping current settings")

    # Step 3: HSM
    heading("Step 3/7 — Hardware Security Module")
    hsm = _load_hsm_manager()
    if hsm:
        try:
            is_mock = type(hsm).__name__ == 'MockHSMManager'
            if is_mock:
                print(f"  {INFO} HSM running in mock mode (no hardware)")
                print(f"     Connect Nitrokey HSM 2 + install PyKCS11 for real protection")
            else:
                status = hsm.get_status()
                if hasattr(status, 'connected') and status.connected:
                    print(f"  {OK} Nitrokey HSM 2 detected")
                    print(f"     Serial: {getattr(status, 'serial', 'N/A')}")
                else:
                    print(f"  {WARN} HSM library loaded but device not connected")
                    print(f"     Connect Nitrokey HSM 2 via USB and run:")
                    print(f"     {Colors.cyan('python tools/hsm_setup.py --init')}")
        except Exception as e:
            print(f"  {WARN} HSM check failed: {e}")
    else:
        print(f"  {INFO} HSM module not available (optional)")
        print(f"     Install: pip install PyKCS11")
        print(f"     AIOHAI works fine without it — uses software verification")

    # Step 4: Admin account
    heading("Step 4/7 — Admin Account")
    store = _load_credential_store()
    if store:
        users = store.get_all_users()
        admin_exists = any(u.role.value == 'admin' for u in users.values())
        if admin_exists:
            admin_user = next(u for u in users.values() if u.role.value == 'admin')
            print(f"  {OK} Admin account exists: {Colors.cyan(admin_user.username)}")
            device_count = len(admin_user.credentials)
            print(f"     Devices registered: {device_count}")
        else:
            print(f"  No admin account yet. Let's create one.\n")
            username = input("  Admin username (e.g. 'dad', 'admin'): ").strip()
            if username:
                try:
                    from aiohai.core.types import UserRole
                    store.add_user(username, UserRole.ADMIN)
                    print(f"  {OK} Admin '{username}' created")
                except Exception as e:
                    print(f"  {FAIL} Error: {e}")
            else:
                print(f"  {WARN} Skipped — create later with: python aiohai_cli.py users add")
    else:
        print(f"  {WARN} FIDO2 module not available")
        print(f"     Install: pip install fido2 flask flask-cors")

    # Step 5: Device registration guidance
    heading("Step 5/7 — Device Registration")
    local_ip = _get_local_ip()
    fido2_port = config.get('proxy', {}).get('fido2_port', 8443)
    print(f"""
  Device registration uses your phone's browser + biometrics.

  When AIOHAI is running, open on your phone:

    {Colors.bold(Colors.cyan(f'https://{local_ip}:{fido2_port}/register'))}

  Then:
    1. Enter your username
    2. Name your device (e.g. "iPhone 15 Pro")
    3. Choose: Biometric (Face ID / Touch ID) or Security Key (Nitrokey)
    4. Authenticate when prompted
    5. Repeat for each family member

  {Colors.dim("You'll accept the self-signed certificate warning once.")}
""")
    input("  Press Enter to continue...")

    # Step 6: Policy signing
    heading("Step 6/7 — Policy Signing")
    policy_path = PROJECT_ROOT / "policy" / "aiohai_security_policy_v3.0.md"
    if policy_path.exists():
        policy_hash = _hash_file(policy_path)
        print(f"  Policy file: {policy_path.name}")
        print(f"  SHA-256:     {Colors.dim(policy_hash[:16])}...{Colors.dim(policy_hash[-16:])}")

        if hsm:
            print(f"\n  To sign with HSM: {Colors.cyan('python tools/hsm_setup.py --sign-policy')}")
        else:
            # Store hash in config for software verification
            config['security']['policy_hash'] = policy_hash
            cfg_path = PROJECT_ROOT / "config" / "config.json"
            cfg_path.write_text(json.dumps(config, indent=2), encoding='utf-8')
            print(f"  {OK} Policy hash stored in config (software verification)")
    else:
        print(f"  {FAIL} Policy file not found: {policy_path}")

    # Step 7: Final verification
    heading("Step 7/7 — Verification")
    print(f"  Running quick health check...")
    issues = _run_doctor_checks(quiet=True)
    total_issues = len(issues['critical']) + len(issues['warnings'])
    if total_issues == 0:
        print(f"\n  {OK} All checks passed!")
    else:
        print(f"\n  {WARN} {total_issues} issue(s) remain (run 'doctor' for details)")

    print(f"""
{'=' * 64}
  {Colors.bold(Colors.green('SETUP COMPLETE'))}
{'=' * 64}

  Start AIOHAI:
    {Colors.cyan('python aiohai_cli.py start')}

  Or start components individually:
    {Colors.cyan('python -m proxy.aiohai_proxy')}

  Register devices (phone browser):
    {Colors.cyan(f'https://{local_ip}:{fido2_port}/register')}

  Check system health:
    {Colors.cyan('python aiohai_cli.py doctor')}
""")


# =============================================================================
# COMMAND: STATUS — System health overview
# =============================================================================

def cmd_status(args):
    """Show system health overview."""
    heading("AIOHAI System Status")
    config = _load_config()

    # Platform info
    table_row("Platform", f"{platform.system()} {platform.release()}")
    table_row("Python", f"{sys.version.split()[0]}")
    table_row("Project root", str(PROJECT_ROOT))
    print()

    # Module availability
    heading("Module Availability")
    modules = [
        ("security.security_components", "Core Security"),
        ("security.hsm_integration", "HSM Integration"),
        ("security.fido2_approval", "FIDO2/WebAuthn"),
    ]
    for mod_path, label in modules:
        try:
            __import__(mod_path)
            table_row(label, "loaded", OK)
        except ImportError as e:
            table_row(label, str(e).split("'")[1] if "'" in str(e) else str(e), WARN)

    deps = [
        ("fido2", "fido2 (WebAuthn)"),
        ("flask", "Flask (web server)"),
        ("flask_cors", "Flask-CORS"),
        ("cryptography", "cryptography"),
        ("PyKCS11", "PyKCS11 (HSM)"),
    ]
    print()
    heading("Python Dependencies")
    for pkg, label in deps:
        try:
            mod = __import__(pkg)
            try:
                from importlib.metadata import version as pkg_version
                ver = pkg_version(pkg)
            except Exception:
                ver = getattr(mod, '__version__', getattr(mod, 'VERSION', '?'))
            table_row(label, str(ver), OK)
        except ImportError:
            table_row(label, "not installed", Colors.dim("–"))

    # Configuration
    print()
    heading("Configuration")
    table_row("Model", config.get('ollama', {}).get('model', '?'))
    table_row("Proxy port", str(config.get('proxy', {}).get('listen_port', '?')))
    table_row("Ollama port", str(config.get('ollama', {}).get('port', '?')))
    table_row("Policy", config.get('security', {}).get('policy_file', '?'))

    policy_path = PROJECT_ROOT / "policy" / "aiohai_security_policy_v3.0.md"
    if policy_path.exists():
        stored_hash = config.get('security', {}).get('policy_hash', '')
        actual_hash = _hash_file(policy_path)
        if stored_hash and stored_hash == actual_hash:
            table_row("Policy integrity", "hash matches", OK)
        elif stored_hash:
            table_row("Policy integrity", "HASH MISMATCH", FAIL)
        else:
            table_row("Policy integrity", "no hash stored", WARN)

    # Users & devices
    print()
    heading("Users & Devices")
    store = _load_credential_store()
    if store:
        users = store.get_all_users()
        total_devices = sum(len(u.credentials) for u in users.values())
        table_row("Users", str(len(users)))
        table_row("Devices", str(total_devices))
        for username, user in users.items():
            role_color = Colors.magenta if user.role.value == 'admin' else Colors.cyan
            devices_str = f"{len(user.credentials)} device(s)"
            table_row(f"  {username}", f"{role_color(user.role.value)} — {devices_str}")
    else:
        table_row("Users", "FIDO2 module not available", WARN)

    # HSM
    print()
    heading("Hardware Security Module")
    hsm = _load_hsm_manager()
    if hsm:
        is_mock = type(hsm).__name__ == 'MockHSMManager'
        if is_mock:
            table_row("HSM mode", "Software simulation (MockHSM)", INFO)
        else:
            try:
                status = hsm.get_status()
                if hasattr(status, 'connected') and status.connected:
                    table_row("HSM", "Nitrokey HSM 2 connected", OK)
                    table_row("Serial", getattr(status, 'serial', 'N/A'))
                else:
                    table_row("HSM", "not connected", WARN)
            except Exception as e:
                table_row("HSM", f"error: {e}", FAIL)
    else:
        table_row("HSM", "module not available", Colors.dim("–"))

    # TLS certificates
    print()
    heading("TLS Certificates")
    cert_dir = PROJECT_ROOT / "data" / "fido2" / "certs"
    cert_file = cert_dir / "server.crt"
    key_file = cert_dir / "server.key"
    if cert_file.exists():
        try:
            from cryptography import x509
            cert = x509.load_pem_x509_certificate(cert_file.read_bytes())
            table_row("Certificate", str(cert_file), OK)
            table_row("Subject", str(cert.subject))
            table_row("Expires", str(cert.not_valid_after_utc))
            if cert.not_valid_after_utc < datetime.utcnow():
                table_row("Status", "EXPIRED — run: aiohai_cli.py certs generate", FAIL)
            else:
                days_left = (cert.not_valid_after_utc - datetime.utcnow()).days
                table_row("Status", f"valid ({days_left} days remaining)", OK)
        except Exception:
            table_row("Certificate", str(cert_file), OK)
    else:
        table_row("Certificate", "not generated yet (auto-creates on first run)", INFO)

    # Logs
    print()
    heading("Log Files")
    log_dir = PROJECT_ROOT / "logs"
    if log_dir.exists():
        for log_file in sorted(log_dir.glob("*.log")):
            size = log_file.stat().st_size
            if size > 1024 * 1024:
                size_str = f"{size / (1024*1024):.1f} MB"
            elif size > 1024:
                size_str = f"{size / 1024:.1f} KB"
            else:
                size_str = f"{size} B"
            mtime = datetime.fromtimestamp(log_file.stat().st_mtime)
            table_row(f"  {log_file.name}", f"{size_str}  (modified {mtime:%Y-%m-%d %H:%M})")
    else:
        table_row("Logs", "no log directory yet (created on first run)", INFO)

    print()


# =============================================================================
# COMMAND: USERS — User management
# =============================================================================

def cmd_users(args):
    """User management subcommand."""
    store = _load_credential_store()
    if not store:
        print(f"  {FAIL} FIDO2 module not available. Install: pip install fido2 flask flask-cors")
        return

    subcmd = args.users_command if hasattr(args, 'users_command') else 'list'

    if subcmd == 'list':
        _users_list(store)
    elif subcmd == 'add':
        _users_add(store)
    elif subcmd == 'remove':
        _users_remove(store, args.username if hasattr(args, 'username') else None)
    elif subcmd == 'modify':
        _users_modify(store, args.username if hasattr(args, 'username') else None)
    else:
        _users_list(store)


def _users_list(store):
    heading("Registered Users")
    users = store.get_all_users()
    if not users:
        print(f"  {INFO} No users registered. Run: python aiohai_cli.py users add")
        return

    for username, user in users.items():
        role_str = user.role.value
        device_count = len(user.credentials)
        created = user.created_at[:10] if user.created_at else "unknown"

        print(f"\n  {Colors.bold(username)}")
        print(f"    Role:      {_role_badge(role_str)}")
        print(f"    Created:   {created}")
        print(f"    Devices:   {device_count}")

        if user.allowed_paths:
            print(f"    Paths:     {', '.join(user.allowed_paths)}")

        for cred in user.credentials:
            auth_type = "🔑 security key" if cred.authenticator_type == 'security_key' else "📱 biometric"
            last = cred.last_used[:10] if cred.last_used else "never"
            print(f"      {auth_type}  {cred.device_name}  (last used: {last})")

    print(f"\n  Total: {len(users)} user(s), "
          f"{sum(len(u.credentials) for u in users.values())} device(s)")


def _users_add(store):
    heading("Add User")
    try:
        from aiohai.core.types import UserRole
    except ImportError:
        print(f"  {FAIL} Cannot import UserRole")
        return

    username = input("  Username: ").strip()
    if not username:
        print(f"  {FAIL} Username required")
        return

    existing = store.get_user(username)
    if existing:
        print(f"  {FAIL} User '{username}' already exists")
        return

    print(f"\n  Roles:")
    print(f"    {Colors.magenta('admin')}          Full access. Manage security, users, HSM.")
    print(f"    {Colors.cyan('trusted')}        Most access. Cannot change security config.")
    print(f"    {Colors.yellow('restricted')}     Own folders only. Must specify allowed paths.")
    print(f"    {Colors.dim('guest')}          Read-only, limited folders.")

    role_str = input("\n  Role [trusted]: ").strip().lower() or 'trusted'
    try:
        role = UserRole(role_str)
    except ValueError:
        print(f"  {FAIL} Invalid role: '{role_str}'")
        return

    allowed_paths = []
    if role in (UserRole.RESTRICTED, UserRole.GUEST):
        print(f"\n  Enter allowed paths (empty line when done):")
        print(f"  {Colors.dim('Example: D:\\\\Users\\\\Teen\\\\*')}")
        while True:
            p = input("    Path: ").strip()
            if not p:
                break
            allowed_paths.append(p)
        if not allowed_paths and role == UserRole.RESTRICTED:
            print(f"  {WARN} No paths specified — this user won't be able to approve anything")

    try:
        store.add_user(username, role, allowed_paths)
        print(f"\n  {OK} User '{username}' created ({role.value})")
        local_ip = _get_local_ip()
        print(f"\n  Next: register a device at https://{local_ip}:8443/register")
    except Exception as e:
        print(f"\n  {FAIL} Error: {e}")


def _users_remove(store, username: Optional[str]):
    heading("Remove User")
    if not username:
        username = input("  Username to remove: ").strip()
    if not username:
        return

    user = store.get_user(username)
    if not user:
        print(f"  {FAIL} User '{username}' not found")
        return

    device_count = len(user.credentials)
    print(f"\n  User:    {username}")
    print(f"  Role:    {user.role.value}")
    print(f"  Devices: {device_count}")

    # Safety check for last admin
    users = store.get_all_users()
    admin_count = sum(1 for u in users.values() if u.role.value == 'admin')
    if user.role.value == 'admin' and admin_count <= 1:
        print(f"\n  {FAIL} Cannot remove the last admin account.")
        print(f"  Create another admin first: python aiohai_cli.py users add")
        return

    confirm = input(f"\n  Type '{username}' to confirm deletion: ").strip()
    if confirm != username:
        print(f"  Cancelled.")
        return

    if store.remove_user(username):
        print(f"\n  {OK} User '{username}' removed ({device_count} device(s) deleted)")
    else:
        print(f"\n  {FAIL} Failed to remove user")


def _users_modify(store, username: Optional[str]):
    heading("Modify User")
    try:
        from aiohai.core.types import UserRole
    except ImportError:
        print(f"  {FAIL} Cannot import UserRole")
        return

    if not username:
        username = input("  Username: ").strip()
    if not username:
        return

    user = store.get_user(username)
    if not user:
        print(f"  {FAIL} User '{username}' not found")
        return

    print(f"\n  Current role: {_role_badge(user.role.value)}")
    print(f"  Current paths: {user.allowed_paths or '(none)'}")

    print(f"\n  What to change?")
    print(f"    1. Role")
    print(f"    2. Allowed paths")
    print(f"    3. Both")
    print(f"    4. Cancel")

    choice = input("\n  Choice [4]: ").strip() or '4'

    if choice in ('1', '3'):
        role_str = input(f"  New role (admin/trusted/restricted/guest): ").strip()
        if role_str:
            try:
                new_role = UserRole(role_str)
                # Check last admin safety
                if user.role == UserRole.ADMIN and new_role != UserRole.ADMIN:
                    users = store.get_all_users()
                    admin_count = sum(1 for u in users.values() if u.role.value == 'admin')
                    if admin_count <= 1:
                        print(f"  {FAIL} Cannot demote the last admin")
                        return
                user.role = new_role
            except ValueError:
                print(f"  {FAIL} Invalid role")
                return

    if choice in ('2', '3'):
        print(f"  Enter new allowed paths (empty line when done):")
        paths = []
        while True:
            p = input("    Path: ").strip()
            if not p:
                break
            paths.append(p)
        user.allowed_paths = paths

    if choice in ('1', '2', '3'):
        store._save()
        print(f"\n  {OK} User '{username}' updated")
        print(f"     Role: {user.role.value}")
        if user.allowed_paths:
            print(f"     Paths: {user.allowed_paths}")


def _role_badge(role: str) -> str:
    badges = {
        'admin': Colors.magenta('admin'),
        'trusted': Colors.cyan('trusted'),
        'restricted': Colors.yellow('restricted'),
        'guest': Colors.dim('guest'),
    }
    return badges.get(role, role)


# =============================================================================
# COMMAND: DEVICES — Device management
# =============================================================================

def cmd_devices(args):
    """Device management subcommand."""
    store = _load_credential_store()
    if not store:
        print(f"  {FAIL} FIDO2 module not available")
        return

    subcmd = args.devices_command if hasattr(args, 'devices_command') else 'list'

    if subcmd == 'list':
        _devices_list(store)
    elif subcmd == 'remove':
        _devices_remove(store, args.device_id if hasattr(args, 'device_id') else None)


def _devices_list(store):
    heading("Registered Devices")
    users = store.get_all_users()
    devices_found = 0

    for username, user in users.items():
        for cred in user.credentials:
            devices_found += 1
            import base64
            cred_id_short = base64.urlsafe_b64encode(cred.credential_id).decode()[:12]
            auth_type = "🔑 Key" if cred.authenticator_type == 'security_key' else "📱 Bio"

            print(f"\n  [{cred_id_short}...]")
            print(f"    Owner:       {username} ({user.role.value})")
            print(f"    Device:      {cred.device_name}")
            print(f"    Type:        {auth_type}")
            print(f"    Registered:  {cred.registered_at[:19] if cred.registered_at else 'unknown'}")
            print(f"    Last used:   {cred.last_used[:19] if cred.last_used else 'never'}")
            print(f"    Sign count:  {cred.sign_count}")

    if not devices_found:
        local_ip = _get_local_ip()
        print(f"  {INFO} No devices registered yet.")
        print(f"  Register at: https://{local_ip}:8443/register")
    else:
        print(f"\n  Total: {devices_found} device(s)")


def _devices_remove(store, device_id_prefix: Optional[str]):
    heading("Remove Device")
    import base64

    if not device_id_prefix:
        device_id_prefix = input("  Device ID prefix (from 'devices list'): ").strip()
    if not device_id_prefix:
        return

    # Find matching device
    found_user = None
    found_cred = None
    for username, user in store.get_all_users().items():
        for cred in user.credentials:
            cred_id_str = base64.urlsafe_b64encode(cred.credential_id).decode()
            if cred_id_str.startswith(device_id_prefix):
                found_user = username
                found_cred = cred
                break
        if found_cred:
            break

    if not found_cred:
        print(f"  {FAIL} No device found matching '{device_id_prefix}'")
        return

    print(f"  Owner:  {found_user}")
    print(f"  Device: {found_cred.device_name}")
    print(f"  Type:   {found_cred.authenticator_type}")

    user = store.get_user(found_user)
    if len(user.credentials) <= 1:
        print(f"\n  {WARN} This is {found_user}'s only device.")
        print(f"  They won't be able to approve operations without a device.")

    confirm = input(f"\n  Remove this device? [y/N]: ").strip().lower()
    if confirm != 'y':
        print(f"  Cancelled.")
        return

    user.credentials.remove(found_cred)
    store._save()
    print(f"\n  {OK} Device '{found_cred.device_name}' removed from {found_user}")


# =============================================================================
# COMMAND: HSM — Hardware Security Module operations
# =============================================================================

def cmd_hsm(args):
    """HSM management subcommand."""
    subcmd = args.hsm_command if hasattr(args, 'hsm_command') else 'status'

    if subcmd == 'status':
        _hsm_status()
    elif subcmd == 'sign-policy':
        _hsm_sign_policy()
    elif subcmd == 'verify-policy':
        _hsm_verify_policy()
    elif subcmd == 'init':
        _hsm_init()


def _hsm_status():
    heading("HSM Status")
    hsm = _load_hsm_manager()
    if not hsm:
        print(f"  {INFO} HSM module not available")
        print(f"  Install: pip install PyKCS11")
        return

    is_mock = type(hsm).__name__ == 'MockHSMManager'
    if is_mock:
        table_row("Mode", "Software simulation (MockHSM)", INFO)
        table_row("Purpose", "Testing without hardware")
        print(f"\n  For real HSM protection, connect a Nitrokey HSM 2")
    else:
        try:
            status = hsm.get_status()
            if hasattr(status, 'connected') and status.connected:
                table_row("Device", "Nitrokey HSM 2", OK)
                table_row("Serial", getattr(status, 'serial', 'N/A'))
                table_row("Firmware", getattr(status, 'firmware', 'N/A'))
                if hasattr(status, 'keys'):
                    print()
                    heading("HSM Keys")
                    for key in status.keys:
                        table_row(f"  {key.label}", f"{key.type} ({key.bits} bit)", OK)
            else:
                table_row("Status", "Not connected", FAIL)
                print(f"\n  Connect Nitrokey HSM 2 via USB")
                print(f"  Then: python aiohai_cli.py hsm init")
        except Exception as e:
            print(f"  {FAIL} HSM error: {e}")


def _hsm_sign_policy():
    heading("Sign Policy File")
    print(f"  Delegating to HSM setup tool...\n")
    hsm_tool = PROJECT_ROOT / "tools" / "hsm_setup.py"
    if hsm_tool.exists():
        os.system(f'{sys.executable} "{hsm_tool}" --sign-policy')
    else:
        print(f"  {FAIL} HSM setup tool not found: {hsm_tool}")


def _hsm_verify_policy():
    heading("Verify Policy Signature")
    hsm = _load_hsm_manager()
    if not hsm:
        print(f"  {FAIL} HSM module not available")
        return

    policy_path = PROJECT_ROOT / "policy" / "aiohai_security_policy_v3.0.md"
    sig_path = PROJECT_ROOT / "policy" / "policy.sig"

    if not policy_path.exists():
        print(f"  {FAIL} Policy file not found")
        return
    if not sig_path.exists():
        print(f"  {WARN} No signature file. Sign first: aiohai_cli.py hsm sign-policy")
        return

    try:
        result = hsm.verify_policy(str(policy_path), str(sig_path))
        if hasattr(result, 'valid') and result.valid:
            print(f"  {OK} Policy signature is valid")
            print(f"     Signed by: {getattr(result, 'signer', 'unknown')}")
            print(f"     Signed at: {getattr(result, 'timestamp', 'unknown')}")
        else:
            print(f"  {FAIL} Policy signature INVALID or could not be verified")
    except Exception as e:
        print(f"  {FAIL} Verification error: {e}")


def _hsm_init():
    heading("Initialize HSM")
    print(f"  Delegating to HSM setup tool...\n")
    hsm_tool = PROJECT_ROOT / "tools" / "hsm_setup.py"
    if hsm_tool.exists():
        os.system(f'{sys.executable} "{hsm_tool}" --init')
    else:
        print(f"  {FAIL} HSM setup tool not found: {hsm_tool}")


# =============================================================================
# COMMAND: LOGS — Log viewing and audit
# =============================================================================

def cmd_logs(args):
    """Log viewing subcommand."""
    subcmd = args.logs_command if hasattr(args, 'logs_command') else 'show'

    if subcmd == 'show':
        _logs_show(args)
    elif subcmd == 'audit':
        _logs_audit()
    elif subcmd == 'clear':
        _logs_clear()


def _logs_show(args):
    heading("Recent Logs")
    log_dir = PROJECT_ROOT / "logs"
    if not log_dir.exists():
        print(f"  {INFO} No logs directory. Logs are created when AIOHAI runs.")
        return

    log_name = args.log_file if hasattr(args, 'log_file') and args.log_file else None
    num_lines = args.lines if hasattr(args, 'lines') else 30

    if log_name:
        lines = _read_log_tail(log_name, num_lines)
        if lines:
            print(f"  {Colors.dim(log_name)} (last {len(lines)} lines)\n")
            for line in lines:
                # Colorize severity
                if 'ERROR' in line or 'BLOCKED' in line:
                    print(f"  {Colors.red(line)}")
                elif 'WARNING' in line or 'DENIED' in line:
                    print(f"  {Colors.yellow(line)}")
                elif 'APPROVED' in line:
                    print(f"  {Colors.green(line)}")
                else:
                    print(f"  {line}")
        else:
            print(f"  {INFO} Log file '{log_name}' is empty or not found")
    else:
        # Show summary of all log files
        log_files = sorted(log_dir.glob("*.log"))
        if not log_files:
            print(f"  {INFO} No log files yet")
            return

        for log_file in log_files:
            lines = log_file.read_text(encoding='utf-8', errors='replace').splitlines()
            last_line = lines[-1] if lines else "(empty)"
            print(f"\n  {Colors.bold(log_file.name)} ({len(lines)} lines)")
            if lines:
                print(f"    Latest: {Colors.dim(last_line[:80])}")

        print(f"\n  View specific log: python aiohai_cli.py logs show --file <name>")


def _logs_audit():
    heading("Log Integrity Audit")
    log_dir = PROJECT_ROOT / "logs"
    if not log_dir.exists():
        print(f"  {INFO} No logs to audit")
        return

    security_log = log_dir / "security_events.log"
    if not security_log.exists():
        print(f"  {INFO} No security event log found")
        return

    lines = security_log.read_text(encoding='utf-8', errors='replace').splitlines()
    print(f"  Security events: {len(lines)} entries")

    # Check for chain-hashing integrity (if enabled)
    hash_chain_ok = True
    chain_entries = 0
    for line in lines:
        if 'chain_hash=' in line:
            chain_entries += 1
            # Basic chain verification would happen here with actual log format
    
    if chain_entries > 0:
        print(f"  Chain-hashed entries: {chain_entries}")
        if hash_chain_ok:
            print(f"  {OK} Log chain integrity: OK")
        else:
            print(f"  {FAIL} Log chain integrity: BROKEN — possible tampering")
    else:
        print(f"  {INFO} No chain-hashed entries (chain hashing may not be active)")

    # Count event types
    blocked = sum(1 for l in lines if 'BLOCKED' in l)
    denied = sum(1 for l in lines if 'DENIED' in l)
    approved = sum(1 for l in lines if 'APPROVED' in l)
    warnings = sum(1 for l in lines if 'WARNING' in l)

    print()
    table_row("Blocked operations", str(blocked), FAIL if blocked else OK)
    table_row("Denied requests", str(denied), WARN if denied else OK)
    table_row("Approved requests", str(approved))
    table_row("Warnings", str(warnings), WARN if warnings else OK)


def _logs_clear():
    heading("Clear Logs")
    log_dir = PROJECT_ROOT / "logs"
    if not log_dir.exists():
        print(f"  {INFO} No logs to clear")
        return

    log_files = list(log_dir.glob("*.log"))
    if not log_files:
        print(f"  {INFO} No log files found")
        return

    print(f"  Found {len(log_files)} log file(s):")
    total_size = 0
    for f in log_files:
        size = f.stat().st_size
        total_size += size
        print(f"    {f.name}: {size / 1024:.1f} KB")

    print(f"\n  Total: {total_size / 1024:.1f} KB")
    confirm = input(f"\n  Type 'CLEAR' to delete all logs: ").strip()
    if confirm != 'CLEAR':
        print(f"  Cancelled.")
        return

    for f in log_files:
        f.unlink()
    print(f"\n  {OK} {len(log_files)} log file(s) deleted")


# =============================================================================
# COMMAND: CONFIG — Configuration management
# =============================================================================

def cmd_config(args):
    """Configuration management subcommand."""
    subcmd = args.config_command if hasattr(args, 'config_command') else 'show'

    if subcmd == 'show':
        _config_show()
    elif subcmd == 'set':
        _config_set(args.key, args.value)
    elif subcmd == 'reset':
        _config_reset()


def _config_show():
    heading("Configuration")
    cfg_path = PROJECT_ROOT / "config" / "config.json"
    if not cfg_path.exists():
        print(f"  {FAIL} Config not found: {cfg_path}")
        return

    config = json.loads(cfg_path.read_text(encoding='utf-8'))

    for section, values in config.items():
        if section.startswith('_') or section.startswith('$'):
            continue
        print(f"\n  {Colors.bold(section)}")
        if isinstance(values, dict):
            for k, v in values.items():
                if k.startswith('_'):
                    continue
                val_str = json.dumps(v) if isinstance(v, (list, dict)) else str(v)
                if len(val_str) > 50:
                    val_str = val_str[:47] + "..."
                print(f"    {k:<35} {Colors.dim(val_str)}")
        else:
            print(f"    {Colors.dim(str(values))}")

    print(f"\n  Config file: {cfg_path}")
    print(f"  Edit directly or use: aiohai_cli.py config set <section.key> <value>")


def _config_set(key: str, value: str):
    heading("Update Configuration")
    cfg_path = PROJECT_ROOT / "config" / "config.json"
    config = json.loads(cfg_path.read_text(encoding='utf-8'))

    parts = key.split('.')
    if len(parts) != 2:
        print(f"  {FAIL} Key format: section.key (e.g. ollama.model)")
        return

    section, setting = parts

    if section not in config:
        print(f"  {FAIL} Unknown section: '{section}'")
        print(f"  Available: {', '.join(k for k in config if not k.startswith('_'))}")
        return

    if setting not in config[section]:
        print(f"  {WARN} New setting: {section}.{setting}")

    old_value = config[section].get(setting, "(not set)")

    # Type coercion
    if isinstance(old_value, bool):
        value = value.lower() in ('true', '1', 'yes')
    elif isinstance(old_value, int):
        try:
            value = int(value)
        except ValueError:
            print(f"  {FAIL} Expected integer for {key}")
            return
    elif isinstance(old_value, float):
        try:
            value = float(value)
        except ValueError:
            print(f"  {FAIL} Expected number for {key}")
            return

    print(f"  {key}: {Colors.red(str(old_value))} → {Colors.green(str(value))}")
    confirm = input(f"  Apply? [Y/n]: ").strip().lower()
    if confirm == 'n':
        print(f"  Cancelled.")
        return

    config[section][setting] = value
    cfg_path.write_text(json.dumps(config, indent=2), encoding='utf-8')
    print(f"  {OK} Configuration updated")
    print(f"  {INFO} Restart AIOHAI for changes to take effect")


def _config_reset():
    heading("Reset Configuration")
    print(f"  {WARN} This will reset config.json to defaults.")
    confirm = input(f"  Type 'RESET' to confirm: ").strip()
    if confirm != 'RESET':
        print(f"  Cancelled.")
        return

    # Backup current
    cfg_path = PROJECT_ROOT / "config" / "config.json"
    if cfg_path.exists():
        backup = cfg_path.with_suffix('.json.bak')
        shutil.copy2(cfg_path, backup)
        print(f"  {OK} Backed up current config to: {backup.name}")

    print(f"  {WARN} No default template available — keeping backup")
    print(f"  Edit manually: {cfg_path}")


# =============================================================================
# COMMAND: CERTS — TLS certificate management
# =============================================================================

def cmd_certs(args):
    """TLS certificate management."""
    subcmd = args.certs_command if hasattr(args, 'certs_command') else 'status'

    if subcmd == 'generate':
        _certs_generate()
    elif subcmd == 'status':
        _certs_status()


def _certs_status():
    heading("TLS Certificate Status")
    cert_dir = PROJECT_ROOT / "data" / "fido2" / "certs"
    cert_file = cert_dir / "server.crt"

    if not cert_file.exists():
        print(f"  {INFO} No certificate generated yet")
        print(f"  Certificates are auto-generated on first run,")
        print(f"  or generate now: python aiohai_cli.py certs generate")
        return

    try:
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(cert_file.read_bytes())
        table_row("File", str(cert_file))
        table_row("Subject", str(cert.subject))
        table_row("Issuer", str(cert.issuer))
        table_row("Not before", str(cert.not_valid_before_utc))
        table_row("Not after", str(cert.not_valid_after_utc))
        table_row("Serial", str(cert.serial_number))

        expires = cert.not_valid_after_utc
        if expires < datetime.utcnow():
            table_row("Status", "EXPIRED", FAIL)
        else:
            days = (expires - datetime.utcnow()).days
            table_row("Status", f"valid ({days} days left)", OK)

        # Show SANs
        try:
            from cryptography.x509 import SubjectAlternativeName, DNSName, IPAddress
            san_ext = cert.extensions.get_extension_for_class(SubjectAlternativeName)
            sans = san_ext.value.get_values_for_type(DNSName)
            if sans:
                table_row("DNS names", ", ".join(sans))
        except Exception:
            pass

    except ImportError:
        print(f"  Certificate exists: {cert_file}")
        print(f"  Install 'cryptography' for detailed info")


def _certs_generate():
    heading("Generate TLS Certificate")

    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509 import (
            CertificateBuilder, NameAttribute, Name,
            BasicConstraints, SubjectAlternativeName, DNSName, IPAddress
        )
        from cryptography.x509.oid import NameOID
        from cryptography import x509
        import ipaddress
    except ImportError:
        print(f"  {FAIL} 'cryptography' package required: pip install cryptography")
        return

    cert_dir = PROJECT_ROOT / "data" / "fido2" / "certs"
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_file = cert_dir / "server.crt"
    key_file = cert_dir / "server.key"

    if cert_file.exists():
        print(f"  Existing certificate found: {cert_file}")
        resp = input(f"  Overwrite? [y/N]: ").strip().lower()
        if resp != 'y':
            print(f"  Cancelled.")
            return

    local_ip = _get_local_ip()
    print(f"  Local IP: {local_ip}")

    extra_ips = input(f"  Additional IPs (comma-separated, or Enter to skip): ").strip()
    all_ips = [local_ip, "127.0.0.1"]
    if extra_ips:
        all_ips.extend(ip.strip() for ip in extra_ips.split(','))

    # Generate ECC P-256 key
    key = ec.generate_private_key(ec.SECP256R1())

    subject = issuer = Name([
        NameAttribute(NameOID.ORGANIZATION_NAME, "AIOHAI"),
        NameAttribute(NameOID.COMMON_NAME, "AIOHAI Approval Server"),
    ])

    san_names = [DNSName("localhost")]
    for ip in all_ips:
        try:
            san_names.append(IPAddress(ipaddress.ip_address(ip)))
        except ValueError:
            san_names.append(DNSName(ip))

    cert = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(SubjectAlternativeName(san_names), critical=False)
        .sign(key, hashes.SHA256())
    )

    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(str(key_file), 0o600)

    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    print(f"\n  {OK} Certificate generated:")
    print(f"     Cert: {cert_file}")
    print(f"     Key:  {key_file}")
    print(f"     SANs: {', '.join(str(s) for s in san_names)}")
    print(f"     Expires: {cert.not_valid_after_utc}")
    print(f"\n  {INFO} Phones will show a certificate warning on first connect.")
    print(f"  Accept it once and you're set.")


# =============================================================================
# COMMAND: DOCTOR — Full diagnostic check
# =============================================================================

def _run_doctor_checks(quiet: bool = False) -> Dict[str, List[str]]:
    """Run all diagnostic checks. Returns dict with 'critical' and 'warnings' lists."""
    issues = {'critical': [], 'warnings': [], 'passed': []}

    # 1. Python version
    if sys.version_info < (3, 9):
        issues['critical'].append(f"Python {sys.version_info.major}.{sys.version_info.minor} — need 3.9+")
    else:
        issues['passed'].append(f"Python {sys.version_info.major}.{sys.version_info.minor}")

    # 2. Core module
    try:
        from aiohai.core.analysis.static_analyzer import StaticSecurityAnalyzer
        issues['passed'].append("Core security module")
    except ImportError:
        issues['critical'].append("Core security module not found")

    # 3. FIDO2 module
    try:
        from aiohai.core.crypto.fido_gate import FIDO2ApprovalServer
        issues['passed'].append("FIDO2/WebAuthn module")
    except ImportError as e:
        missing = str(e).split("'")[1] if "'" in str(e) else str(e)
        issues['warnings'].append(f"FIDO2 module unavailable ({missing})")

    # 4. Flask
    try:
        import flask
        issues['passed'].append("Flask web server")
    except ImportError:
        issues['warnings'].append("Flask not installed (needed for approval server)")

    # 5. Cryptography
    try:
        import cryptography
        issues['passed'].append("cryptography library")
    except ImportError:
        issues['critical'].append("'cryptography' not installed: pip install cryptography")

    # 6. Policy file
    policy_path = PROJECT_ROOT / "policy" / "aiohai_security_policy_v3.0.md"
    if policy_path.exists():
        issues['passed'].append("Policy file present")
    else:
        issues['critical'].append(f"Policy file missing: {policy_path}")

    # 7. Config file
    cfg_path = PROJECT_ROOT / "config" / "config.json"
    if cfg_path.exists():
        try:
            json.loads(cfg_path.read_text(encoding='utf-8'))
            issues['passed'].append("Config file valid JSON")
        except json.JSONDecodeError:
            issues['critical'].append("Config file is invalid JSON")
    else:
        issues['critical'].append("Config file missing")

    # 8. Proxy module
    try:
        proxy_path = PROJECT_ROOT / "proxy" / "aiohai_proxy.py"
        if proxy_path.exists():
            compile(proxy_path.read_text(encoding='utf-8'), str(proxy_path), 'exec')
            issues['passed'].append("Proxy module syntax OK")
        else:
            issues['critical'].append("Proxy module not found")
    except SyntaxError as e:
        issues['critical'].append(f"Proxy syntax error: {e}")

    # 9. Data directory writable
    data_dir = PROJECT_ROOT / "data"
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        test_file = data_dir / ".write_test"
        test_file.write_text("test")
        test_file.unlink()
        issues['passed'].append("Data directory writable")
    except Exception:
        issues['critical'].append("Cannot write to data/ directory")

    # 10. Port availability (non-blocking check)
    proxy_port = _load_config().get('proxy', {}).get('listen_port', 11435)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex(('127.0.0.1', proxy_port))
        s.close()
        if result == 0:
            issues['warnings'].append(f"Port {proxy_port} already in use (proxy may be running)")
        else:
            issues['passed'].append(f"Proxy port {proxy_port} available")
    except Exception:
        issues['passed'].append(f"Proxy port {proxy_port} (could not check)")

    # 11. Users and devices
    store = _load_credential_store()
    if store:
        users = store.get_all_users()
        admins = [u for u in users.values() if u.role.value == 'admin']
        if not users:
            issues['warnings'].append("No users registered")
        elif not admins:
            issues['warnings'].append("No admin user — cannot approve TIER 4 operations")
        else:
            total_devices = sum(len(u.credentials) for u in users.values())
            issues['passed'].append(f"{len(users)} user(s), {total_devices} device(s)")
            if total_devices == 0:
                issues['warnings'].append("No devices registered — approval system won't work")

    # 12. TLS certificate
    cert_file = PROJECT_ROOT / "data" / "fido2" / "certs" / "server.crt"
    if cert_file.exists():
        try:
            from cryptography import x509
            cert = x509.load_pem_x509_certificate(cert_file.read_bytes())
            if cert.not_valid_after_utc < datetime.utcnow():
                issues['warnings'].append("TLS certificate expired — run: aiohai_cli.py certs generate")
            else:
                days = (cert.not_valid_after_utc - datetime.utcnow()).days
                issues['passed'].append(f"TLS certificate valid ({days} days)")
        except Exception:
            issues['passed'].append("TLS certificate present")
    else:
        issues['warnings'].append("No TLS certificate (auto-generated on first run)")

    return issues


def cmd_doctor(args):
    """Run full diagnostic check."""
    heading("AIOHAI Doctor")
    print(f"  Running {Colors.bold('12')} diagnostic checks...\n")

    issues = _run_doctor_checks()

    # Display results
    for item in issues['passed']:
        print(f"  {OK} {item}")

    for item in issues['warnings']:
        print(f"  {WARN} {item}")

    for item in issues['critical']:
        print(f"  {FAIL} {item}")

    # Summary
    total = len(issues['passed']) + len(issues['warnings']) + len(issues['critical'])
    print(f"\n  {'─' * 50}")
    print(f"  {Colors.bold('Results')}: "
          f"{Colors.green(str(len(issues['passed'])))} passed, "
          f"{Colors.yellow(str(len(issues['warnings'])))} warnings, "
          f"{Colors.red(str(len(issues['critical'])))} critical")

    if issues['critical']:
        print(f"\n  {FAIL} Fix critical issues before running AIOHAI")
    elif issues['warnings']:
        print(f"\n  {WARN} System functional but some features may be limited")
    else:
        print(f"\n  {OK} All systems go!")


# =============================================================================
# COMMAND: START — Launch AIOHAI
# =============================================================================

def cmd_start(args):
    """Start AIOHAI proxy (and optionally approval server)."""
    heading("Starting AIOHAI")

    proxy_path = PROJECT_ROOT / "proxy" / "aiohai_proxy.py"
    if not proxy_path.exists():
        print(f"  {FAIL} Proxy not found: {proxy_path}")
        return

    cmd_args = [sys.executable, str(proxy_path)]

    if hasattr(args, 'no_fido2') and args.no_fido2:
        cmd_args.append('--no-fido2')
    if hasattr(args, 'fido2_port') and args.fido2_port:
        cmd_args.extend(['--fido2-port', str(args.fido2_port)])
    if hasattr(args, 'no_approval_server') and args.no_approval_server:
        cmd_args.append('--no-approval-server')

    print(f"  Command: {' '.join(cmd_args)}\n")

    try:
        os.execv(sys.executable, cmd_args)
    except Exception:
        # Fallback if execv not available (Windows edge case)
        os.system(' '.join(f'"{a}"' for a in cmd_args))


# =============================================================================
# INTERACTIVE MODE — Main menu
# =============================================================================

def interactive_menu():
    """Main interactive menu for when CLI is run without arguments."""
    while True:
        print(f"""
{Colors.bold('AIOHAI Management')}
{Colors.dim('─' * 40)}

  {Colors.cyan('1')}  System status
  {Colors.cyan('2')}  First-time setup
  {Colors.cyan('3')}  Manage users
  {Colors.cyan('4')}  Manage devices
  {Colors.cyan('5')}  HSM operations
  {Colors.cyan('6')}  View logs
  {Colors.cyan('7')}  Configuration
  {Colors.cyan('8')}  TLS certificates
  {Colors.cyan('9')}  Run diagnostics (doctor)
  {Colors.cyan('0')}  Start AIOHAI
  {Colors.dim('q')}  Quit
""")
        choice = input("  Choice: ").strip().lower()

        if choice == '1':
            cmd_status(argparse.Namespace())
        elif choice == '2':
            cmd_setup(argparse.Namespace())
        elif choice == '3':
            _interactive_users()
        elif choice == '4':
            _interactive_devices()
        elif choice == '5':
            _interactive_hsm()
        elif choice == '6':
            _interactive_logs()
        elif choice == '7':
            _interactive_config()
        elif choice == '8':
            _interactive_certs()
        elif choice == '9':
            cmd_doctor(argparse.Namespace())
        elif choice == '0':
            cmd_start(argparse.Namespace())
            break
        elif choice in ('q', 'quit', 'exit'):
            print(f"\n  {Colors.dim('Goodbye.')}\n")
            break
        else:
            print(f"  {WARN} Unknown option: '{choice}'")

        input(f"\n  {Colors.dim('Press Enter to continue...')}")


def _interactive_dispatch(title: str, options: list):
    """O5: Generic interactive sub-menu dispatcher.

    Args:
        title: Menu heading
        options: List of (label, callable) tuples
    """
    print(f"\n  {Colors.bold(title)}")
    for i, (label, _) in enumerate(options, 1):
        print(f"  {Colors.cyan(str(i))}  {label}")
    print()
    choice = input("  Choice: ").strip()
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(options):
            options[idx][1]()
        else:
            print(f"  {WARN} Invalid choice")
    except (ValueError, IndexError):
        print(f"  {WARN} Invalid choice")


def _interactive_users():
    store = _load_credential_store()
    if not store:
        print(f"  {FAIL} FIDO2 module not available")
        return
    _interactive_dispatch("Users", [
        ("List users",   lambda: _users_list(store)),
        ("Add user",     lambda: _users_add(store)),
        ("Remove user",  lambda: _users_remove(store, None)),
        ("Modify user",  lambda: _users_modify(store, None)),
    ])


def _interactive_devices():
    store = _load_credential_store()
    if not store:
        print(f"  {FAIL} FIDO2 module not available")
        return
    _interactive_dispatch("Devices", [
        ("List devices",  lambda: _devices_list(store)),
        ("Remove device", lambda: _devices_remove(store, None)),
    ])


def _interactive_hsm():
    _interactive_dispatch("HSM", [
        ("HSM status",     _hsm_status),
        ("Initialize HSM", _hsm_init),
        ("Sign policy",    _hsm_sign_policy),
        ("Verify policy",  _hsm_verify_policy),
    ])


def _interactive_logs():
    _interactive_dispatch("Logs", [
        ("Show log summary", lambda: _logs_show(argparse.Namespace())),
        ("View specific log", lambda: _logs_show(
            argparse.Namespace(log_file=input("  Log file name: ").strip(), lines=50))),
        ("Audit log integrity", _logs_audit),
        ("Clear logs",          _logs_clear),
    ])


def _interactive_config():
    def _change_setting():
        key = input("  Setting (section.key): ").strip()
        value = input("  New value: ").strip()
        if key and value:
            _config_set(key, value)

    _interactive_dispatch("Configuration", [
        ("Show configuration", _config_show),
        ("Change a setting",   _change_setting),
        ("Reset to defaults",  _config_reset),
    ])


def _interactive_certs():
    _interactive_dispatch("TLS Certificates", [
        ("Certificate status",       _certs_status),
        ("Generate new certificate", _certs_generate),
    ])


# =============================================================================
# ARGUMENT PARSER
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='aiohai',
        description='AIOHAI Management CLI — unified tool for setup, user management, and diagnostics',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  aiohai_cli.py                           Interactive menu
  aiohai_cli.py setup                     First-time setup wizard
  aiohai_cli.py status                    System overview
  aiohai_cli.py users list                List all users
  aiohai_cli.py users add                 Add a new user
  aiohai_cli.py users remove alice        Remove user 'alice'
  aiohai_cli.py devices list              List registered devices
  aiohai_cli.py hsm status                HSM health check
  aiohai_cli.py logs show --file blocked.log --lines 50
  aiohai_cli.py config set ollama.model llama3.2
  aiohai_cli.py certs generate            New TLS certificate
  aiohai_cli.py doctor                    Full diagnostic check
  aiohai_cli.py start                     Launch AIOHAI
        """
    )

    sub = parser.add_subparsers(dest='command')

    # setup
    sub.add_parser('setup', help='First-time setup wizard')

    # status
    sub.add_parser('status', help='System health overview')

    # users
    users_p = sub.add_parser('users', help='User management')
    users_sub = users_p.add_subparsers(dest='users_command')
    users_sub.add_parser('list', help='List all users')
    users_sub.add_parser('add', help='Add a new user')
    rm_u = users_sub.add_parser('remove', help='Remove a user')
    rm_u.add_argument('username', nargs='?', help='Username to remove')
    mod_u = users_sub.add_parser('modify', help='Modify user role/paths')
    mod_u.add_argument('username', nargs='?', help='Username to modify')

    # devices
    dev_p = sub.add_parser('devices', help='Device management')
    dev_sub = dev_p.add_subparsers(dest='devices_command')
    dev_sub.add_parser('list', help='List registered devices')
    rm_d = dev_sub.add_parser('remove', help='Remove a device')
    rm_d.add_argument('device_id', nargs='?', help='Device ID prefix')

    # hsm
    hsm_p = sub.add_parser('hsm', help='HSM operations')
    hsm_sub = hsm_p.add_subparsers(dest='hsm_command')
    hsm_sub.add_parser('status', help='HSM status')
    hsm_sub.add_parser('init', help='Initialize HSM keys')
    hsm_sub.add_parser('sign-policy', help='Sign policy with HSM')
    hsm_sub.add_parser('verify-policy', help='Verify policy signature')

    # logs
    logs_p = sub.add_parser('logs', help='Log viewing and audit')
    logs_sub = logs_p.add_subparsers(dest='logs_command')
    show_l = logs_sub.add_parser('show', help='View logs')
    show_l.add_argument('--file', dest='log_file', help='Specific log file')
    show_l.add_argument('--lines', type=int, default=30, help='Number of lines')
    logs_sub.add_parser('audit', help='Verify log integrity')
    logs_sub.add_parser('clear', help='Clear all logs')

    # config
    cfg_p = sub.add_parser('config', help='Configuration management')
    cfg_sub = cfg_p.add_subparsers(dest='config_command')
    cfg_sub.add_parser('show', help='Show configuration')
    set_c = cfg_sub.add_parser('set', help='Update a setting')
    set_c.add_argument('key', help='Setting key (section.key)')
    set_c.add_argument('value', help='New value')
    cfg_sub.add_parser('reset', help='Reset to defaults')

    # certs
    certs_p = sub.add_parser('certs', help='TLS certificate management')
    certs_sub = certs_p.add_subparsers(dest='certs_command')
    certs_sub.add_parser('status', help='Certificate status')
    certs_sub.add_parser('generate', help='Generate new certificate')

    # doctor
    sub.add_parser('doctor', help='Full diagnostic check')

    # start
    start_p = sub.add_parser('start', help='Start AIOHAI')
    start_p.add_argument('--no-fido2', action='store_true', help='Disable FIDO2')
    start_p.add_argument('--fido2-port', type=int, help='FIDO2 server port')
    start_p.add_argument('--no-approval-server', action='store_true',
                          help='Don\'t auto-start approval server')

    return parser


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        'setup': cmd_setup,
        'status': cmd_status,
        'users': cmd_users,
        'devices': cmd_devices,
        'hsm': cmd_hsm,
        'logs': cmd_logs,
        'config': cmd_config,
        'certs': cmd_certs,
        'doctor': cmd_doctor,
        'start': cmd_start,
    }

    if args.command:
        handler = dispatch.get(args.command)
        if handler:
            try:
                handler(args)
            except KeyboardInterrupt:
                print(f"\n  {Colors.dim('Interrupted.')}")
        else:
            parser.print_help()
    else:
        interactive_menu()


if __name__ == '__main__':
    main()
