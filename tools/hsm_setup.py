#!/usr/bin/env python3
"""
AIOHAI HSM Setup Tool
========================

Initializes Nitrokey HSM 2 with the required keys for AIOHAI:
  1. Policy signing key (RSA-2048) - for policy file integrity
  2. Log signing key (RSA-2048) - for tamper-evident audit logs
  3. Entropy key (AES-256) - for secure random generation

Prerequisites:
  - Nitrokey HSM 2 connected via USB
  - OpenSC installed (provides PKCS#11 library)
  - PyKCS11 installed: pip install PyKCS11

Usage:
  python hsm_setup.py --init          # Initialize HSM with new keys
  python hsm_setup.py --sign-policy   # Sign the policy file
  python hsm_setup.py --status        # Check HSM status
  python hsm_setup.py --backup        # Create encrypted backup

Author: AIOHAI Project
Version: 1.0.0
"""

import os
import sys
import json
import getpass
import argparse
import hashlib
from pathlib import Path
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from security.hsm_integration import (
        get_hsm_manager, 
        NitrokeyHSMManager,
        HSMStatus,
        PKCS11_AVAILABLE
    )
except ImportError:
    print("ERROR: Could not import hsm_integration module")
    print("Make sure you're running from the AIOHAI directory")
    sys.exit(1)


# =============================================================================
# CONSTANTS
# =============================================================================

DEFAULT_POLICY_PATH = Path(__file__).parent.parent / "policy" / "aiohai_security_policy_v3.0.md"
DEFAULT_SIGNATURE_PATH = Path(__file__).parent.parent / "policy" / "policy.sig"
DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config" / "hsm_config.json"


# =============================================================================
# SETUP FUNCTIONS
# =============================================================================

def print_banner():
    """Print setup banner."""
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                    AIOHAI HSM Setup Tool                                  ║
║                    ════════════════════════                                  ║
║                                                                              ║
║  This tool initializes your Nitrokey HSM 2 for use with AIOHAI.         ║
║                                                                              ║
║  Hardware Required: Nitrokey HSM 2                                          ║
║  Software Required: OpenSC (PKCS#11 library)                                ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)


def check_prerequisites():
    """Check that all prerequisites are met."""
    print("\n=== Checking Prerequisites ===\n")
    
    issues = []
    
    # Check PyKCS11
    if PKCS11_AVAILABLE:
        print("✅ PyKCS11 library installed")
    else:
        print("❌ PyKCS11 library not installed")
        issues.append("Install PyKCS11: pip install PyKCS11")
    
    # Check for OpenSC
    opensc_paths = [
        '/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so',
        '/usr/lib/opensc-pkcs11.so',
        'C:\\Windows\\System32\\opensc-pkcs11.dll',
        'C:\\Program Files\\OpenSC Project\\OpenSC\\pkcs11\\opensc-pkcs11.dll',
    ]
    
    opensc_found = any(os.path.exists(p) for p in opensc_paths)
    if opensc_found:
        print("✅ OpenSC PKCS#11 library found")
    else:
        print("❌ OpenSC PKCS#11 library not found")
        issues.append("Install OpenSC: https://github.com/OpenSC/OpenSC/releases")
    
    # Check policy file exists
    if DEFAULT_POLICY_PATH.exists():
        print(f"✅ Policy file found: {DEFAULT_POLICY_PATH.name}")
    else:
        print(f"⚠️  Policy file not found: {DEFAULT_POLICY_PATH}")
        issues.append("Policy file missing - will need to specify path manually")
    
    if issues:
        print("\n⚠️  Issues found:")
        for issue in issues:
            print(f"   • {issue}")
        return False
    
    print("\n✅ All prerequisites met")
    return True


def initialize_hsm(hsm: NitrokeyHSMManager, so_pin: str, user_pin: str):
    """
    Initialize HSM with required keys.
    
    WARNING: This will create new keys. Existing keys with same labels
    will NOT be overwritten (for safety).
    """
    print("\n=== Initializing HSM Keys ===\n")
    
    # Note: Key generation requires SO (Security Officer) access
    # For Nitrokey HSM 2, keys are typically generated using:
    #   sc-hsm-tool or pkcs11-tool
    # 
    # This function will CHECK for keys and provide guidance
    
    keys = hsm.list_keys()
    key_labels = [k.label for k in keys]
    
    required_keys = [
        ('aiohai-policy-key', 'RSA-2048', 'Policy signing/verification'),
        ('aiohai-log-key', 'RSA-2048', 'Log entry signing'),
        ('aiohai-entropy-key', 'AES-256', 'Random number generation'),
    ]
    
    missing_keys = []
    for label, key_type, purpose in required_keys:
        if label in key_labels:
            print(f"✅ {label} ({key_type}) - exists")
        else:
            print(f"❌ {label} ({key_type}) - MISSING")
            missing_keys.append((label, key_type, purpose))
    
    if missing_keys:
        print("\n" + "=" * 60)
        print("MANUAL KEY GENERATION REQUIRED")
        print("=" * 60)
        print("\nThe following keys need to be created using pkcs11-tool:")
        print("(This is a one-time setup)\n")
        
        for label, key_type, purpose in missing_keys:
            if 'RSA' in key_type:
                print(f"# {purpose}")
                print(f"pkcs11-tool --module /usr/lib/opensc-pkcs11.so \\")
                print(f"    --login --pin {user_pin} \\")
                print(f"    --keypairgen --key-type rsa:2048 \\")
                print(f"    --label '{label}'")
                print()
            elif 'AES' in key_type:
                print(f"# {purpose}")
                print(f"pkcs11-tool --module /usr/lib/opensc-pkcs11.so \\")
                print(f"    --login --pin {user_pin} \\")
                print(f"    --keygen --key-type aes:256 \\")
                print(f"    --label '{label}'")
                print()
        
        print("After creating keys, run this setup again to verify.")
        return False
    
    print("\n✅ All required keys present in HSM")
    return True


def sign_policy_file(hsm: NitrokeyHSMManager, policy_path: Path, signature_path: Path):
    """Sign the policy file with HSM."""
    print("\n=== Signing Policy File ===\n")
    
    if not policy_path.exists():
        print(f"❌ Policy file not found: {policy_path}")
        return False
    
    # Read policy
    with open(policy_path, 'rb') as f:
        policy_content = f.read()
    
    policy_hash = hashlib.sha256(policy_content).hexdigest()
    print(f"Policy file: {policy_path.name}")
    print(f"Policy size: {len(policy_content):,} bytes")
    print(f"Policy hash: {policy_hash[:32]}...")
    
    print("\n⚠️  TOUCH YOUR NITROKEY HSM TO SIGN")
    print("   (The device should blink)\n")
    
    success, signature, message = hsm.sign_policy(policy_content, require_touch=True)
    
    if success:
        # Save signature
        with open(signature_path, 'wb') as f:
            f.write(signature)
        
        print(f"✅ Policy signed successfully")
        print(f"   Signature saved to: {signature_path}")
        print(f"   Signature size: {len(signature)} bytes")
        
        # Also save metadata
        metadata_path = signature_path.with_suffix('.meta.json')
        metadata = {
            'policy_file': policy_path.name,
            'policy_hash': policy_hash,
            'signed_at': datetime.now().isoformat(),
            'signature_file': signature_path.name,
        }
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        print(f"   Metadata saved to: {metadata_path.name}")
        
        return True
    else:
        print(f"❌ Signing failed: {message}")
        return False


def verify_policy_signature(hsm: NitrokeyHSMManager, policy_path: Path, signature_path: Path):
    """Verify the policy file signature."""
    print("\n=== Verifying Policy Signature ===\n")
    
    if not policy_path.exists():
        print(f"❌ Policy file not found: {policy_path}")
        return False
    
    if not signature_path.exists():
        print(f"❌ Signature file not found: {signature_path}")
        print("   Run with --sign-policy first")
        return False
    
    # Read files
    with open(policy_path, 'rb') as f:
        policy_content = f.read()
    with open(signature_path, 'rb') as f:
        signature = f.read()
    
    # Verify
    result = hsm.verify_policy_signature(policy_content, signature)
    
    if result.is_valid:
        print("✅ Policy signature is VALID")
        print(f"   Policy hash: {result.policy_hash[:32]}...")
        print(f"   Signed by: {result.signer_key_id}")
        return True
    else:
        print("❌ Policy signature is INVALID")
        print(f"   Error: {result.error_message}")
        print("\n   This could mean:")
        print("   • The policy file was modified after signing")
        print("   • The signature file is corrupted")
        print("   • The signing key was changed")
        return False


def show_status(hsm: NitrokeyHSMManager):
    """Show HSM status."""
    print("\n=== HSM Status ===\n")
    
    report = hsm.get_status_report()
    
    print(f"Status: {report['status']}")
    print(f"Connected: {report['connected']}")
    
    if 'token' in report:
        print(f"\nToken Info:")
        print(f"  Label: {report['token']['label']}")
        print(f"  Manufacturer: {report['token']['manufacturer']}")
        print(f"  Serial: {report['token']['serial']}")
    
    if report['keys']:
        print(f"\nKeys ({len(report['keys'])}):")
        for key in report['keys']:
            print(f"  • {key['label']} ({key['type']})")
            caps = []
            if key.get('can_sign'):
                caps.append('sign')
            if key.get('can_verify'):
                caps.append('verify')
            if caps:
                print(f"    Capabilities: {', '.join(caps)}")
    
    if report.get('error'):
        print(f"\nError: {report['error']}")


def create_backup_guidance():
    """Provide guidance for HSM backup."""
    print("\n=== HSM Backup Guidance ===\n")
    print("""
IMPORTANT: Back up your HSM keys!

If your Nitrokey HSM 2 is lost, stolen, or fails, you will lose:
  • Ability to verify old policy signatures
  • Ability to verify old log entries
  • Ability to sign new policies (without re-initializing)

BACKUP OPTIONS:

1. DKEK (Device Key Encryption Key) Backup:
   ─────────────────────────────────────────
   The Nitrokey HSM 2 supports DKEK backup, which allows you to
   export encrypted keys that can be imported to a new device.
   
   # Initialize DKEK (do this BEFORE generating keys)
   sc-hsm-tool --create-dkek-share dkek-share-1.pbe
   sc-hsm-tool --create-dkek-share dkek-share-2.pbe
   
   # Later, to export keys:
   sc-hsm-tool --wrap-key policy-key-backup.bin --key-reference 1
   
   Store DKEK shares in separate secure locations (e.g., safe deposit boxes).

2. Key Ceremony with Multiple HSMs:
   ──────────────────────────────────
   For maximum security, initialize multiple HSMs simultaneously
   with the same keys using DKEK sharing.

3. Document Your Setup:
   ─────────────────────
   Record (securely):
   • HSM Serial Number
   • When keys were generated
   • Key labels and purposes
   • SO-PIN (encrypted/split)
   
WARNING: Never store PINs in plain text or on the same system as the HSM.
    """)


def save_config(policy_path: Path, signature_path: Path):
    """Save HSM configuration for AIOHAI."""
    config = {
        'hsm': {
            'enabled': True,
            'pkcs11_library': 'auto',
            'require_for_startup': True,
            'policy_key_label': 'aiohai-policy-key',
            'log_key_label': 'aiohai-log-key',
            'entropy_key_label': 'aiohai-entropy-key',
        },
        'policy': {
            'path': str(policy_path),
            'signature_path': str(signature_path),
        }
    }
    
    DEFAULT_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(DEFAULT_CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=2)
    
    print(f"\n✅ Configuration saved to: {DEFAULT_CONFIG_PATH}")


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="AIOHAI HSM Setup Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python hsm_setup.py --init              # Initialize HSM with keys
  python hsm_setup.py --sign-policy       # Sign the policy file
  python hsm_setup.py --verify            # Verify policy signature
  python hsm_setup.py --status            # Check HSM status
  python hsm_setup.py --backup-guide      # Show backup guidance
        """
    )
    
    parser.add_argument('--init', action='store_true', 
                        help='Initialize HSM with required keys')
    parser.add_argument('--sign-policy', action='store_true',
                        help='Sign the policy file')
    parser.add_argument('--verify', action='store_true',
                        help='Verify policy signature')
    parser.add_argument('--status', action='store_true',
                        help='Show HSM status')
    parser.add_argument('--backup-guide', action='store_true',
                        help='Show backup guidance')
    parser.add_argument('--policy', type=Path, default=DEFAULT_POLICY_PATH,
                        help='Path to policy file')
    parser.add_argument('--signature', type=Path, default=DEFAULT_SIGNATURE_PATH,
                        help='Path to signature file')
    parser.add_argument('--pin', help='HSM PIN (will prompt if not provided)')
    parser.add_argument('--mock', action='store_true',
                        help='Use mock HSM for testing (NO SECURITY)')
    
    args = parser.parse_args()
    
    # Default to status if no command
    if not any([args.init, args.sign_policy, args.verify, args.status, args.backup_guide]):
        args.status = True
    
    print_banner()
    
    # Backup guide doesn't need HSM
    if args.backup_guide:
        create_backup_guidance()
        return 0
    
    # Check prerequisites
    if not args.mock and not check_prerequisites():
        print("\n❌ Prerequisites not met. Please resolve issues above.")
        return 1
    
    # Get HSM manager
    hsm = get_hsm_manager(use_mock=args.mock)
    
    # Initialize connection
    print("\n=== Connecting to HSM ===\n")
    success, msg = hsm.initialize()
    print(msg)
    
    if not success:
        if not args.mock:
            print("\n❌ Could not connect to HSM")
            print("   • Is the Nitrokey HSM 2 plugged in?")
            print("   • Check USB connection")
            print("   • Try a different USB port")
            return 1
    
    # Get PIN
    pin = args.pin
    if not pin:
        pin = getpass.getpass("Enter HSM User PIN: ")
    
    # Login
    success, msg = hsm.login(pin)
    print(msg)
    
    if not success:
        print("\n❌ Login failed")
        return 1
    
    # Execute command
    try:
        if args.init:
            so_pin = getpass.getpass("Enter HSM SO-PIN (for key generation): ")
            success = initialize_hsm(hsm, so_pin, pin)
            if success:
                # Also sign policy after init
                print("\nWould you like to sign the policy file now? [Y/n] ", end='')
                response = input().strip().lower()
                if response != 'n':
                    sign_policy_file(hsm, args.policy, args.signature)
                    save_config(args.policy, args.signature)
            return 0 if success else 1
            
        elif args.sign_policy:
            success = sign_policy_file(hsm, args.policy, args.signature)
            if success:
                save_config(args.policy, args.signature)
            return 0 if success else 1
            
        elif args.verify:
            success = verify_policy_signature(hsm, args.policy, args.signature)
            return 0 if success else 1
            
        elif args.status:
            show_status(hsm)
            return 0
            
    finally:
        hsm.logout()
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
