#!/usr/bin/env python3
"""
AIOHAI Device Registration Tool
====================================

Sets up users and guides through WebAuthn authenticator registration.
Supports both interactive CLI setup and programmatic use.

Usage:
  python register_devices.py --setup          # Full interactive setup
  python register_devices.py --add-user       # Add a single user
  python register_devices.py --list           # List users and devices
  python register_devices.py --server         # Start registration server

Author: AIOHAI Project
Version: 1.0.0
"""

import os
import sys
import json
import argparse
import logging
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from aiohai.core.crypto.credentials import CredentialStore
from aiohai.core.crypto.fido_gate import FIDO2ApprovalServer
from aiohai.core.types import UserRole

# Map old names for template compatibility
PermissionLevel = UserRole


# =============================================================================
# CONSTANTS
# =============================================================================

DEFAULT_CONFIG = Path(__file__).parent.parent / 'config' / 'fido2_config.json'

# Family templates for quick setup
FAMILY_TEMPLATES = {
    'admin': {
        'display_name_hint': 'Primary admin (you)',
        'permission': PermissionLevel.ADMIN,
        'path_restrictions': [],
        'suggested_devices': [
            ('Nitrokey 3A NFC', 'security_key'),
            ('iPhone (Face ID)', 'platform'),
        ],
    },
    'spouse': {
        'display_name_hint': 'Spouse / partner',
        'permission': PermissionLevel.TRUSTED_ADULT,
        'path_restrictions': [],
        'suggested_devices': [
            ('iPhone / Android (Biometric)', 'platform'),
        ],
    },
    'teen': {
        'display_name_hint': 'Teenager',
        'permission': PermissionLevel.RESTRICTED,
        'path_restrictions': ['D:\\Users\\{name}\\*', 'D:\\Shared\\*'],
        'suggested_devices': [
            ('Phone (Biometric)', 'platform'),
        ],
    },
    'guest': {
        'display_name_hint': 'Temporary guest',
        'permission': PermissionLevel.GUEST,
        'path_restrictions': ['D:\\Shared\\Guest\\*'],
        'suggested_devices': [],
    },
}


# =============================================================================
# SETUP WIZARD
# =============================================================================

def full_setup_wizard(manager: CredentialStore):
    """Run the full interactive setup wizard."""
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║              AIOHAI Device Registration Wizard                ║
║              ═══════════════════════════════════                 ║
║                                                                  ║
║  This wizard will help you:                                     ║
║    1. Create user accounts for your family                      ║
║    2. Set permission levels                                     ║
║    3. Guide you through registering authenticators              ║
║       (Nitrokey 3A NFC, Face ID, Fingerprint)                   ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
    """)
    
    # Check existing users
    existing = manager.get_all_users()
    if existing:
        print(f"Found {len(existing)} existing user(s):")
        for username, u in existing.items():
            print(f"  • {username}: {u.username} ({u.role.value})")
        print()
        resp = input("Start fresh (delete existing) or add to them? [add/fresh]: ").strip().lower()
        if resp == 'fresh':
            print("⚠️  This would clear all users and devices.")
            confirm = input("Type 'RESET' to confirm: ").strip()
            if confirm == 'RESET':
                manager._users.clear()
                manager._save()
                print("✅ Reset complete.\n")
            else:
                print("Reset cancelled.\n")
    
    # Step 1: Create admin user
    print("=" * 60)
    print("STEP 1: Create Admin Account (You)")
    print("=" * 60)
    
    if not any(u.role.value == 'admin' for u in manager.get_all_users().values()):
        admin_id = input("\nYour user ID (e.g., 'dad', 'admin'): ").strip() or 'admin'
        admin_name = input(f"Your display name (e.g., 'Dad'): ").strip() or admin_id.title()
        
        manager.add_user(
            username=admin_id,
            role=PermissionLevel.ADMIN,
        )
        print(f"✅ Admin account created: {admin_id}")
    else:
        admin_user = next(u for u in manager.get_all_users().values() if u.role.value == 'admin')
        print(f"✅ Admin account already exists: {admin_user.username}")
        admin_id = admin_user.username
    
    # Step 2: Additional family members
    print(f"\n{'=' * 60}")
    print("STEP 2: Add Family Members (Optional)")
    print("=" * 60)
    
    while True:
        print("\nFamily member templates:")
        print("  1. Spouse / Partner  (trusted_adult — most access)")
        print("  2. Teenager          (restricted — own folders only)")
        print("  3. Guest             (guest — read-only, limited)")
        print("  4. Custom            (choose permission manually)")
        print("  5. Done — skip to device registration")
        
        choice = input("\nChoice [1-5]: ").strip()
        
        if choice == '5' or choice == '':
            break
        
        if choice in ('1', '2', '3', '4'):
            template_key = {'1': 'spouse', '2': 'teen', '3': 'guest'}.get(choice)
            
            user_id = input("User ID (e.g., 'spouse', 'teen'): ").strip()
            if not user_id:
                continue
            
            display_name = input(f"Display name: ").strip() or user_id.title()
            
            if choice == '4':
                print("\nPermission levels:")
                print("  admin          — Full access, manage security")
                print("  trusted_adult  — Most access, no security config changes")
                print("  restricted     — Own folders only")
                print("  guest          — Read-only, limited folders")
                perm_str = input("Permission: ").strip()
                try:
                    permission = PermissionLevel(perm_str)
                except ValueError:
                    print(f"Invalid permission: {perm_str}")
                    continue
                path_restrictions = []
                if permission in (PermissionLevel.RESTRICTED, PermissionLevel.GUEST):
                    print("Enter allowed paths (empty line to finish):")
                    while True:
                        p = input("  Path: ").strip()
                        if not p:
                            break
                        path_restrictions.append(p)
            else:
                template = FAMILY_TEMPLATES[template_key]
                permission = template['permission']
                path_restrictions = [
                    p.replace('{name}', user_id) for p in template['path_restrictions']
                ]
            
            manager.add_user(user_id, permission, path_restrictions)
            print(f"✅ Created: {user_id} ({permission.value})")
            if path_restrictions:
                print(f"   Allowed paths: {path_restrictions}")
    
    # Step 3: Device registration guidance
    print(f"\n{'=' * 60}")
    print("STEP 3: Register Authenticator Devices")
    print("=" * 60)
    
    print("""
Device registration happens via the web interface because the
browser needs to interact with your authenticator hardware.

Here's what to do:

  1. Start the proxy (includes approval server):
     python -m proxy.aiohai_proxy

  2. On your phone, open:
     https://<server-ip>:8443/register

  3. Select your user and device type:
     • "Platform" for Face ID / Touch ID / Fingerprint
     • "Roaming" for Nitrokey 3A NFC

  4. Follow the on-screen prompts:
     • Face ID: Look at phone
     • Nitrokey: Tap to phone NFC reader

  5. Repeat for each family member's phone

IMPORTANT FOR NITROKEY 3A NFC:
  • Hold the Nitrokey to the back of your phone
  • Keep it pressed until the registration completes
  • On iPhone, the NFC reader is near the top of the phone
""")

    users = manager.get_all_users()
    print("Users ready for device registration:")
    for username, u in users.items():
        device_count = len(u.credentials)
        status = f"({device_count} device(s))" if device_count else "(no devices yet)"
        print(f"  • {u.username} [{username}] — {u.role.value} {status}")
    
    print(f"\n{'=' * 60}")
    print("SETUP COMPLETE")
    print("=" * 60)
    print(f"\nConfig saved to: {manager.users_file}")
    print("\nNext steps:")
    print("  1. Start the proxy (approval server starts automatically):")
    print("     python -m proxy.aiohai_proxy")
    print("  2. Register devices via phone browser")
    print("  3. Test by asking the AI to delete a file")


def add_single_user(manager: CredentialStore):
    """Add a single user interactively."""
    print("\n=== Add User ===\n")
    
    user_id = input("User ID: ").strip()
    if not user_id:
        print("User ID required")
        return
    
    display_name = input("Display name: ").strip() or user_id.title()
    
    print("\nPermission levels: admin, trusted_adult, restricted, guest")
    perm_str = input("Permission: ").strip()
    
    try:
        permission = PermissionLevel(perm_str)
    except ValueError:
        print(f"Invalid: {perm_str}")
        return
    
    paths = []
    if permission in (PermissionLevel.RESTRICTED, PermissionLevel.GUEST):
        print("Allowed paths (empty line to finish):")
        while True:
            p = input("  Path: ").strip()
            if not p:
                break
            paths.append(p)
    
    manager.add_user(user_id, permission, paths)
    print(f"\n✅ Created user: {user_id} ({permission.value})")


def list_all(manager: CredentialStore):
    """List all users and authenticators."""
    users = manager.get_all_users()
    
    print("\n=== AIOHAI Users & Devices ===\n")
    
    print(f"Users ({len(users)}):")
    for username, u in users.items():
        device_count = len(u.credentials)
        print(f"  {username}: {u.username} — {u.role.value} ({device_count} device(s))")
    
    total_devices = sum(len(u.credentials) for u in users.values())
    print(f"\nAuthenticators ({total_devices}):")
    for username, u in users.items():
        for cred in u.credentials:
            import base64
            cred_id_short = base64.urlsafe_b64encode(cred.credential_id).decode()[:12]
            print(f"  {cred_id_short}...: {cred.device_name} ({cred.authenticator_type}) → user: {username}")
            print(f"    Last used: {cred.last_used or 'never'}")
    
    if not users:
        print("  (none — run --setup to create users)")


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="AIOHAI Device Registration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python register_devices.py --setup       # Full setup wizard
  python register_devices.py --add-user    # Add one user
  python register_devices.py --list        # Show users/devices
  python register_devices.py --server      # Start registration web server
        """
    )
    
    parser.add_argument('--setup', action='store_true', help='Run full setup wizard')
    parser.add_argument('--add-user', action='store_true', help='Add a single user')
    parser.add_argument('--list', action='store_true', help='List users and devices')
    parser.add_argument('--server', action='store_true', help='Start registration web server')
    parser.add_argument('--config', type=Path, default=DEFAULT_CONFIG, help='Config path')
    parser.add_argument('--port', type=int, default=8443, help='Server port')
    
    args = parser.parse_args()
    
    if not any([args.setup, args.add_user, args.list, args.server]):
        args.setup = True  # Default to setup
    
    logging.basicConfig(level=logging.INFO)
    storage_path = args.config.parent.parent / 'data' / 'fido2'
    manager = CredentialStore(storage_path)
    
    if args.setup:
        full_setup_wizard(manager)
    elif args.add_user:
        add_single_user(manager)
    elif args.list:
        list_all(manager)
    elif args.server:
        print("The standalone approval server has been removed.")
        print("The approval server is now built into the proxy (fido2_approval.py).")
        print("Start it via: python -m proxy.aiohai_proxy")
        sys.exit(1)


if __name__ == '__main__':
    main()
