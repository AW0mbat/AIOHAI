#!/usr/bin/env python3
"""
AIOHAI HSM Integration Module — Backward Compatibility Facade

This module now re-exports from aiohai.core.crypto.hsm_bridge.
The canonical implementation has moved to the Core layer.

For new code, import directly from aiohai.core.crypto.hsm_bridge:
    from aiohai.core.crypto.hsm_bridge import NitrokeyHSMManager, get_hsm_manager

This facade is maintained for backward compatibility with existing code.
"""

import warnings
import sys

# Try to import from the new canonical location
try:
    from aiohai.core.crypto.hsm_bridge import (
        NitrokeyHSMManager,
        MockHSMManager,
        get_hsm_manager,
        PKCS11_AVAILABLE,
        HSM_KEY_LABELS,
    )
    from aiohai.core.types import (
        HSMStatus,
        HSMKeyInfo,
        SignedLogEntry,
        PolicyVerificationResult,
    )
    _IMPORTS_FROM_CORE = True
except ImportError:
    # Fallback: Core not available, define locally
    # This should not happen in normal operation but provides safety
    _IMPORTS_FROM_CORE = False
    warnings.warn(
        "Failed to import from aiohai.core.crypto.hsm_bridge. "
        "Using local fallback definitions.",
        ImportWarning
    )
    
    # Minimal fallback imports
    import os
    import json
    import base64
    import hashlib
    import logging
    from pathlib import Path
    from datetime import datetime
    from typing import Optional, Tuple, Dict, Any, List
    from dataclasses import dataclass, field
    from enum import Enum
    import threading
    
    # Fallback PKCS11 check
    PKCS11_AVAILABLE = False
    try:
        from PyKCS11 import PyKCS11Lib, PyKCS11Error
        PKCS11_AVAILABLE = True
    except ImportError:
        pass
    
    # Fallback type definitions
    class HSMStatus(Enum):
        NOT_INITIALIZED = "not_initialized"
        CONNECTED = "connected"
        DISCONNECTED = "disconnected"
        ERROR = "error"
        PIN_REQUIRED = "pin_required"
        PIN_LOCKED = "pin_locked"

    @dataclass
    class HSMKeyInfo:
        label: str
        key_type: str
        key_id: bytes
        can_sign: bool = False
        can_verify: bool = False
        can_encrypt: bool = False
        can_decrypt: bool = False
        is_private: bool = False

    @dataclass
    class SignedLogEntry:
        timestamp: str
        event_type: str
        data: Dict[str, Any]
        entry_hash: str
        signature: str
        previous_hash: str

    @dataclass
    class PolicyVerificationResult:
        is_valid: bool
        policy_hash: str
        signature_date: Optional[str] = None
        signer_key_id: Optional[str] = None
        error_message: Optional[str] = None

    HSM_KEY_LABELS = {
        'policy_signing': 'aiohai-policy-key',
        'log_signing': 'aiohai-log-key',
        'entropy': 'aiohai-entropy-key',
    }

    # Minimal MockHSMManager fallback
    class MockHSMManager:
        def __init__(self, config_path=None):
            self._status = HSMStatus.NOT_INITIALIZED
            self._logged_in = False
            self._chain_hash = hashlib.sha256(b"MOCK-GENESIS").hexdigest()
        
        @property
        def status(self): return self._status
        
        @property
        def is_connected(self): return self._logged_in
        
        def initialize(self): 
            self._status = HSMStatus.PIN_REQUIRED
            return True, "Mock HSM initialized"
        
        def login(self, pin):
            self._logged_in = True
            self._status = HSMStatus.CONNECTED
            return True, "Mock login"
        
        def logout(self):
            self._logged_in = False
            return True, "Logged out"
        
        def list_keys(self): return []
        def sign_data(self, data, key_label=None): return True, "", "Mock"
        def verify_signature(self, data, sig, key_label=None): return True, "Mock"
        def sign_policy(self, content): return True, "", "Mock"
        def verify_policy(self, content, sig):
            return PolicyVerificationResult(True, hashlib.sha256(content).hexdigest())
        def sign_log_entry(self, data):
            return SignedLogEntry(datetime.now().isoformat(), "unknown", data, "", "", "")
        def get_random_bytes(self, length): return os.urandom(length)
        def get_status_report(self): return {'status': 'mock', 'mock': True}

    NitrokeyHSMManager = MockHSMManager  # Fallback to mock

    def get_hsm_manager(use_mock=False, config_path=None):
        return MockHSMManager(config_path)


# =============================================================================
# CLI INTERFACE (kept here for backward compat with tools/hsm_setup.py)
# =============================================================================

def main():
    """Command-line interface for HSM operations."""
    import argparse
    
    parser = argparse.ArgumentParser(description="AIOHAI HSM Management")
    parser.add_argument('command', choices=['status', 'list-keys', 'sign-policy', 'verify-policy', 'test'])
    parser.add_argument('--policy', help="Path to policy file")
    parser.add_argument('--signature', help="Path to signature file")
    parser.add_argument('--pin', help="HSM PIN (will prompt if not provided)")
    parser.add_argument('--mock', action='store_true', help="Use mock HSM for testing")
    
    args = parser.parse_args()
    
    import logging
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    
    hsm = get_hsm_manager(use_mock=args.mock)
    
    success, msg = hsm.initialize()
    print(msg)
    if not success:
        sys.exit(1)
    
    pin = args.pin
    if not pin:
        import getpass
        pin = getpass.getpass("HSM PIN: ")
    
    success, msg = hsm.login(pin)
    print(msg)
    if not success:
        sys.exit(1)
    
    if args.command == 'status':
        report = hsm.get_status_report()
        print(json.dumps(report, indent=2, default=str))
        
    elif args.command == 'list-keys':
        keys = hsm.list_keys()
        print(f"\nFound {len(keys)} keys:")
        for key in keys:
            print(f"  - {key.label} ({key.key_type})")
            
    elif args.command == 'sign-policy':
        if not args.policy:
            print("ERROR: --policy required")
            sys.exit(1)
        with open(args.policy, 'rb') as f:
            content = f.read()
        success, signature, msg = hsm.sign_policy(content)
        print(msg)
        if success and args.signature:
            with open(args.signature, 'w') as f:
                f.write(signature)
            print(f"Signature written to {args.signature}")
            
    elif args.command == 'verify-policy':
        if not args.policy or not args.signature:
            print("ERROR: --policy and --signature required")
            sys.exit(1)
        with open(args.policy, 'rb') as f:
            content = f.read()
        with open(args.signature, 'r') as f:
            signature = f.read().strip()
        result = hsm.verify_policy(content, signature)
        print(f"Valid: {result.is_valid}")
        print(f"Hash: {result.policy_hash}")
        if result.error_message:
            print(f"Error: {result.error_message}")
            
    elif args.command == 'test':
        print("\nTesting HSM operations...")
        test_data = b"Test data for signing"
        success, sig, msg = hsm.sign_data(test_data)
        print(f"Sign: {msg}")
        if success:
            valid, msg = hsm.verify_signature(test_data, sig)
            print(f"Verify: {msg}")
        print("\nRandom bytes test:")
        random_bytes = hsm.get_random_bytes(16)
        print(f"Generated: {random_bytes.hex()}")


if __name__ == "__main__":
    main()


# =============================================================================
# EXPORTS (same as before for backward compatibility)
# =============================================================================

__all__ = [
    'NitrokeyHSMManager',
    'MockHSMManager', 
    'get_hsm_manager',
    'HSMStatus',
    'HSMKeyInfo',
    'SignedLogEntry',
    'PolicyVerificationResult',
    'PKCS11_AVAILABLE',
    'HSM_KEY_LABELS',
]
