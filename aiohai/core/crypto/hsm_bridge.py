#!/usr/bin/env python3
"""
AIOHAI Core Crypto — HSM Bridge

Provides integration with Nitrokey HSM 2 for:
- Policy file signature verification (startup)
- Log entry signing (tamper-evident audit trail)
- Secure random generation (session tokens, approval IDs)

Hardware: Nitrokey HSM 2 (SmartCard-HSM based)
Protocol: PKCS#11
Library: PyKCS11

This module is part of the AIOHAI Core layer and provides accessor-agnostic
HSM functionality. Both the AI proxy and direct user access use this module.

Migration Note:
    Previously in security/hsm_integration.py
    Now canonical location is aiohai/core/crypto/hsm_bridge.py
"""

import os
import sys
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

# Import types from core
from aiohai.core.types import (
    HSMStatus, HSMKeyInfo, SignedLogEntry, PolicyVerificationResult
)

# =============================================================================
# CONDITIONAL IMPORTS
# =============================================================================

PKCS11_AVAILABLE = False
try:
    from PyKCS11 import PyKCS11Lib, PyKCS11Error
    from PyKCS11.LowLevel import (
        CKA_CLASS, CKA_LABEL, CKA_ID, CKA_KEY_TYPE, CKA_TOKEN, CKA_PRIVATE,
        CKA_SENSITIVE, CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN, CKA_VERIFY,
        CKA_MODULUS_BITS, CKA_PUBLIC_EXPONENT, CKA_VALUE_LEN,
        CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKO_SECRET_KEY,
        CKK_RSA, CKK_EC, CKK_AES,
        CKM_RSA_PKCS, CKM_SHA256_RSA_PKCS, CKM_ECDSA_SHA256,
        CKM_AES_KEY_GEN, CKM_AES_CBC_PAD,
        CKU_USER, CKU_SO,
        CKF_SERIAL_SESSION, CKF_RW_SESSION
    )
    PKCS11_AVAILABLE = True
except ImportError:
    pass

# =============================================================================
# CONSTANTS
# =============================================================================

# Key labels used in HSM
HSM_KEY_LABELS = {
    'policy_signing': 'aiohai-policy-key',
    'log_signing': 'aiohai-log-key',
    'entropy': 'aiohai-entropy-key',
}

# PKCS#11 library paths by platform
PKCS11_LIBRARY_PATHS = {
    'linux': [
        '/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so',
        '/usr/lib/opensc-pkcs11.so',
        '/usr/local/lib/opensc-pkcs11.so',
        '/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so',
    ],
    'darwin': [
        '/usr/local/lib/opensc-pkcs11.so',
        '/opt/homebrew/lib/opensc-pkcs11.so',
        '/Library/OpenSC/lib/opensc-pkcs11.so',
    ],
    'win32': [
        'C:\\Windows\\System32\\opensc-pkcs11.dll',
        'C:\\Program Files\\OpenSC Project\\OpenSC\\pkcs11\\opensc-pkcs11.dll',
        'C:\\Program Files (x86)\\OpenSC Project\\OpenSC\\pkcs11\\opensc-pkcs11.dll',
    ],
}

logger = logging.getLogger("aiohai.core.crypto.hsm")


# =============================================================================
# HSM MANAGER CLASS
# =============================================================================

class NitrokeyHSMManager:
    """
    Manages connection and operations with Nitrokey HSM 2.
    
    This class provides:
    - HSM detection and connection
    - PIN authentication
    - Policy signature verification
    - Log entry signing
    - Secure random generation
    
    Thread Safety:
        All operations are protected by a lock. Multiple threads can
        safely call methods on the same instance.
    
    Usage:
        hsm = NitrokeyHSMManager()
        success, msg = hsm.initialize()
        if success:
            hsm.login(pin)
            signature = hsm.sign_log_entry(data)
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize HSM manager.
        
        Args:
            config_path: Optional path to configuration file containing
                        HSM settings (library path, slot, etc.)
        """
        self._lock = threading.RLock()
        self._pkcs11 = None
        self._session = None
        self._slot = None
        self._status = HSMStatus.NOT_INITIALIZED
        self._config_path = config_path
        self._library_path = None
        self._last_error = None
        
        # Chain hash for log signing
        self._chain_hash = hashlib.sha256(b"AIOHAI-GENESIS").hexdigest()
        
    @property
    def status(self) -> HSMStatus:
        """Current HSM connection status."""
        return self._status
    
    @property
    def is_connected(self) -> bool:
        """Check if HSM is connected and ready."""
        return self._status == HSMStatus.CONNECTED
    
    def _find_library(self) -> Optional[str]:
        """Find PKCS#11 library for current platform."""
        platform = sys.platform
        if platform.startswith('linux'):
            platform = 'linux'
        
        paths = PKCS11_LIBRARY_PATHS.get(platform, [])
        
        # Also check environment variable
        env_path = os.environ.get('PKCS11_LIBRARY')
        if env_path:
            paths.insert(0, env_path)
        
        # Check config file
        if self._config_path:
            try:
                with open(self._config_path) as f:
                    config = json.load(f)
                    if 'hsm' in config and 'library_path' in config['hsm']:
                        paths.insert(0, config['hsm']['library_path'])
            except (IOError, json.JSONDecodeError):
                pass
        
        for path in paths:
            if os.path.exists(path):
                return path
        
        return None
    
    def initialize(self) -> Tuple[bool, str]:
        """
        Initialize connection to HSM.
        
        Returns:
            Tuple of (success: bool, message: str)
        """
        with self._lock:
            if not PKCS11_AVAILABLE:
                self._status = HSMStatus.ERROR
                return False, "PyKCS11 not installed. Run: pip install PyKCS11"
            
            # Find library
            self._library_path = self._find_library()
            if not self._library_path:
                self._status = HSMStatus.ERROR
                return False, "PKCS#11 library not found. Install OpenSC."
            
            try:
                # Load library
                self._pkcs11 = PyKCS11Lib()
                self._pkcs11.load(self._library_path)
                
                # Find slots with tokens
                slots = self._pkcs11.getSlotList(tokenPresent=True)
                if not slots:
                    self._status = HSMStatus.DISCONNECTED
                    return False, "No HSM token found. Insert Nitrokey HSM 2."
                
                # Use first slot (or configured slot)
                self._slot = slots[0]
                
                # Get token info
                token_info = self._pkcs11.getTokenInfo(self._slot)
                
                self._status = HSMStatus.PIN_REQUIRED
                return True, f"HSM found: {token_info.label.strip()} (PIN required)"
                
            except Exception as e:
                self._status = HSMStatus.ERROR
                self._last_error = str(e)
                return False, f"HSM initialization failed: {e}"
    
    def login(self, pin: str) -> Tuple[bool, str]:
        """
        Authenticate to HSM with PIN.
        
        Args:
            pin: User PIN for HSM
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        with self._lock:
            if self._status == HSMStatus.NOT_INITIALIZED:
                return False, "HSM not initialized. Call initialize() first."
            
            if self._status == HSMStatus.CONNECTED:
                return True, "Already logged in."
            
            try:
                # Open session
                self._session = self._pkcs11.openSession(
                    self._slot,
                    CKF_SERIAL_SESSION | CKF_RW_SESSION
                )
                
                # Login
                self._session.login(pin, CKU_USER)
                
                self._status = HSMStatus.CONNECTED
                return True, "HSM login successful."
                
            except PyKCS11Error as e:
                if 'CKR_PIN_INCORRECT' in str(e):
                    self._status = HSMStatus.PIN_REQUIRED
                    return False, "Incorrect PIN."
                elif 'CKR_PIN_LOCKED' in str(e):
                    self._status = HSMStatus.PIN_LOCKED
                    return False, "PIN locked. HSM requires reset."
                else:
                    self._status = HSMStatus.ERROR
                    self._last_error = str(e)
                    return False, f"HSM login failed: {e}"
            except Exception as e:
                self._status = HSMStatus.ERROR
                self._last_error = str(e)
                return False, f"HSM login failed: {e}"
    
    def logout(self) -> Tuple[bool, str]:
        """
        Logout from HSM and close session.
        
        Returns:
            Tuple of (success: bool, message: str)
        """
        with self._lock:
            try:
                if self._session:
                    self._session.logout()
                    self._session.closeSession()
                    self._session = None
                
                self._status = HSMStatus.PIN_REQUIRED
                return True, "Logged out from HSM."
                
            except Exception as e:
                self._last_error = str(e)
                return False, f"Logout failed: {e}"
    
    def _find_key(self, label: str, key_class: int) -> Optional[Any]:
        """Find a key by label and class."""
        if not self._session:
            return None
        
        try:
            template = [
                (CKA_CLASS, key_class),
                (CKA_LABEL, label),
            ]
            
            objects = self._session.findObjects(template)
            return objects[0] if objects else None
            
        except Exception:
            return None
    
    def list_keys(self) -> List[HSMKeyInfo]:
        """
        List all keys in HSM.
        
        Returns:
            List of HSMKeyInfo objects
        """
        with self._lock:
            if not self.is_connected:
                return []
            
            keys = []
            
            try:
                # Find all key objects
                for key_class in [CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKO_SECRET_KEY]:
                    template = [(CKA_CLASS, key_class)]
                    objects = self._session.findObjects(template)
                    
                    for obj in objects:
                        attrs = self._session.getAttributeValue(obj, [
                            CKA_LABEL, CKA_ID, CKA_KEY_TYPE,
                            CKA_SIGN, CKA_VERIFY, CKA_ENCRYPT, CKA_DECRYPT
                        ])
                        
                        # Determine key type string
                        key_type_val = attrs[2]
                        if key_type_val == CKK_RSA:
                            key_type = 'RSA'
                        elif key_type_val == CKK_EC:
                            key_type = 'EC'
                        elif key_type_val == CKK_AES:
                            key_type = 'AES'
                        else:
                            key_type = f'Unknown({key_type_val})'
                        
                        keys.append(HSMKeyInfo(
                            label=attrs[0] if isinstance(attrs[0], str) else bytes(attrs[0]).decode('utf-8', errors='replace').strip(),
                            key_type=key_type,
                            key_id=bytes(attrs[1]) if attrs[1] else b'',
                            can_sign=bool(attrs[3]) if attrs[3] is not None else False,
                            can_verify=bool(attrs[4]) if attrs[4] is not None else False,
                            can_encrypt=bool(attrs[5]) if attrs[5] is not None else False,
                            can_decrypt=bool(attrs[6]) if attrs[6] is not None else False,
                            is_private=(key_class == CKO_PRIVATE_KEY),
                        ))
                
            except Exception as e:
                logger.error(f"Error listing keys: {e}")
            
            return keys
    
    def sign_data(self, data: bytes, key_label: str = None) -> Tuple[bool, str, str]:
        """
        Sign data using HSM key.
        
        Args:
            data: Data to sign
            key_label: Label of signing key (defaults to log signing key)
            
        Returns:
            Tuple of (success: bool, signature_b64: str, message: str)
        """
        with self._lock:
            if not self.is_connected:
                return False, "", "HSM not connected."
            
            key_label = key_label or HSM_KEY_LABELS['log_signing']
            
            try:
                # Find signing key
                key = self._find_key(key_label, CKO_PRIVATE_KEY)
                if not key:
                    return False, "", f"Signing key '{key_label}' not found."
                
                # Compute hash
                data_hash = hashlib.sha256(data).digest()
                
                # C1 FIX: Use CKM_RSA_PKCS (raw RSA) when passing pre-hashed data.
                # CKM_SHA256_RSA_PKCS would hash again internally, producing a
                # double-hash that isn't interoperable with standard tooling.
                mechanism = CKM_RSA_PKCS
                signature = bytes(self._session.sign(key, data_hash, mechanism))
                
                signature_b64 = base64.b64encode(signature).decode('ascii')
                return True, signature_b64, "Data signed successfully."
                
            except Exception as e:
                logger.error(f"Signing failed: {e}")
                return False, "", f"Signing failed: {e}"
    
    def verify_signature(self, data: bytes, signature_b64: str, 
                        key_label: str = None) -> Tuple[bool, str]:
        """
        Verify a signature using HSM key.
        
        Args:
            data: Original data that was signed
            signature_b64: Base64-encoded signature
            key_label: Label of verification key
            
        Returns:
            Tuple of (valid: bool, message: str)
        """
        with self._lock:
            if not self.is_connected:
                return False, "HSM not connected."
            
            key_label = key_label or HSM_KEY_LABELS['log_signing']
            
            try:
                # Find verification key
                key = self._find_key(key_label, CKO_PUBLIC_KEY)
                if not key:
                    return False, f"Verification key '{key_label}' not found."
                
                # Decode signature
                signature = base64.b64decode(signature_b64)
                
                # Compute hash
                data_hash = hashlib.sha256(data).digest()
                
                # C1 FIX: Use CKM_RSA_PKCS (raw RSA) to match sign_data().
                # See sign_data() comment for rationale.
                mechanism = CKM_RSA_PKCS
                self._session.verify(key, data_hash, signature, mechanism)
                
                return True, "Signature valid."
                
            except PyKCS11Error as e:
                if 'CKR_SIGNATURE_INVALID' in str(e):
                    return False, "Signature invalid."
                return False, f"Verification failed: {e}"
            except Exception as e:
                return False, f"Verification failed: {e}"
    
    def sign_policy(self, policy_content: bytes) -> Tuple[bool, str, str]:
        """
        Sign policy file content.
        
        Args:
            policy_content: Raw bytes of policy file
            
        Returns:
            Tuple of (success: bool, signature_b64: str, message: str)
        """
        return self.sign_data(policy_content, HSM_KEY_LABELS['policy_signing'])
    
    def verify_policy(self, policy_content: bytes, 
                     signature_b64: str) -> PolicyVerificationResult:
        """
        Verify policy file signature.
        
        Args:
            policy_content: Raw bytes of policy file
            signature_b64: Base64-encoded signature
            
        Returns:
            PolicyVerificationResult with verification status
        """
        policy_hash = hashlib.sha256(policy_content).hexdigest()
        
        if not self.is_connected:
            return PolicyVerificationResult(
                is_valid=False,
                policy_hash=policy_hash,
                error_message="HSM not connected."
            )
        
        valid, msg = self.verify_signature(
            policy_content, 
            signature_b64,
            HSM_KEY_LABELS['policy_signing']
        )
        
        return PolicyVerificationResult(
            is_valid=valid,
            policy_hash=policy_hash,
            signature_date=datetime.now().isoformat() if valid else None,
            error_message=None if valid else msg
        )
    
    def sign_log_entry(self, entry_data: Dict[str, Any]) -> SignedLogEntry:
        """
        Sign a log entry with chain linking.
        
        Args:
            entry_data: Dictionary of log entry data
            
        Returns:
            SignedLogEntry with signature and chain hash
        """
        timestamp = datetime.now().isoformat()
        event_type = entry_data.get('event', 'unknown')
        
        # Create entry hash including previous hash (chain)
        entry_str = json.dumps({
            'timestamp': timestamp,
            'event': event_type,
            'data': entry_data,
            'previous_hash': self._chain_hash,
        }, sort_keys=True)
        
        entry_hash = hashlib.sha256(entry_str.encode()).hexdigest()
        
        # Sign
        success, signature, _ = self.sign_data(
            entry_str.encode(),
            HSM_KEY_LABELS['log_signing']
        )
        
        # Update chain
        old_chain = self._chain_hash
        self._chain_hash = entry_hash
        
        return SignedLogEntry(
            timestamp=timestamp,
            event_type=event_type,
            data=entry_data,
            entry_hash=entry_hash,
            signature=signature if success else "",
            previous_hash=old_chain,
        )
    
    def get_random_bytes(self, length: int) -> bytes:
        """
        Generate cryptographically secure random bytes from HSM.
        
        Args:
            length: Number of bytes to generate
            
        Returns:
            Random bytes (falls back to os.urandom if HSM unavailable)
        """
        with self._lock:
            if not self.is_connected:
                return os.urandom(length)
            
            try:
                return bytes(self._session.generateRandom(length))
            except Exception:
                return os.urandom(length)
    
    def get_status_report(self) -> Dict[str, Any]:
        """
        Get comprehensive HSM status report.
        
        Returns:
            Dictionary with status information
        """
        with self._lock:
            report = {
                'status': self._status.value,
                'connected': self.is_connected,
                'library_path': self._library_path,
                'last_error': self._last_error,
            }
            
            if self._pkcs11 and self._slot is not None:
                try:
                    token_info = self._pkcs11.getTokenInfo(self._slot)
                    report['token'] = {
                        'label': token_info.label.strip(),
                        'manufacturer': token_info.manufacturerID.strip(),
                        'model': token_info.model.strip(),
                        'serial': token_info.serialNumber.strip(),
                    }
                except Exception:
                    pass
            
            if self.is_connected:
                keys = self.list_keys()
                report['key_count'] = len(keys)
                report['keys'] = [
                    {'label': k.label, 'type': k.key_type, 'can_sign': k.can_sign}
                    for k in keys
                ]
            
            return report


# =============================================================================
# MOCK HSM MANAGER (for testing)
# =============================================================================

class MockHSMManager:
    """
    Mock HSM manager for testing without hardware.
    
    WARNING: This provides NO SECURITY. Use only for development/testing.
    All "signatures" are just hashes - not cryptographically secure.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        self._status = HSMStatus.NOT_INITIALIZED
        self._logged_in = False
        self._chain_hash = hashlib.sha256(b"MOCK-GENESIS").hexdigest()
        self._config_path = config_path
        logger.warning("Using MOCK HSM - NO ACTUAL SECURITY")
    
    @property
    def status(self) -> HSMStatus:
        return self._status
    
    @property
    def is_connected(self) -> bool:
        return self._logged_in
    
    def initialize(self) -> Tuple[bool, str]:
        self._status = HSMStatus.PIN_REQUIRED
        return True, "Mock HSM initialized (NO SECURITY)"
    
    def login(self, pin: str) -> Tuple[bool, str]:
        if not pin:
            return False, "PIN required"
        self._logged_in = True
        self._status = HSMStatus.CONNECTED
        return True, "Mock HSM login successful (NO SECURITY)"
    
    def logout(self) -> Tuple[bool, str]:
        self._logged_in = False
        self._status = HSMStatus.PIN_REQUIRED
        return True, "Logged out from mock HSM"
    
    def list_keys(self) -> List[HSMKeyInfo]:
        if not self._logged_in:
            return []
        # Return fake keys
        return [
            HSMKeyInfo(
                label=HSM_KEY_LABELS['policy_signing'],
                key_type='RSA',
                key_id=b'mock-policy-key',
                can_sign=True,
                can_verify=True,
            ),
            HSMKeyInfo(
                label=HSM_KEY_LABELS['log_signing'],
                key_type='RSA',
                key_id=b'mock-log-key',
                can_sign=True,
                can_verify=True,
            ),
        ]
    
    def sign_data(self, data: bytes, key_label: str = None) -> Tuple[bool, str, str]:
        if not self._logged_in:
            return False, "", "Mock HSM not logged in"
        # "Signature" is just a hash - NOT SECURE
        fake_sig = hashlib.sha256(data + b"MOCK-KEY").digest()
        return True, base64.b64encode(fake_sig).decode(), "Mock signature (NOT SECURE)"
    
    def verify_signature(self, data: bytes, signature_b64: str,
                        key_label: str = None) -> Tuple[bool, str]:
        if not self._logged_in:
            return False, "Mock HSM not logged in"
        # Verify by recomputing
        expected = hashlib.sha256(data + b"MOCK-KEY").digest()
        try:
            actual = base64.b64decode(signature_b64)
            if actual == expected:
                return True, "Mock signature valid (NOT SECURE)"
            return False, "Mock signature invalid"
        except Exception:
            return False, "Invalid signature format"
    
    def sign_policy(self, policy_content: bytes) -> Tuple[bool, str, str]:
        return self.sign_data(policy_content, HSM_KEY_LABELS['policy_signing'])
    
    def verify_policy(self, policy_content: bytes,
                     signature_b64: str) -> PolicyVerificationResult:
        policy_hash = hashlib.sha256(policy_content).hexdigest()
        valid, msg = self.verify_signature(policy_content, signature_b64)
        return PolicyVerificationResult(
            is_valid=valid,
            policy_hash=policy_hash,
            signature_date=datetime.now().isoformat() if valid else None,
            error_message=None if valid else msg
        )
    
    def sign_log_entry(self, entry_data: Dict[str, Any]) -> SignedLogEntry:
        timestamp = datetime.now().isoformat()
        event_type = entry_data.get('event', 'unknown')
        
        entry_str = json.dumps({
            'timestamp': timestamp,
            'event': event_type,
            'data': entry_data,
            'previous_hash': self._chain_hash,
        }, sort_keys=True)
        
        entry_hash = hashlib.sha256(entry_str.encode()).hexdigest()
        success, signature, _ = self.sign_data(entry_str.encode())
        
        old_chain = self._chain_hash
        self._chain_hash = entry_hash
        
        return SignedLogEntry(
            timestamp=timestamp,
            event_type=event_type,
            data=entry_data,
            entry_hash=entry_hash,
            signature=signature if success else "",
            previous_hash=old_chain,
        )
    
    def get_random_bytes(self, length: int) -> bytes:
        return os.urandom(length)
    
    def get_status_report(self) -> Dict[str, Any]:
        return {
            'status': self._status.value,
            'connected': self._logged_in,
            'mock': True,
            'warning': 'NO ACTUAL SECURITY - Mock HSM',
        }


# =============================================================================
# FACTORY FUNCTION
# =============================================================================

def get_hsm_manager(
    use_mock: bool = False, 
    config_path: Optional[str] = None
) -> NitrokeyHSMManager:
    """
    Get HSM manager instance.
    
    Args:
        use_mock: If True, return mock manager (for testing)
        config_path: Path to configuration file
        
    Returns:
        HSM manager instance (NitrokeyHSMManager or MockHSMManager)
    """
    if use_mock or not PKCS11_AVAILABLE:
        if not use_mock:
            logging.warning("PyKCS11 not available - using mock HSM (NO SECURITY)")
        return MockHSMManager(config_path)
    
    return NitrokeyHSMManager(config_path)


# =============================================================================
# EXPORTS
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
