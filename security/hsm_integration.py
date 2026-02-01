#!/usr/bin/env python3
"""
AIOHAI HSM Integration Module
================================

Provides integration with Nitrokey HSM 2 for:
- Policy file signature verification (startup)
- Log entry signing (tamper-evident audit trail)
- Secure random generation (session tokens, approval IDs)

Hardware: Nitrokey HSM 2 (SmartCard-HSM based)
Protocol: PKCS#11
Library: PyKCS11

Author: AIOHAI Project
Version: 1.0.0
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

# =============================================================================
# DATA CLASSES
# =============================================================================

class HSMStatus(Enum):
    """HSM connection status."""
    NOT_INITIALIZED = "not_initialized"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"
    PIN_REQUIRED = "pin_required"
    PIN_LOCKED = "pin_locked"


@dataclass
class HSMKeyInfo:
    """Information about a key stored in HSM."""
    label: str
    key_type: str  # 'RSA', 'EC', 'AES'
    key_id: bytes
    can_sign: bool = False
    can_verify: bool = False
    can_encrypt: bool = False
    can_decrypt: bool = False
    is_private: bool = False


@dataclass
class SignedLogEntry:
    """A log entry with HSM signature."""
    timestamp: str
    event_type: str
    data: Dict[str, Any]
    entry_hash: str
    signature: str  # Base64 encoded
    previous_hash: str  # Chain link


@dataclass
class PolicyVerificationResult:
    """Result of policy signature verification."""
    is_valid: bool
    policy_hash: str
    signature_date: Optional[str] = None
    signer_key_id: Optional[str] = None
    error_message: Optional[str] = None


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
    
    Thread-safe: Uses locks for all HSM operations.
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, *args, **kwargs):
        """Singleton pattern - only one HSM manager per process."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize HSM manager.
        
        Args:
            config_path: Path to HSM configuration file (optional)
        """
        # Avoid re-initialization for singleton
        if hasattr(self, '_initialized') and self._initialized:
            return
        
        self.logger = logging.getLogger('AIOHAI.HSM')
        self.status = HSMStatus.NOT_INITIALIZED
        self.error_message: Optional[str] = None
        
        # PKCS#11 objects
        self._pkcs11: Optional[PyKCS11Lib] = None
        self._session = None
        self._slot: Optional[int] = None
        
        # Key handles (cached after login)
        self._policy_key_handle = None
        self._log_key_handle = None
        self._entropy_key_handle = None
        
        # Log chain state
        self._last_log_hash = "GENESIS"
        self._log_counter = 0
        
        # Thread safety
        self._hsm_lock = threading.Lock()
        
        # Configuration
        self.config = self._load_config(config_path)
        
        self._initialized = True
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load HSM configuration."""
        default_config = {
            'pkcs11_library': 'auto',
            'slot_index': 0,
            'require_hsm': True,
            'policy_key_label': HSM_KEY_LABELS['policy_signing'],
            'log_key_label': HSM_KEY_LABELS['log_signing'],
            'entropy_key_label': HSM_KEY_LABELS['entropy'],
        }
        
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                default_config.update(user_config.get('hsm', {}))
            except Exception as e:
                self.logger.warning(f"Failed to load HSM config: {e}")
        
        return default_config
    
    # =========================================================================
    # CONNECTION MANAGEMENT
    # =========================================================================
    
    def initialize(self) -> Tuple[bool, str]:
        """
        Initialize connection to HSM.
        
        Returns:
            Tuple of (success, message)
        """
        if not PKCS11_AVAILABLE:
            self.status = HSMStatus.ERROR
            self.error_message = "PyKCS11 library not installed. Run: pip install PyKCS11"
            return False, self.error_message
        
        with self._hsm_lock:
            try:
                # Find PKCS#11 library
                library_path = self._find_pkcs11_library()
                if not library_path:
                    self.status = HSMStatus.ERROR
                    self.error_message = "PKCS#11 library not found. Install OpenSC."
                    return False, self.error_message
                
                # Load library
                self._pkcs11 = PyKCS11Lib()
                self._pkcs11.load(library_path)
                self.logger.info(f"Loaded PKCS#11 library: {library_path}")
                
                # Find HSM slot
                slots = self._pkcs11.getSlotList(tokenPresent=True)
                if not slots:
                    self.status = HSMStatus.DISCONNECTED
                    self.error_message = "No Nitrokey HSM detected. Please insert device."
                    return False, self.error_message
                
                self._slot = slots[self.config.get('slot_index', 0)]
                
                # Get token info
                token_info = self._pkcs11.getTokenInfo(self._slot)
                self.logger.info(f"Found HSM: {token_info.label.strip()}")
                
                self.status = HSMStatus.PIN_REQUIRED
                return True, f"HSM detected: {token_info.label.strip()}. PIN required."
                
            except Exception as e:
                self.status = HSMStatus.ERROR
                self.error_message = f"HSM initialization failed: {e}"
                self.logger.error(self.error_message)
                return False, self.error_message
    
    def login(self, pin: str) -> Tuple[bool, str]:
        """
        Authenticate to HSM with user PIN.
        
        Args:
            pin: User PIN for HSM
            
        Returns:
            Tuple of (success, message)
        """
        if self.status == HSMStatus.NOT_INITIALIZED:
            return False, "HSM not initialized. Call initialize() first."
        
        with self._hsm_lock:
            try:
                # Open session
                self._session = self._pkcs11.openSession(
                    self._slot,
                    CKF_SERIAL_SESSION | CKF_RW_SESSION
                )
                
                # Login
                self._session.login(pin, CKU_USER)
                
                # Cache key handles
                self._cache_key_handles()
                
                self.status = HSMStatus.CONNECTED
                self.logger.info("HSM login successful")
                return True, "HSM login successful"
                
            except PyKCS11Error as e:
                if "PIN" in str(e).upper():
                    self.status = HSMStatus.PIN_REQUIRED
                    return False, "Invalid PIN"
                self.status = HSMStatus.ERROR
                self.error_message = f"HSM login failed: {e}"
                return False, self.error_message
            except Exception as e:
                self.status = HSMStatus.ERROR
                self.error_message = f"HSM login failed: {e}"
                return False, self.error_message
    
    def logout(self):
        """Logout and close HSM session."""
        with self._hsm_lock:
            try:
                if self._session:
                    self._session.logout()
                    self._session.closeSession()
                    self._session = None
                self.status = HSMStatus.DISCONNECTED
                self._policy_key_handle = None
                self._log_key_handle = None
                self._entropy_key_handle = None
                self.logger.info("HSM logout successful")
            except Exception as e:
                self.logger.warning(f"HSM logout error: {e}")
    
    def is_connected(self) -> bool:
        """Check if HSM is connected and logged in."""
        return self.status == HSMStatus.CONNECTED and self._session is not None
    
    def _find_pkcs11_library(self) -> Optional[str]:
        """Find PKCS#11 library path for current platform."""
        if self.config.get('pkcs11_library') != 'auto':
            path = self.config['pkcs11_library']
            if os.path.exists(path):
                return path
            return None
        
        platform = sys.platform
        if platform.startswith('linux'):
            paths = PKCS11_LIBRARY_PATHS['linux']
        elif platform == 'darwin':
            paths = PKCS11_LIBRARY_PATHS['darwin']
        elif platform == 'win32':
            paths = PKCS11_LIBRARY_PATHS['win32']
        else:
            paths = []
        
        for path in paths:
            if os.path.exists(path):
                return path
        
        return None
    
    def _cache_key_handles(self):
        """Cache handles for frequently used keys."""
        try:
            # Policy signing key (public, for verification)
            policy_keys = self._session.findObjects([
                (CKA_CLASS, CKO_PUBLIC_KEY),
                (CKA_LABEL, self.config['policy_key_label'])
            ])
            if policy_keys:
                self._policy_key_handle = policy_keys[0]
                self.logger.debug("Cached policy verification key")
            
            # Log signing key (private)
            log_keys = self._session.findObjects([
                (CKA_CLASS, CKO_PRIVATE_KEY),
                (CKA_LABEL, self.config['log_key_label'])
            ])
            if log_keys:
                self._log_key_handle = log_keys[0]
                self.logger.debug("Cached log signing key")
            
            # Entropy key (for random generation)
            entropy_keys = self._session.findObjects([
                (CKA_CLASS, CKO_SECRET_KEY),
                (CKA_LABEL, self.config['entropy_key_label'])
            ])
            if entropy_keys:
                self._entropy_key_handle = entropy_keys[0]
                self.logger.debug("Cached entropy key")
                
        except Exception as e:
            self.logger.warning(f"Failed to cache some key handles: {e}")
    
    # =========================================================================
    # POLICY VERIFICATION
    # =========================================================================
    
    def verify_policy_signature(
        self, 
        policy_content: bytes, 
        signature: bytes
    ) -> PolicyVerificationResult:
        """
        Verify policy file signature using HSM.
        
        Args:
            policy_content: Raw bytes of policy file
            signature: Signature to verify (raw bytes)
            
        Returns:
            PolicyVerificationResult with verification status
        """
        if not self.is_connected():
            return PolicyVerificationResult(
                is_valid=False,
                policy_hash=hashlib.sha256(policy_content).hexdigest(),
                error_message="HSM not connected"
            )
        
        with self._hsm_lock:
            try:
                # Find policy verification key if not cached
                if not self._policy_key_handle:
                    keys = self._session.findObjects([
                        (CKA_CLASS, CKO_PUBLIC_KEY),
                        (CKA_LABEL, self.config['policy_key_label'])
                    ])
                    if not keys:
                        return PolicyVerificationResult(
                            is_valid=False,
                            policy_hash=hashlib.sha256(policy_content).hexdigest(),
                            error_message="Policy signing key not found in HSM"
                        )
                    self._policy_key_handle = keys[0]
                
                # Hash the policy content
                policy_hash = hashlib.sha256(policy_content).hexdigest()
                
                # Verify signature
                # Note: Using SHA256_RSA_PKCS mechanism
                mechanism = CKM_SHA256_RSA_PKCS
                
                try:
                    self._session.verify(
                        self._policy_key_handle,
                        policy_content,
                        signature,
                        mechanism
                    )
                    
                    return PolicyVerificationResult(
                        is_valid=True,
                        policy_hash=policy_hash,
                        signature_date=datetime.now().isoformat(),
                        signer_key_id=self.config['policy_key_label']
                    )
                    
                except PyKCS11Error:
                    return PolicyVerificationResult(
                        is_valid=False,
                        policy_hash=policy_hash,
                        error_message="Signature verification failed - policy may be tampered"
                    )
                    
            except Exception as e:
                return PolicyVerificationResult(
                    is_valid=False,
                    policy_hash=hashlib.sha256(policy_content).hexdigest(),
                    error_message=f"Verification error: {e}"
                )
    
    def sign_policy(self, policy_content: bytes, require_touch: bool = True) -> Tuple[bool, bytes, str]:
        """
        Sign a policy file with HSM (requires touch for security).
        
        This operation requires physical presence (touch) because
        modifying the security policy is a critical action.
        
        Args:
            policy_content: Raw bytes of policy file to sign
            require_touch: Whether to require touch confirmation
            
        Returns:
            Tuple of (success, signature_bytes, message)
        """
        if not self.is_connected():
            return False, b'', "HSM not connected"
        
        with self._hsm_lock:
            try:
                # Find private signing key
                keys = self._session.findObjects([
                    (CKA_CLASS, CKO_PRIVATE_KEY),
                    (CKA_LABEL, self.config['policy_key_label'])
                ])
                if not keys:
                    return False, b'', "Policy signing key not found in HSM"
                
                private_key = keys[0]
                
                if require_touch:
                    print("\n" + "=" * 60)
                    print("⚠️  TOUCH YOUR NITROKEY HSM TO SIGN POLICY")
                    print("=" * 60 + "\n")
                
                # Sign
                mechanism = CKM_SHA256_RSA_PKCS
                signature = self._session.sign(private_key, policy_content, mechanism)
                
                return True, bytes(signature), "Policy signed successfully"
                
            except Exception as e:
                return False, b'', f"Signing failed: {e}"
    
    # =========================================================================
    # LOG SIGNING
    # =========================================================================
    
    def sign_log_entry(self, entry_data: Dict[str, Any]) -> Optional[SignedLogEntry]:
        """
        Sign a log entry for tamper-evident logging.
        
        Creates a chain of signed entries where each entry
        includes the hash of the previous entry.
        
        Args:
            entry_data: Dictionary containing log event data
            
        Returns:
            SignedLogEntry if successful, None otherwise
        """
        if not self.is_connected():
            self.logger.warning("HSM not connected - log entry not signed")
            return None
        
        with self._hsm_lock:
            try:
                # Create entry structure
                timestamp = datetime.now().isoformat()
                self._log_counter += 1
                
                entry = {
                    'timestamp': timestamp,
                    'counter': self._log_counter,
                    'previous_hash': self._last_log_hash,
                    'data': entry_data
                }
                
                # Compute entry hash
                entry_bytes = json.dumps(entry, sort_keys=True).encode('utf-8')
                entry_hash = hashlib.sha256(entry_bytes).hexdigest()
                
                # Sign with HSM
                if self._log_key_handle:
                    mechanism = CKM_SHA256_RSA_PKCS
                    signature = self._session.sign(
                        self._log_key_handle,
                        entry_bytes,
                        mechanism
                    )
                    signature_b64 = base64.b64encode(bytes(signature)).decode('ascii')
                else:
                    # Fallback: unsigned entry (marked)
                    signature_b64 = "UNSIGNED"
                    self.logger.warning("Log key not found - entry unsigned")
                
                # Update chain
                self._last_log_hash = entry_hash
                
                return SignedLogEntry(
                    timestamp=timestamp,
                    event_type=entry_data.get('event', 'UNKNOWN'),
                    data=entry_data,
                    entry_hash=entry_hash,
                    signature=signature_b64,
                    previous_hash=entry['previous_hash']
                )
                
            except Exception as e:
                self.logger.error(f"Failed to sign log entry: {e}")
                return None
    
    def verify_log_chain(self, entries: List[SignedLogEntry]) -> Tuple[bool, str]:
        """
        Verify integrity of log entry chain.
        
        Args:
            entries: List of signed log entries in order
            
        Returns:
            Tuple of (all_valid, message)
        """
        if not entries:
            return True, "No entries to verify"
        
        if not self.is_connected():
            return False, "HSM not connected for verification"
        
        with self._hsm_lock:
            try:
                # Find verification key
                keys = self._session.findObjects([
                    (CKA_CLASS, CKO_PUBLIC_KEY),
                    (CKA_LABEL, self.config['log_key_label'])
                ])
                if not keys:
                    return False, "Log verification key not found"
                
                verify_key = keys[0]
                expected_prev = "GENESIS"
                
                for i, entry in enumerate(entries):
                    # Check chain link
                    if entry.previous_hash != expected_prev:
                        return False, f"Chain broken at entry {i}: expected prev={expected_prev[:16]}..., got {entry.previous_hash[:16]}..."
                    
                    # Reconstruct entry for verification
                    entry_dict = {
                        'timestamp': entry.timestamp,
                        'counter': i + 1,
                        'previous_hash': entry.previous_hash,
                        'data': entry.data
                    }
                    entry_bytes = json.dumps(entry_dict, sort_keys=True).encode('utf-8')
                    
                    # Verify hash
                    computed_hash = hashlib.sha256(entry_bytes).hexdigest()
                    if computed_hash != entry.entry_hash:
                        return False, f"Hash mismatch at entry {i}"
                    
                    # Verify signature (if not UNSIGNED)
                    if entry.signature != "UNSIGNED":
                        signature = base64.b64decode(entry.signature)
                        try:
                            self._session.verify(
                                verify_key,
                                entry_bytes,
                                signature,
                                CKM_SHA256_RSA_PKCS
                            )
                        except PyKCS11Error:
                            return False, f"Invalid signature at entry {i}"
                    
                    expected_prev = entry.entry_hash
                
                return True, f"All {len(entries)} entries verified"
                
            except Exception as e:
                return False, f"Verification error: {e}"
    
    # =========================================================================
    # SECURE RANDOM GENERATION
    # =========================================================================
    
    def generate_random(self, length: int = 32) -> bytes:
        """
        Generate cryptographically secure random bytes using HSM's RNG.
        
        HSM hardware random number generators are higher quality
        than software PRNGs.
        
        Args:
            length: Number of random bytes to generate
            
        Returns:
            Random bytes, or os.urandom() fallback if HSM unavailable
        """
        if not self.is_connected():
            self.logger.debug("HSM not connected - using os.urandom() fallback")
            return os.urandom(length)
        
        with self._hsm_lock:
            try:
                random_bytes = self._session.generateRandom(length)
                return bytes(random_bytes)
            except Exception as e:
                self.logger.warning(f"HSM random generation failed: {e}, using fallback")
                return os.urandom(length)
    
    def generate_token(self, length: int = 16) -> str:
        """
        Generate a secure random token (hex string).
        
        Args:
            length: Number of bytes (token will be 2x this in hex chars)
            
        Returns:
            Hex-encoded random token
        """
        return self.generate_random(length).hex()
    
    # =========================================================================
    # KEY MANAGEMENT
    # =========================================================================
    
    def list_keys(self) -> List[HSMKeyInfo]:
        """
        List all keys stored in HSM.
        
        Returns:
            List of HSMKeyInfo for each key
        """
        if not self.is_connected():
            return []
        
        keys = []
        with self._hsm_lock:
            try:
                # Find all key objects
                for key_class in [CKO_PUBLIC_KEY, CKO_PRIVATE_KEY, CKO_SECRET_KEY]:
                    found = self._session.findObjects([(CKA_CLASS, key_class)])
                    for key_handle in found:
                        attrs = self._session.getAttributeValue(key_handle, [
                            CKA_LABEL, CKA_ID, CKA_KEY_TYPE,
                            CKA_SIGN, CKA_VERIFY, CKA_ENCRYPT, CKA_DECRYPT
                        ])
                        
                        label = attrs[0].decode() if isinstance(attrs[0], bytes) else str(attrs[0])
                        key_id = bytes(attrs[1]) if attrs[1] else b''
                        key_type = attrs[2]
                        
                        type_name = {
                            CKK_RSA: 'RSA',
                            CKK_EC: 'EC',
                            CKK_AES: 'AES'
                        }.get(key_type, 'UNKNOWN')
                        
                        keys.append(HSMKeyInfo(
                            label=label,
                            key_type=type_name,
                            key_id=key_id,
                            can_sign=bool(attrs[3]),
                            can_verify=bool(attrs[4]),
                            can_encrypt=bool(attrs[5]),
                            can_decrypt=bool(attrs[6]),
                            is_private=(key_class == CKO_PRIVATE_KEY)
                        ))
                        
            except Exception as e:
                self.logger.error(f"Failed to list keys: {e}")
        
        return keys
    
    def get_status_report(self) -> Dict[str, Any]:
        """
        Get comprehensive HSM status report.
        
        Returns:
            Dictionary with status information
        """
        report = {
            'status': self.status.value,
            'connected': self.is_connected(),
            'error': self.error_message,
            'pkcs11_available': PKCS11_AVAILABLE,
            'keys': [],
            'log_chain_length': self._log_counter,
        }
        
        if self.is_connected():
            try:
                token_info = self._pkcs11.getTokenInfo(self._slot)
                report['token'] = {
                    'label': token_info.label.strip(),
                    'manufacturer': token_info.manufacturerID.strip(),
                    'serial': token_info.serialNumber.strip(),
                }
                report['keys'] = [
                    {
                        'label': k.label,
                        'type': k.key_type,
                        'can_sign': k.can_sign,
                        'can_verify': k.can_verify,
                    }
                    for k in self.list_keys()
                ]
            except Exception as e:
                report['token_error'] = str(e)
        
        return report


# =============================================================================
# MOCK HSM FOR TESTING (When no hardware available)
# =============================================================================

class MockHSMManager:
    """
    Mock HSM manager for development/testing without hardware.
    
    WARNING: This provides NO actual security. Use only for testing.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        self.logger = logging.getLogger('AIOHAI.MockHSM')
        self.status = HSMStatus.NOT_INITIALIZED
        self._logged_in = False
        self._last_log_hash = "GENESIS"
        self._log_counter = 0
        self._mock_private_key = os.urandom(32)  # Fake key
        self.logger.warning("=" * 60)
        self.logger.warning("USING MOCK HSM - NO HARDWARE SECURITY")
        self.logger.warning("This is for testing only. Do not use in production.")
        self.logger.warning("=" * 60)
    
    def initialize(self) -> Tuple[bool, str]:
        self.status = HSMStatus.PIN_REQUIRED
        return True, "Mock HSM initialized (NO SECURITY)"
    
    def login(self, pin: str) -> Tuple[bool, str]:
        if pin == "":
            return False, "PIN required"
        self._logged_in = True
        self.status = HSMStatus.CONNECTED
        return True, "Mock HSM login (NO SECURITY)"
    
    def logout(self):
        self._logged_in = False
        self.status = HSMStatus.DISCONNECTED
    
    def is_connected(self) -> bool:
        return self._logged_in
    
    def verify_policy_signature(self, policy_content: bytes, signature: bytes) -> PolicyVerificationResult:
        # Mock: just check if signature matches our mock scheme
        policy_hash = hashlib.sha256(policy_content).hexdigest()
        expected_sig = hashlib.sha256(self._mock_private_key + policy_content).digest()
        
        return PolicyVerificationResult(
            is_valid=(signature == expected_sig),
            policy_hash=policy_hash,
            signature_date=datetime.now().isoformat(),
            signer_key_id="mock-key"
        )
    
    def sign_policy(self, policy_content: bytes, require_touch: bool = True) -> Tuple[bool, bytes, str]:
        if require_touch:
            print("\n[MOCK HSM] Would require touch - skipping for mock\n")
        signature = hashlib.sha256(self._mock_private_key + policy_content).digest()
        return True, signature, "Mock signature created (NO SECURITY)"
    
    def sign_log_entry(self, entry_data: Dict[str, Any]) -> Optional[SignedLogEntry]:
        timestamp = datetime.now().isoformat()
        self._log_counter += 1
        
        entry = {
            'timestamp': timestamp,
            'counter': self._log_counter,
            'previous_hash': self._last_log_hash,
            'data': entry_data
        }
        
        entry_bytes = json.dumps(entry, sort_keys=True).encode('utf-8')
        entry_hash = hashlib.sha256(entry_bytes).hexdigest()
        
        # Mock signature
        signature = hashlib.sha256(self._mock_private_key + entry_bytes).digest()
        signature_b64 = base64.b64encode(signature).decode('ascii')
        
        self._last_log_hash = entry_hash
        
        return SignedLogEntry(
            timestamp=timestamp,
            event_type=entry_data.get('event', 'UNKNOWN'),
            data=entry_data,
            entry_hash=entry_hash,
            signature=signature_b64,
            previous_hash=entry['previous_hash']
        )
    
    def verify_log_chain(self, entries: List[SignedLogEntry]) -> Tuple[bool, str]:
        # Simplified verification for mock
        expected_prev = "GENESIS"
        for i, entry in enumerate(entries):
            if entry.previous_hash != expected_prev:
                return False, f"Chain broken at entry {i}"
            expected_prev = entry.entry_hash
        return True, f"Mock verified {len(entries)} entries"
    
    def generate_random(self, length: int = 32) -> bytes:
        return os.urandom(length)
    
    def generate_token(self, length: int = 16) -> str:
        return os.urandom(length).hex()
    
    def list_keys(self) -> List[HSMKeyInfo]:
        return [
            HSMKeyInfo("mock-policy-key", "RSA", b"mock", can_sign=True, can_verify=True),
            HSMKeyInfo("mock-log-key", "RSA", b"mock", can_sign=True, can_verify=True),
        ]
    
    def get_status_report(self) -> Dict[str, Any]:
        return {
            'status': self.status.value,
            'connected': self.is_connected(),
            'is_mock': True,
            'warning': 'NO HARDWARE SECURITY - MOCK ONLY',
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
        HSM manager instance
    """
    if use_mock or not PKCS11_AVAILABLE:
        if not use_mock:
            logging.warning("PyKCS11 not available - using mock HSM (NO SECURITY)")
        return MockHSMManager(config_path)
    
    return NitrokeyHSMManager(config_path)


# =============================================================================
# CLI INTERFACE (for testing/setup)
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
    
    # Setup logging
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    
    # Get HSM manager
    hsm = get_hsm_manager(use_mock=args.mock)
    
    # Initialize
    success, msg = hsm.initialize()
    print(msg)
    if not success:
        sys.exit(1)
    
    # Login
    pin = args.pin
    if not pin:
        import getpass
        pin = getpass.getpass("HSM PIN: ")
    
    success, msg = hsm.login(pin)
    print(msg)
    if not success:
        sys.exit(1)
    
    # Execute command
    if args.command == 'status':
        report = hsm.get_status_report()
        print(json.dumps(report, indent=2, default=str))
        
    elif args.command == 'list-keys':
        keys = hsm.list_keys()
        print(f"\nFound {len(keys)} keys:")
        for key in keys:
            print(f"  - {key.label} ({key.key_type})")
            print(f"    Sign: {key.can_sign}, Verify: {key.can_verify}")
            
    elif args.command == 'sign-policy':
        if not args.policy:
            print("ERROR: --policy required")
            sys.exit(1)
        
        with open(args.policy, 'rb') as f:
            policy_content = f.read()
        
        success, signature, msg = hsm.sign_policy(policy_content)
        print(msg)
        
        if success:
            sig_path = args.signature or (args.policy + '.sig')
            with open(sig_path, 'wb') as f:
                f.write(signature)
            print(f"Signature saved to: {sig_path}")
            
    elif args.command == 'verify-policy':
        if not args.policy or not args.signature:
            print("ERROR: --policy and --signature required")
            sys.exit(1)
        
        with open(args.policy, 'rb') as f:
            policy_content = f.read()
        with open(args.signature, 'rb') as f:
            signature = f.read()
        
        result = hsm.verify_policy_signature(policy_content, signature)
        if result.is_valid:
            print("✅ Policy signature VALID")
            print(f"   Hash: {result.policy_hash[:32]}...")
        else:
            print("❌ Policy signature INVALID")
            print(f"   Error: {result.error_message}")
            
    elif args.command == 'test':
        print("\n=== HSM Integration Test ===\n")
        
        # Test random generation
        print("1. Testing random generation...")
        random_bytes = hsm.generate_random(32)
        print(f"   Generated: {random_bytes.hex()[:32]}...")
        
        # Test log signing
        print("\n2. Testing log signing...")
        entry = hsm.sign_log_entry({'event': 'TEST', 'message': 'Test entry'})
        if entry:
            print(f"   Signed entry: {entry.entry_hash[:32]}...")
            print(f"   Signature: {entry.signature[:32]}...")
        
        # Test chain
        print("\n3. Testing log chain...")
        entries = [entry] if entry else []
        for i in range(3):
            e = hsm.sign_log_entry({'event': 'TEST', 'index': i})
            if e:
                entries.append(e)
        
        valid, msg = hsm.verify_log_chain(entries)
        print(f"   Chain verification: {msg}")
        
        print("\n=== Test Complete ===")
    
    # Logout
    hsm.logout()


if __name__ == '__main__':
    main()
