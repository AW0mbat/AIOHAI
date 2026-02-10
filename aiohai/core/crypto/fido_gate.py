#!/usr/bin/env python3
"""
AIOHAI Core Crypto — FIDO2/WebAuthn Gate
=========================================
Provides hardware-based approval for high-security operations using:
- Nitrokey 3A NFC (roaming authenticator, USB/NFC)
- iPhone Face ID (platform authenticator via Safari)
- Android fingerprint (platform authenticator via Chrome)

This module is part of the AIOHAI Core layer and provides accessor-agnostic
FIDO2/WebAuthn functionality. Both the AI proxy and direct user access use
this module for Tier 3/4 approvals.

Architecture:
  Any Accessor --> FIDOGate --> FIDO2ApprovalServer --> User Device
       |              |                  |                   |
       |   Request    |  WebAuthn        |  Face ID/Touch/   |
       |   Approval   |  challenge       |  NFC key tap      |
       |              |                  |                   |
       +--------------+------------------+-------------------+

Previously defined in security/fido2_approval.py.
Extracted as Phase 3 of the monolith → layered architecture migration.

Dependencies:
  pip install fido2>=1.1.0 flask>=3.0.0 flask-cors>=4.0.0 cryptography>=42.0.0

Import from: aiohai.core.crypto.fido_gate
"""

import json
import secrets
import hmac
import time
import threading
import logging
import os
import ssl
import base64
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, Any

# Import types from core
from aiohai.core.types import (
    ApprovalTier,
    ApprovalStatus,
    UserRole,
    RegisteredCredential,
    RegisteredUser,
    HardwareApprovalRequest,
)

# Import sibling modules
from aiohai.core.crypto.classifier import OperationClassifier
from aiohai.core.crypto.credentials import CredentialStore

logger = logging.getLogger("aiohai.core.crypto.fido")

# Optional imports with graceful degradation
try:
    from fido2.server import Fido2Server
    from fido2.webauthn import (
        PublicKeyCredentialRpEntity,
        PublicKeyCredentialUserEntity,
        AuthenticatorSelectionCriteria,
        UserVerificationRequirement,
        ResidentKeyRequirement,
        AuthenticatorAttachment,
        PublicKeyCredentialDescriptor,
        PublicKeyCredentialType,
    )
    FIDO2_AVAILABLE = True
except ImportError:
    FIDO2_AVAILABLE = False

try:
    from flask import Flask, request as flask_request, jsonify, render_template_string, abort
    from flask_cors import CORS
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

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
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# =============================================================================
# FIDO2 APPROVAL SERVER
# =============================================================================

class FIDO2ApprovalServer:
    """
    WebAuthn/FIDO2 approval server for AIOHAI.
    Runs as HTTPS, presents mobile-friendly approval UI,
    requires WebAuthn authentication to approve TIER 3+ operations.
    """

    def __init__(self, config: dict = None):
        if not FIDO2_AVAILABLE:
            raise ImportError("fido2 required: pip install fido2>=1.1.0")
        if not FLASK_AVAILABLE:
            raise ImportError("Flask required: pip install flask>=3.0.0 flask-cors>=4.0.0")

        self.config = config or {}
        self.host = self.config.get('host', '0.0.0.0')
        self.port = self.config.get('port', 11436)
        self.rp_id = self.config.get('rp_id', 'localhost')
        self.rp_name = self.config.get('rp_name', 'AIOHAI')
        self.origin = self.config.get('origin', f'https://{self.rp_id}:{self.port}')

        storage_path = Path(self.config.get('storage_path', 'data/fido2'))
        self.storage_path = storage_path
        self.credential_store = CredentialStore(storage_path)

        self.approval_requests: Dict[str, HardwareApprovalRequest] = {}
        self.approval_lock = threading.Lock()
        self.request_expiry_minutes = self.config.get('request_expiry_minutes', 5)

        self._reg_challenges: Dict[str, Any] = {}
        self._auth_challenges: Dict[str, Any] = {}
        self._challenge_lock = threading.Lock()
        self._api_secret = self.config.get('api_secret', secrets.token_hex(32))

        self.rp = PublicKeyCredentialRpEntity(self.rp_id, self.rp_name)
        self.fido2_server = Fido2Server(self.rp)
        self.hsm_manager = None
        self.app = self._create_flask_app()

        # Restore any pending approvals from a previous session
        self._restore_pending()

    def set_hsm_manager(self, hsm_manager):
        """Set the HSM manager for log signing integration."""
        self.hsm_manager = hsm_manager

    @property
    def api_secret(self) -> str:
        return self._api_secret

    def _verify_api_secret(self) -> bool:
        """Timing-safe verification of API secret from request headers."""
        provided = flask_request.headers.get('X-AIOHAI-Secret', '')
        return hmac.compare_digest(provided, self._api_secret)

    def _create_flask_app(self) -> 'Flask':
        """Create and configure the Flask application with all routes."""
        app = Flask(__name__)
        # SECURITY FIX (F-004): Restrict CORS to localhost/LAN origins
        allowed_origins = [
            "https://localhost:*", "http://localhost:*",
            "https://127.0.0.1:*", "http://127.0.0.1:*",
            "https://[::1]:*", "http://[::1]:*",
        ]
        # Allow user-configured additional origins (e.g. LAN phone IP)
        extra_origins = self.config.get('cors_allowed_origins', [])
        if extra_origins:
            allowed_origins.extend(extra_origins)
        CORS(app, resources={
            r"/api/*": {"origins": allowed_origins},
            r"/auth/*": {"origins": allowed_origins},
        })

        # === WEB ROUTES ===

        @app.route('/')
        def index():
            return render_template_string(
                _get_dashboard_html(), rp_name=self.rp_name)

        @app.route('/approve/<request_id>')
        def approve_page(request_id):
            with self.approval_lock:
                req = self.approval_requests.get(request_id)
            if not req:
                return render_template_string(
                    _get_error_html(), message="Request not found or expired"), 404
            if req.status != ApprovalStatus.PENDING:
                return render_template_string(
                    _get_error_html(), message=f"Request already {req.status.value}"), 400
            return render_template_string(
                _get_approval_html(), request=req.to_dict(), rp_name=self.rp_name)

        @app.route('/register')
        def register_page():
            return render_template_string(
                _get_register_html(), rp_name=self.rp_name)

        # === INTERNAL API ===

        @app.route('/api/request', methods=['POST'])
        def create_request():
            if not self._verify_api_secret():
                abort(403)
            data = flask_request.get_json()
            if not data:
                return jsonify({'error': 'No data'}), 400
            req = self.create_request_obj(
                data.get('operation_type', 'UNKNOWN'),
                data.get('target', ''),
                data.get('description', ''),
                data.get('tier', 3),
                data.get('metadata', {}),
            )
            return jsonify({
                'request_id': req.request_id,
                'approval_url': f"{self.origin}/approve/{req.request_id}",
                'expires_at': req.expires_at,
            }), 201

        @app.route('/api/status/<request_id>')
        def check_status(request_id):
            if not self._verify_api_secret():
                abort(403)
            with self.approval_lock:
                req = self.approval_requests.get(request_id)
            if not req:
                return jsonify({'status': 'not_found'}), 404
            if req.is_expired() and req.status == ApprovalStatus.PENDING:
                req.status = ApprovalStatus.EXPIRED
            return jsonify({
                'request_id': request_id,
                'status': req.status.value,
                'approved_by': req.approved_by,
                'authenticator_used': req.authenticator_used,
                'approved_at': req.approved_at,
            })

        @app.route('/api/cancel/<request_id>', methods=['POST'])
        def cancel(request_id):
            if not self._verify_api_secret():
                abort(403)
            with self.approval_lock:
                req = self.approval_requests.get(request_id)
                if req and req.status == ApprovalStatus.PENDING:
                    req.status = ApprovalStatus.CANCELLED
                    return jsonify({'status': 'cancelled'})
            return jsonify({'status': 'not_found'}), 404

        @app.route('/api/pending')
        def list_pending():
            if not self._verify_api_secret():
                return jsonify({'error': 'Unauthorized'}), 401
            with self.approval_lock:
                self._cleanup_expired()
                pending = {
                    rid: req.to_dict()
                    for rid, req in self.approval_requests.items()
                    if req.status == ApprovalStatus.PENDING
                }
            return jsonify({'requests': pending})

        # === WEBAUTHN REGISTRATION ===

        @app.route('/auth/register/begin', methods=['POST'])
        def reg_begin():
            data = flask_request.get_json()
            username = data.get('username', '').strip()
            device_name = data.get('device_name', 'Unknown')
            auth_type = data.get('authenticator_type', 'any')

            if not username:
                return jsonify({'error': 'Username required'}), 400

            user = self.credential_store.get_user(username)
            if not user:
                requested_role = data.get('role', 'admin')
                has_any_users = len(self.credential_store.get_all_users()) > 0

                if has_any_users and requested_role == 'admin':
                    # S2 FIX: After bootstrap, admin registration requires API secret
                    # (which only the proxy knows). This prevents LAN attackers from
                    # registering admin keys directly against the FIDO2 server.
                    if not self._verify_api_secret():
                        return jsonify({
                            'error': 'Admin registration requires existing admin '
                                     'approval (API secret). Use role=restricted '
                                     'for self-registration.'
                        }), 403

                role = UserRole(data.get('role', 'admin') if not has_any_users
                                else requested_role)
                user = self.credential_store.add_user(
                    username, role, data.get('allowed_paths', []))

            existing = [
                PublicKeyCredentialDescriptor(
                    type=PublicKeyCredentialType.PUBLIC_KEY, id=c.credential_id)
                for c in user.credentials
            ]

            webauthn_user = PublicKeyCredentialUserEntity(
                id=user.user_id, name=username, display_name=username)

            attachment = None
            if auth_type == 'security_key':
                attachment = AuthenticatorAttachment.CROSS_PLATFORM
            elif auth_type == 'platform':
                attachment = AuthenticatorAttachment.PLATFORM

            creation_options, state = self.fido2_server.register_begin(
                user=webauthn_user,
                credentials=existing,
                user_verification=UserVerificationRequirement.PREFERRED,
                authenticator_attachment=attachment,
            )

            session_id = secrets.token_hex(16)
            with self._challenge_lock:
                self._reg_challenges[session_id] = {
                    'state': state, 'username': username,
                    'device_name': device_name,
                    'authenticator_type': auth_type,
                    'expires': time.time() + 120,
                }

            resp = self._encode_bytes_deep(dict(creation_options))
            resp['session_id'] = session_id
            return jsonify(resp)

        @app.route('/auth/register/complete', methods=['POST'])
        def reg_complete():
            data = flask_request.get_json()
            session_id = data.get('session_id')
            with self._challenge_lock:
                ch = self._reg_challenges.pop(session_id, None)
            if not ch:
                return jsonify({'error': 'Session not found'}), 400
            if time.time() > ch['expires']:
                return jsonify({'error': 'Session expired'}), 400
            try:
                auth_data = self.fido2_server.register_complete(
                    ch['state'], response=data.get('credential'))
                cred = RegisteredCredential(
                    credential_id=auth_data.credential_data.credential_id,
                    public_key=auth_data.credential_data.public_key,
                    sign_count=0,
                    authenticator_type=ch['authenticator_type'],
                    device_name=ch['device_name'],
                    registered_at=datetime.now().isoformat(),
                )
                self.credential_store.add_credential(ch['username'], cred)
                return jsonify({
                    'status': 'ok',
                    'message': f"'{ch['device_name']}' registered for {ch['username']}",
                })
            except Exception as e:
                logger.error(f"Registration failed: {e}")
                return jsonify({'error': str(e)}), 400

        # === WEBAUTHN AUTHENTICATION (APPROVAL) ===

        @app.route('/auth/approve/begin', methods=['POST'])
        def auth_begin():
            data = flask_request.get_json()
            request_id = data.get('request_id')
            username = data.get('username', '').strip()
            if not request_id or not username:
                return jsonify({'error': 'request_id and username required'}), 400

            with self.approval_lock:
                areq = self.approval_requests.get(request_id)
            if not areq:
                return jsonify({'error': 'Not found'}), 404
            if areq.status != ApprovalStatus.PENDING:
                return jsonify({'error': f'Already {areq.status.value}'}), 400
            if areq.is_expired():
                areq.status = ApprovalStatus.EXPIRED
                return jsonify({'error': 'Expired'}), 400

            can, reason = self.credential_store.user_can_approve(
                username, areq.tier, areq.target)
            if not can:
                return jsonify({'error': reason}), 403

            user = self.credential_store.get_user(username)
            if not user or not user.credentials:
                return jsonify({'error': 'No credentials registered'}), 400

            # Filter credentials based on tier's required authenticator type.
            # Tier 4 requires a roaming hardware key (security_key) — platform
            # authenticators (biometric) are not accepted.
            required_auth = areq.required_authenticator
            if required_auth == 'security_key':
                eligible_creds = [
                    c for c in user.credentials
                    if c.authenticator_type == 'security_key'
                ]
                if not eligible_creds:
                    return jsonify({
                        'error': 'This operation requires a physical security '
                                 'key (YubiKey/Nitrokey). Platform authenticators '
                                 '(biometric) are not accepted for Tier 4 '
                                 'operations. Register a hardware key first.'
                    }), 403
            else:
                eligible_creds = user.credentials

            cred_descs = [
                PublicKeyCredentialDescriptor(
                    type=PublicKeyCredentialType.PUBLIC_KEY, id=c.credential_id)
                for c in eligible_creds
            ]

            req_options, state = self.fido2_server.authenticate_begin(
                credentials=cred_descs,
                user_verification=UserVerificationRequirement.PREFERRED,
            )

            session_id = secrets.token_hex(16)
            with self._challenge_lock:
                self._auth_challenges[session_id] = {
                    'state': state, 'username': username,
                    'request_id': request_id,
                    'expires': time.time() + 60,
                }

            resp = self._encode_bytes_deep(dict(req_options))
            resp['session_id'] = session_id
            return jsonify(resp)

        @app.route('/auth/approve/complete', methods=['POST'])
        def auth_complete():
            data = flask_request.get_json()
            session_id = data.get('session_id')
            with self._challenge_lock:
                ch = self._auth_challenges.pop(session_id, None)
            if not ch:
                return jsonify({'error': 'Session not found'}), 400
            if time.time() > ch['expires']:
                return jsonify({'error': 'Session expired'}), 400

            username = ch['username']
            request_id = ch['request_id']
            user = self.credential_store.get_user(username)
            if not user:
                return jsonify({'error': 'User not found'}), 400

            try:
                cred_descs = [
                    PublicKeyCredentialDescriptor(
                        type=PublicKeyCredentialType.PUBLIC_KEY,
                        id=c.credential_id)
                    for c in user.credentials
                ]
                auth_result = self.fido2_server.authenticate_complete(
                    ch['state'], credentials=cred_descs,
                    response=data.get('credential'),
                )
                with self.approval_lock:
                    areq = self.approval_requests.get(request_id)
                    if areq and areq.status == ApprovalStatus.PENDING:
                        areq.status = ApprovalStatus.APPROVED
                        areq.approved_by = username
                        areq.approved_at = datetime.now().isoformat()
                        # C2 FIX: Match the actual credential used (by credential_id)
                        # instead of always recording the first registered credential.
                        authenticator_name = "unknown"
                        try:
                            used_cred_id = auth_result.credential_id
                            for c in user.credentials:
                                if c.credential_id == used_cred_id:
                                    authenticator_name = c.device_name
                                    break
                        except AttributeError:
                            # Fallback: library version doesn't expose credential_id
                            for c in user.credentials:
                                authenticator_name = c.device_name
                                break
                        areq.authenticator_used = authenticator_name
                        logger.info(
                            f"APPROVED: {request_id[:8]}... by {username} "
                            f"({areq.operation_type})")
                        return jsonify({
                            'status': 'approved',
                            'message': f'Approved by {username}',
                            'request_id': request_id,
                        })
                return jsonify({'error': 'No longer pending'}), 400
            except Exception as e:
                logger.error(f"Auth failed for {username}: {e}")
                return jsonify({'error': f'Auth failed: {str(e)}'}), 400

        @app.route('/auth/reject', methods=['POST'])
        def auth_reject():
            data = flask_request.get_json()
            request_id = data.get('request_id')
            username = data.get('username', 'unknown')
            with self.approval_lock:
                req = self.approval_requests.get(request_id)
                if req and req.status == ApprovalStatus.PENDING:
                    req.status = ApprovalStatus.REJECTED
                    req.approved_by = username
                    req.approved_at = datetime.now().isoformat()
                    logger.info(f"REJECTED: {request_id[:8]}... by {username}")
                    return jsonify({'status': 'rejected'})
            return jsonify({'error': 'Not found'}), 404

        # === STATUS ===

        @app.route('/api/users')
        def list_users():
            if not self._verify_api_secret():
                return jsonify({'error': 'Unauthorized'}), 401
            users = self.credential_store.get_all_users()
            result = {}
            for name, user in users.items():
                result[name] = {
                    'role': user.role.value,
                    'devices': [{'name': c.device_name, 'type': c.authenticator_type,
                                 'registered': c.registered_at, 'last_used': c.last_used}
                                for c in user.credentials],
                    'created': user.created_at,
                }
            return jsonify(result)

        @app.route('/api/health')
        def health():
            # S1 FIX: Health check remains unauthenticated (monitoring needs it),
            # but no longer discloses user count or pending request count.
            from aiohai.core.version import __version__
            return jsonify({
                'status': 'ok', 'server': self.rp_name,
                'fido2': FIDO2_AVAILABLE,
                'version': __version__,
            })

        return app

    # =========================================================================
    # HELPERS
    # =========================================================================

    @staticmethod
    def _encode_bytes_deep(obj):
        """Recursively encode bytes to base64url strings for JSON serialization."""
        if isinstance(obj, bytes):
            return base64.urlsafe_b64encode(obj).decode('ascii')
        elif isinstance(obj, dict):
            return {k: FIDO2ApprovalServer._encode_bytes_deep(v) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return [FIDO2ApprovalServer._encode_bytes_deep(v) for v in obj]
        elif hasattr(obj, '__iter__') and not isinstance(obj, str):
            try:
                return [FIDO2ApprovalServer._encode_bytes_deep(v) for v in obj]
            except TypeError:
                return obj
        return obj

    def create_request_obj(self, operation_type: str, target: str,
                           description: str, tier: int = 3,
                           metadata: dict = None) -> HardwareApprovalRequest:
        """Create a new approval request and store it."""
        request_id = secrets.token_urlsafe(16)
        now = datetime.now()
        approval_tier = ApprovalTier(tier)
        req = HardwareApprovalRequest(
            request_id=request_id,
            operation_type=operation_type,
            target=target,
            description=description,
            tier=approval_tier,
            required_role=OperationClassifier.get_required_role(approval_tier, target),
            required_authenticator=OperationClassifier.get_required_authenticator(
                approval_tier),
            created_at=now.isoformat(),
            expires_at=(now + timedelta(minutes=self.request_expiry_minutes)).isoformat(),
            metadata=metadata or {},
        )
        with self.approval_lock:
            self._cleanup_expired()
            self.approval_requests[request_id] = req
            self._persist_pending()
        return req

    def get_request_status(self, request_id: str) -> Optional[HardwareApprovalRequest]:
        """Get the current status of an approval request."""
        with self.approval_lock:
            req = self.approval_requests.get(request_id)
            if req and req.is_expired() and req.status == ApprovalStatus.PENDING:
                req.status = ApprovalStatus.EXPIRED
                self._persist_pending()
            return req

    def _cleanup_expired(self):
        """Remove old non-pending requests."""
        cutoff = datetime.now() - timedelta(minutes=self.request_expiry_minutes * 6)
        to_remove = [
            rid for rid, req in self.approval_requests.items()
            if req.status != ApprovalStatus.PENDING
            and datetime.fromisoformat(req.created_at) < cutoff
        ]
        for rid in to_remove:
            del self.approval_requests[rid]
        if to_remove:
            self._persist_pending()

    def _persist_pending(self):
        """Save pending approval requests to disk for crash recovery."""
        try:
            pending = {
                rid: req.to_dict() for rid, req in self.approval_requests.items()
                if req.status == ApprovalStatus.PENDING
            }
            pending_path = Path(self.storage_path) / 'pending_approvals.json'
            pending_path.parent.mkdir(parents=True, exist_ok=True)
            pending_path.write_text(json.dumps(pending, indent=2))
        except Exception as e:
            logger.warning(f"Failed to persist pending approvals: {e}")

    def _restore_pending(self):
        """Restore pending approval requests from disk after restart."""
        try:
            pending_path = Path(self.storage_path) / 'pending_approvals.json'
            if not pending_path.exists():
                return
            data = json.loads(pending_path.read_text())
            restored = 0
            for rid, req_dict in data.items():
                # Only restore requests that haven't expired
                expires_at = datetime.fromisoformat(req_dict.get('expires_at', ''))
                if expires_at > datetime.now():
                    req = HardwareApprovalRequest(
                        request_id=rid,
                        operation_type=req_dict.get('operation_type', 'UNKNOWN'),
                        target=req_dict.get('target', ''),
                        description=req_dict.get('description', ''),
                        tier=ApprovalTier(req_dict.get('tier', 3)),
                        required_role=req_dict.get('required_role', 'admin'),
                        created_at=req_dict.get('created_at', ''),
                        expires_at=req_dict.get('expires_at', ''),
                        metadata=req_dict.get('metadata', {}),
                    )
                    self.approval_requests[rid] = req
                    restored += 1
            if restored:
                logger.info(f"Restored {restored} pending approval requests from disk")
            # Clean up the file
            pending_path.unlink(missing_ok=True)
        except Exception as e:
            logger.warning(f"Failed to restore pending approvals: {e}")

    # =========================================================================
    # SSL
    # =========================================================================

    def generate_self_signed_cert(self, cert_dir: Path) -> Tuple[Path, Path]:
        """Generate a self-signed TLS certificate for the approval server."""
        if not CRYPTO_AVAILABLE:
            raise ImportError("cryptography library required for SSL")
        cert_dir.mkdir(parents=True, exist_ok=True)
        cert_path = cert_dir / "aiohai.crt"
        key_path = cert_dir / "aiohai.key"

        if cert_path.exists() and key_path.exists():
            try:
                cert_data = cert_path.read_bytes()
                cert_obj = x509.load_pem_x509_certificate(cert_data)
                if cert_obj.not_valid_after_utc > datetime.utcnow():
                    return cert_path, key_path
            except Exception:
                pass

        key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = Name([
            NameAttribute(NameOID.COMMON_NAME, self.rp_id),
            NameAttribute(NameOID.ORGANIZATION_NAME, 'AIOHAI'),
        ])
        san_names = [DNSName(self.rp_id), DNSName('localhost')]
        for ip_str in ['127.0.0.1', '192.168.1.1']:
            try:
                san_names.append(IPAddress(ipaddress.ip_address(ip_str)))
            except Exception:
                pass

        cert_obj = (
            CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .add_extension(BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(SubjectAlternativeName(san_names), critical=False)
            .sign(key, hashes.SHA256())
        )
        key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        cert_path.write_bytes(cert_obj.public_bytes(serialization.Encoding.PEM))
        try:
            os.chmod(key_path, 0o600)
        except Exception:
            pass
        logger.info(f"Generated SSL cert: {cert_path}")
        return cert_path, key_path

    # =========================================================================
    # START
    # =========================================================================

    def start(self, use_ssl: bool = True, cert_dir: Path = None,
              threaded: bool = True):
        """Start the FIDO2 approval server.
        
        Args:
            use_ssl: Whether to use HTTPS (recommended)
            cert_dir: Directory for SSL certificates
            threaded: If True, start in a daemon thread and return
        """
        ssl_ctx = None
        if use_ssl:
            cert_dir = cert_dir or Path('data/ssl')
            cert_path, key_path = self.generate_self_signed_cert(cert_dir)
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx.load_cert_chain(cert_path, key_path)
            ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        proto = 'https' if use_ssl else 'http'
        print(f"\n  FIDO2 Approval Server: {proto}://{self.host}:{self.port}")
        print(f"  RP ID: {self.rp_id}  |  Users: {len(self.credential_store.get_all_users())}")

        if threaded:
            t = threading.Thread(
                target=self.app.run,
                kwargs={'host': self.host, 'port': self.port,
                        'ssl_context': ssl_ctx, 'debug': False,
                        'use_reloader': False},
                daemon=True)
            t.start()
            return t
        else:
            self.app.run(host=self.host, port=self.port,
                         ssl_context=ssl_ctx, debug=False)


# =============================================================================
# PROXY INTEGRATION CLIENT
# =============================================================================

class FIDO2ApprovalClient:
    """Client for proxy to communicate with the approval server."""

    MAX_RETRIES = 3
    RETRY_BACKOFF = 0.5  # seconds, doubles each retry

    def __init__(self, server: FIDO2ApprovalServer = None,
                 server_url: str = None, api_secret: str = None,
                 cert_path: str = None):
        self.server = server
        self.server_url = server_url
        self.api_secret = api_secret
        self.cert_path = cert_path  # Path to server's self-signed cert for verification
        self._mode = 'direct' if server else 'http'

    @property
    def _verify(self):
        """SSL verification: use pinned cert if available, else True (system CAs)."""
        if self.cert_path and os.path.exists(self.cert_path):
            return self.cert_path
        return True

    def _http_request(self, method: str, url: str, **kwargs):
        """HTTP request with retry and exponential backoff for transient failures."""
        import requests as http
        kwargs.setdefault('verify', self._verify)
        kwargs.setdefault('timeout', 5)
        kwargs.setdefault('headers', {})
        if self.api_secret:
            kwargs['headers']['X-AIOHAI-Secret'] = self.api_secret

        last_err = None
        for attempt in range(self.MAX_RETRIES):
            try:
                resp = getattr(http, method)(url, **kwargs)
                return resp
            except (http.exceptions.ConnectionError,
                    http.exceptions.Timeout) as e:
                last_err = e
                if attempt < self.MAX_RETRIES - 1:
                    time.sleep(self.RETRY_BACKOFF * (2 ** attempt))
        raise last_err

    def request_approval(self, operation_type: str, target: str,
                         description: str, tier: int = 3,
                         metadata: dict = None) -> dict:
        """Request approval for an operation."""
        if self._mode == 'direct':
            req = self.server.create_request_obj(
                operation_type, target, description, tier, metadata)
            return {
                'request_id': req.request_id,
                'approval_url': f"{self.server.origin}/approve/{req.request_id}",
                'expires_at': req.expires_at,
                'status': req.status.value,
            }
        else:
            resp = self._http_request('post',
                f"{self.server_url}/api/request",
                json={'operation_type': operation_type, 'target': target,
                      'description': description, 'tier': tier,
                      'metadata': metadata or {}})
            return resp.json()

    # =========================================================================
    # Phase 1B: Gate-aware authentication methods
    # =========================================================================

    def authenticate_physical(self, operation_type: str, target: str,
                              description: str, metadata: dict = None,
                              timeout_seconds: int = None) -> dict:
        """Request PHYSICAL gate authentication (NFC tap at server).

        The PHYSICAL gate proves the authorized person is physically present
        at the server. This method sets tier=4 to require a roaming key
        (no platform/biometric authenticator) and uses no timeout by default
        (the user might need to walk to the server).

        Returns dict with 'status' key: 'approved', 'rejected', 'timeout', etc.
        """
        # Physical gate: require roaming key, no biometric allowed
        req = self.request_approval(
            operation_type=operation_type,
            target=target,
            description=description,
            tier=4,  # Tier 4 = roaming hardware key only (NFC/USB)
            metadata={**(metadata or {}), '_gate': 'PHYSICAL'},
        )
        request_id = req.get('request_id', '')

        # No default timeout for physical gate — user might be walking to server
        if timeout_seconds is None:
            timeout_seconds = 600  # 10 minute generous default

        return self.wait_for_approval(
            request_id,
            timeout_seconds=timeout_seconds,
            poll_interval=1.0,
        )

    def authenticate_biometric(self, operation_type: str, target: str,
                               description: str, metadata: dict = None,
                               timeout_seconds: int = 120) -> dict:
        """Request BIOMETRIC gate authentication (any registered authenticator).

        The BIOMETRIC gate proves the authorized person possesses their
        registered authenticator and is actively choosing to approve. Any
        FIDO2-compatible device works (fingerprint, Face ID, security key).

        Returns dict with 'status' key: 'approved', 'rejected', 'timeout', etc.
        """
        # Biometric gate: any FIDO2 authenticator (platform or roaming)
        req = self.request_approval(
            operation_type=operation_type,
            target=target,
            description=description,
            tier=3,  # Tier 3 = any FIDO2 (platform biometric or roaming key)
            metadata={**(metadata or {}), '_gate': 'BIOMETRIC'},
        )
        request_id = req.get('request_id', '')

        return self.wait_for_approval(
            request_id,
            timeout_seconds=timeout_seconds,
            poll_interval=1.0,
        )

    def check_status(self, request_id: str) -> dict:
        """Check the status of an approval request."""
        if self._mode == 'direct':
            req = self.server.get_request_status(request_id)
            if not req:
                return {'status': 'not_found'}
            return {
                'request_id': request_id,
                'status': req.status.value,
                'approved_by': req.approved_by,
                'authenticator_used': req.authenticator_used,
                'approved_at': req.approved_at,
            }
        else:
            resp = self._http_request('get',
                f"{self.server_url}/api/status/{request_id}")
            return resp.json()

    def wait_for_approval(self, request_id: str, timeout_seconds: int = 300,
                          poll_interval: float = 1.0, callback=None) -> dict:
        """Poll for approval status until resolved or timeout."""
        start = time.time()
        while time.time() - start < timeout_seconds:
            try:
                status = self.check_status(request_id)
            except Exception:
                # Transient failure during poll — continue waiting
                time.sleep(poll_interval)
                continue
            if callback:
                callback(status)
            if status.get('status') in ('approved', 'rejected', 'expired',
                                         'cancelled', 'not_found'):
                return status
            time.sleep(poll_interval)
        return {'status': 'timeout', 'request_id': request_id}

    def cancel_request(self, request_id: str) -> bool:
        """Cancel a pending approval request."""
        if self._mode == 'direct':
            req = self.server.get_request_status(request_id)
            if req and req.status == ApprovalStatus.PENDING:
                req.status = ApprovalStatus.CANCELLED
                return True
            return False
        else:
            resp = self._http_request('post',
                f"{self.server_url}/api/cancel/{request_id}")
            return resp.json().get('status') == 'cancelled'


# =============================================================================
# HTML TEMPLATES — O1 FIX: Extracted to fido2_templates.py for readability.
# This is a standard Python import, NOT runtime file loading.
# =============================================================================

from aiohai.core.crypto.fido2_templates import (
    _get_dashboard_html, _get_approval_html,
    _get_register_html, _get_error_html,
)


# =============================================================================
# CLI
# =============================================================================

def main():
    """Standalone CLI for running the FIDO2 approval server."""
    import argparse
    parser = argparse.ArgumentParser(description='AIOHAI FIDO2 Approval Server')
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=11436)
    parser.add_argument('--rp-id', default='localhost')
    parser.add_argument('--rp-name', default='AIOHAI')
    parser.add_argument('--no-ssl', action='store_true')
    parser.add_argument('--storage', default='data/fido2')
    parser.add_argument('--cert-dir', default='data/ssl')
    args = parser.parse_args()

    config = {
        'host': args.host, 'port': args.port,
        'rp_id': args.rp_id, 'rp_name': args.rp_name,
        'origin': f"{'http' if args.no_ssl else 'https'}://{args.rp_id}:{args.port}",
        'storage_path': args.storage,
    }
    print("=" * 60)
    print("AIOHAI FIDO2 Approval Server")
    print("=" * 60)
    server = FIDO2ApprovalServer(config)
    print(f"\nAPI Secret: {server.api_secret[:8]}...{server.api_secret[-4:]}")
    server.start(use_ssl=not args.no_ssl, cert_dir=Path(args.cert_dir), threaded=False)


if __name__ == '__main__':
    main()


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Types (from core.types)
    'ApprovalTier',
    'ApprovalStatus',
    'UserRole',
    'RegisteredCredential',
    'RegisteredUser',
    'HardwareApprovalRequest',

    # Classes
    'OperationClassifier',
    'CredentialStore',
    'FIDO2ApprovalServer',
    'FIDO2ApprovalClient',

    # Availability flags
    'FIDO2_AVAILABLE',
    'FLASK_AVAILABLE',
    'CRYPTO_AVAILABLE',
]
