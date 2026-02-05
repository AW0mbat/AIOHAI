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
                role = UserRole(data.get('role', 'admin'))
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

            cred_descs = [
                PublicKeyCredentialDescriptor(
                    type=PublicKeyCredentialType.PUBLIC_KEY, id=c.credential_id)
                for c in user.credentials
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
                self.fido2_server.authenticate_complete(
                    ch['state'], credentials=cred_descs,
                    response=data.get('credential'),
                )
                with self.approval_lock:
                    areq = self.approval_requests.get(request_id)
                    if areq and areq.status == ApprovalStatus.PENDING:
                        areq.status = ApprovalStatus.APPROVED
                        areq.approved_by = username
                        areq.approved_at = datetime.now().isoformat()
                        for c in user.credentials:
                            areq.authenticator_used = c.device_name
                            break
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
            return jsonify({
                'status': 'ok', 'server': self.rp_name,
                'fido2': FIDO2_AVAILABLE,
                'users': len(self.credential_store.get_all_users()),
                'pending': sum(1 for r in self.approval_requests.values()
                               if r.status == ApprovalStatus.PENDING),
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
# HTML TEMPLATES
# =============================================================================

def _get_dashboard_html():
    return _DASHBOARD_HTML

def _get_approval_html():
    return _APPROVAL_HTML

def _get_register_html():
    return _REGISTER_HTML

def _get_error_html():
    return _ERROR_HTML

# Templates loaded from companion file or inline
try:
    _templates_path = Path(__file__).parent / 'fido2_templates.py'
    if _templates_path.exists():
        exec(_templates_path.read_text(encoding='utf-8'))
    else:
        raise FileNotFoundError
except Exception:
    # Inline fallback templates
    _DASHBOARD_HTML = r"""<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ rp_name }} Approvals</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui;background:#0a0a0f;color:#e8e8f0;min-height:100vh;padding:1rem}
.hdr{padding:1rem 0;border-bottom:1px solid #2a2a3a;margin-bottom:1rem;display:flex;justify-content:space-between;align-items:center}
.hdr h1{font-size:1.1rem}.dot{width:8px;height:8px;border-radius:50%;background:#4f8;animation:p 2s infinite}
@keyframes p{50%{opacity:.5}}.empty{text-align:center;padding:3rem;color:#888}.card{background:#12121a;border:1px solid #2a2a3a;border-radius:12px;padding:1rem;margin-bottom:.75rem}
.card.del{border-left:3px solid #f44}.op{font-family:monospace;font-size:.8rem;font-weight:700;padding:.15rem .5rem;border-radius:4px;background:rgba(255,68,68,.15);color:#f44;display:inline-block}
.tgt{font-family:monospace;font-size:.85rem;margin:.5rem 0;word-break:break-all}.desc{font-size:.85rem;color:#888}
.btns{display:flex;gap:.5rem;margin-top:1rem}.btn{flex:1;padding:.75rem;border:none;border-radius:8px;font-weight:700;cursor:pointer;font-size:.85rem}
.btn-a{background:#4af;color:#000}.btn-r{background:#1a1a28;color:#888;border:1px solid #2a2a3a}
.nav{position:fixed;bottom:0;left:0;right:0;background:#12121a;border-top:1px solid #2a2a3a;display:flex;padding:.5rem 0}
.nav a{flex:1;text-align:center;color:#888;text-decoration:none;font-size:.7rem;padding:.5rem}
.nav a.on{color:#4af}.badge{background:#f44;color:#fff;font-size:.6rem;padding:.1rem .35rem;border-radius:9px;margin-left:.2rem}
.toast{position:fixed;bottom:4rem;left:50%;transform:translateX(-50%) translateY(100px);background:#1a1a28;border:1px solid #2a2a3a;border-radius:8px;padding:.75rem 1.25rem;font-size:.85rem;opacity:0;transition:.3s;z-index:99}
.toast.show{transform:translateX(-50%) translateY(0);opacity:1}.toast.ok{border-color:#4f8}.toast.err{border-color:#f44}</style></head>
<body><div class="hdr"><h1>🔐 {{ rp_name }}</h1><div class="dot"></div></div>
<div id="list"><div class="empty">🛡️<br><br>No pending approvals</div></div>
<div class="nav"><a href="/" class="on">🛡️ Approvals<span class="badge" id="badge" style="display:none">0</span></a><a href="/register">🔑 Devices</a></div>
<div class="toast" id="toast"></div>
<script>
async function poll(){try{const r=await fetch('/api/pending');const d=await r.json();render(d.requests||{})}catch(e){}}
function render(reqs){const l=document.getElementById('list');const b=document.getElementById('badge');const e=Object.entries(reqs);
b.textContent=e.length;b.style.display=e.length?'inline':'none';
if(!e.length){l.innerHTML='<div class="empty">🛡️<br><br>No pending approvals</div>';return}
l.innerHTML=e.map(([id,r])=>{const rem=Math.max(0,Math.floor((new Date(r.expires_at)-Date.now())/1000));
return`<div class="card del"><div style="display:flex;justify-content:space-between"><span class="op">${r.operation_type}</span><span style="font-family:monospace;font-size:.75rem;color:#888">${Math.floor(rem/60)}:${String(rem%60).padStart(2,'0')}</span></div>
<div class="tgt">${esc(r.target)}</div><div class="desc">${esc(r.description)}</div>
<div class="btns"><button class="btn btn-a" onclick="doApprove('${id}')">🔐 Approve</button><button class="btn btn-r" onclick="doReject('${id}')">✕ Reject</button></div></div>`}).join('')}
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
function toast(m,t){const e=document.getElementById('toast');e.textContent=m;e.className='toast show '+(t||'');setTimeout(()=>e.className='toast',3000)}
function b64d(s){s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';return Uint8Array.from(atob(s),c=>c.charCodeAt(0))}
function b64e(b){return btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')}
function decOpts(o){const p=o.publicKey||o;if(p.challenge)p.challenge=b64d(p.challenge);if(p.allowCredentials)p.allowCredentials=p.allowCredentials.map(c=>({...c,id:b64d(c.id)}));return p}
function encCred(c){return{id:c.id,rawId:b64e(c.rawId),type:c.type,response:{authenticatorData:b64e(c.response.authenticatorData),clientDataJSON:b64e(c.response.clientDataJSON),signature:b64e(c.response.signature),userHandle:c.response.userHandle?b64e(c.response.userHandle):null}}}
async function doApprove(rid){const u=localStorage.getItem('aiohai_username');if(!u){toast('Set username at /register','err');return}
try{const br=await fetch('/auth/approve/begin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({request_id:rid,username:u})});
if(!br.ok){toast((await br.json()).error||'Failed','err');return}const opts=await br.json();
const cred=await navigator.credentials.get({publicKey:decOpts(opts)});
const cr=await fetch('/auth/approve/complete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session_id:opts.session_id,credential:encCred(cred)})});
if(cr.ok){toast('✓ Approved','ok');poll()}else{toast((await cr.json()).error||'Failed','err')}}
catch(e){if(e.name==='NotAllowedError')toast('Cancelled','err');else toast(e.message,'err')}}
async function doReject(rid){const u=localStorage.getItem('aiohai_username')||'unknown';
await fetch('/auth/reject',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({request_id:rid,username:u})});toast('Rejected','ok');poll()}
poll();setInterval(poll,2000);
</script></body></html>"""

    _APPROVAL_HTML = r"""<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Approve — {{ rp_name }}</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui;background:#0a0a0f;color:#e8e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1.5rem}
.card{background:#12121a;border:1px solid #2a2a3a;border-radius:16px;padding:2rem;max-width:420px;width:100%;text-align:center}
.icon{font-size:3rem;margin-bottom:1rem}.title{font-size:1.1rem;font-weight:700;margin-bottom:.5rem}
.sub{font-size:.85rem;color:#888;margin-bottom:1.5rem}.detail{background:#1a1a28;border-radius:8px;padding:1rem;margin-bottom:1.5rem;text-align:left}
.row{display:flex;justify-content:space-between;margin-bottom:.5rem}.lbl{font-size:.7rem;color:#888;text-transform:uppercase;letter-spacing:1px;font-family:monospace}
.val{font-family:monospace;font-size:.85rem;word-break:break-all}.val.red{color:#f44}
.btn{width:100%;padding:1rem;border:none;border-radius:12px;font-size:1rem;font-weight:700;cursor:pointer;margin-bottom:.75rem}
.btn-a{background:#4af;color:#000}.btn-r{background:#1a1a28;color:#888;border:1px solid #2a2a3a}
.btn:disabled{opacity:.5}#st{font-size:.8rem;color:#888;margin-top:1rem;min-height:1.5rem}
.done{padding:2rem;text-align:center}.done .icon{font-size:4rem}.done.ok{color:#4f8}.done.no{color:#f44}</style></head>
<body><div class="card" id="card"><div class="icon">🔐</div><div class="title">Hardware Approval Required</div>
<div class="sub">Authenticate to approve this operation</div>
<div class="detail"><div class="row"><span class="lbl">Operation</span><span class="val red">{{ request.operation_type }}</span></div>
<div class="row"><span class="lbl">Target</span><span class="val">{{ request.target }}</span></div>
<div class="row"><span class="lbl">Tier</span><span class="val">TIER {{ request.tier }}</span></div>
{% if request.description %}<div class="row"><span class="lbl">Details</span><span class="val">{{ request.description }}</span></div>{% endif %}</div>
<button class="btn btn-a" id="abtn" onclick="go()">🔐 Approve with Biometrics</button>
<button class="btn btn-r" onclick="rej()">✕ Reject</button><div id="st"></div></div>
<script>const RID='{{ request.request_id }}';
function b64d(s){s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';return Uint8Array.from(atob(s),c=>c.charCodeAt(0))}
function b64e(b){return btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')}
function decO(o){const p=o.publicKey||o;if(p.challenge)p.challenge=b64d(p.challenge);if(p.allowCredentials)p.allowCredentials=p.allowCredentials.map(c=>({...c,id:b64d(c.id)}));return p}
function encC(c){return{id:c.id,rawId:b64e(c.rawId),type:c.type,response:{authenticatorData:b64e(c.response.authenticatorData),clientDataJSON:b64e(c.response.clientDataJSON),signature:b64e(c.response.signature),userHandle:c.response.userHandle?b64e(c.response.userHandle):null}}}
async function go(){const u=localStorage.getItem('aiohai_username');if(!u){document.getElementById('st').textContent='Set username at /register';return}
const b=document.getElementById('abtn');b.disabled=true;b.textContent='⏳ Authenticating...';
try{const br=await fetch('/auth/approve/begin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({request_id:RID,username:u})});
if(!br.ok)throw new Error((await br.json()).error);const opts=await br.json();document.getElementById('st').textContent='Touch key or verify biometrics...';
const cred=await navigator.credentials.get({publicKey:decO(opts)});
const cr=await fetch('/auth/approve/complete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session_id:opts.session_id,credential:encC(cred)})});
if(cr.ok){document.getElementById('card').innerHTML='<div class="done ok"><div class="icon">✅</div><div class="title">Approved</div><p style="margin-top:1rem;color:#888">You can close this page.</p></div>'}
else throw new Error((await cr.json()).error)}
catch(e){b.disabled=false;b.textContent='🔐 Approve with Biometrics';document.getElementById('st').textContent='Error: '+e.message}}
async function rej(){const u=localStorage.getItem('aiohai_username')||'unknown';
await fetch('/auth/reject',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({request_id:RID,username:u})});
document.getElementById('card').innerHTML='<div class="done no"><div class="icon">❌</div><div class="title">Rejected</div><p style="margin-top:1rem;color:#888">You can close this page.</p></div>'}
</script></body></html>"""

    _REGISTER_HTML = r"""<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Register — {{ rp_name }}</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui;background:#0a0a0f;color:#e8e8f0;min-height:100vh;padding:1.5rem}
.hdr{text-align:center;margin-bottom:2rem}.hdr h1{font-size:1.2rem;margin-bottom:.5rem}.hdr p{font-size:.85rem;color:#888}
.fg{margin-bottom:1.25rem}.fl{font-size:.7rem;text-transform:uppercase;letter-spacing:2px;color:#888;margin-bottom:.5rem;display:block;font-family:monospace}
.fi{width:100%;padding:.75rem;background:#12121a;border:1px solid #2a2a3a;border-radius:8px;color:#e8e8f0;font-size:.9rem}
.fi:focus{outline:none;border-color:#4af}select.fi{appearance:none;-webkit-appearance:none}
.dg{display:grid;grid-template-columns:1fr 1fr;gap:.75rem;margin-bottom:1.5rem}
.dc{background:#12121a;border:2px solid #2a2a3a;border-radius:12px;padding:1.25rem;text-align:center;cursor:pointer;transition:.2s}
.dc:hover{border-color:#4af}.dc.sel{border-color:#4af;box-shadow:0 0 20px rgba(68,170,255,.15)}
.dc .di{font-size:2rem;margin-bottom:.5rem}.dc .dn{font-size:.8rem;font-weight:700}.dc .dd{font-size:.7rem;color:#888;margin-top:.25rem}
.btn{width:100%;padding:1rem;border:none;border-radius:12px;font-size:1rem;font-weight:700;cursor:pointer;background:#4af;color:#000}
.btn:disabled{opacity:.5}#st{text-align:center;font-size:.85rem;margin-top:1rem;min-height:1.5rem}#st.ok{color:#4f8}#st.err{color:#f44}
.devs{margin-top:2rem}.di-item{background:#12121a;border:1px solid #2a2a3a;border-radius:8px;padding:1rem;margin-bottom:.5rem;display:flex;justify-content:space-between}
.di-info .di-t{font-weight:700;font-size:.9rem}.di-info .di-m{font-size:.75rem;color:#888;font-family:monospace}
a.back{display:block;text-align:center;margin-top:1.5rem;color:#4af;text-decoration:none;font-size:.85rem}</style></head>
<body><div class="hdr"><h1>🔑 Register Device</h1><p>Add a security key or biometric authenticator</p></div>
<div class="fg"><label class="fl">Username</label><input class="fi" id="uname" placeholder="e.g. admin"></div>
<div class="fg"><label class="fl">Device Name</label><input class="fi" id="dname" placeholder="e.g. iPhone 15 Face ID"></div>
<label class="fl">Type</label>
<div class="dg"><div class="dc sel" id="cp" onclick="sel('platform')"><div class="di">📱</div><div class="dn">Biometric</div><div class="dd">Face ID, Touch ID</div></div>
<div class="dc" id="ck" onclick="sel('security_key')"><div class="di">🔑</div><div class="dn">Security Key</div><div class="dd">Nitrokey, YubiKey</div></div></div>
<button class="btn" id="rbtn" onclick="reg()">Register Device</button><div id="st"></div>
<div class="devs"><label class="fl">Registered Devices</label><div id="dl"><p style="color:#888;font-size:.85rem;text-align:center">Loading...</p></div></div>
<a href="/" class="back">&larr; Back to Approvals</a>
<script>let stype='platform';
function sel(t){stype=t;document.getElementById('cp').classList.toggle('sel',t==='platform');document.getElementById('ck').classList.toggle('sel',t==='security_key')}
const sv=localStorage.getItem('aiohai_username');if(sv)document.getElementById('uname').value=sv;
function b64d(s){s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';return Uint8Array.from(atob(s),c=>c.charCodeAt(0))}
function b64e(b){return btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')}
function decCO(o){const p=o.publicKey||o;if(p.challenge)p.challenge=b64d(p.challenge);if(p.user&&p.user.id)p.user.id=b64d(p.user.id);
if(p.excludeCredentials)p.excludeCredentials=p.excludeCredentials.map(c=>({...c,id:b64d(c.id)}));return p}
function encAR(c){return{id:c.id,rawId:b64e(c.rawId),type:c.type,response:{attestationObject:b64e(c.response.attestationObject),clientDataJSON:b64e(c.response.clientDataJSON)}}}
async function reg(){const u=document.getElementById('uname').value.trim();const d=document.getElementById('dname').value.trim();const st=document.getElementById('st');const btn=document.getElementById('rbtn');
if(!u){st.textContent='Username required';st.className='err';return}if(!d){st.textContent='Device name required';st.className='err';return}
localStorage.setItem('aiohai_username',u);btn.disabled=true;st.textContent='Starting...';st.className='';
try{const br=await fetch('/auth/register/begin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,device_name:d,authenticator_type:stype,role:'admin'})});
if(!br.ok)throw new Error((await br.json()).error);const opts=await br.json();st.textContent='Touch key or verify biometrics...';
const cred=await navigator.credentials.create({publicKey:decCO(opts)});
const cr=await fetch('/auth/register/complete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session_id:opts.session_id,credential:encAR(cred)})});
const res=await cr.json();if(cr.ok){st.textContent='✓ '+res.message;st.className='ok';loadDevs()}else throw new Error(res.error)}
catch(e){st.textContent='Error: '+e.message;st.className='err'}finally{btn.disabled=false}}
async function loadDevs(){try{const r=await fetch('/api/users');const d=await r.json();const l=document.getElementById('dl');
let h='';for(const[n,i]of Object.entries(d))for(const dv of i.devices)h+=`<div class="di-item"><div class="di-info"><div class="di-t">${dv.name}</div><div class="di-m">${n} · ${i.role} · ${dv.type}</div></div></div>`;
l.innerHTML=h||'<p style="color:#888;font-size:.85rem;text-align:center">No devices registered</p>'}catch(e){}}
loadDevs();
</script></body></html>"""

    _ERROR_HTML = r"""<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Error</title>
<style>body{font-family:system-ui;background:#0a0a0f;color:#e8e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.e{text-align:center}.e .i{font-size:3rem;margin-bottom:1rem}.e h1{font-size:1.2rem;margin-bottom:.5rem}.e p{color:#888;font-size:.9rem}
.e a{color:#4af;text-decoration:none;display:block;margin-top:1.5rem}</style></head>
<body><div class="e"><div class="i">⚠️</div><h1>{{ message }}</h1><p>The request may have expired or been processed.</p><a href="/">&larr; Back</a></div></body></html>"""


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
