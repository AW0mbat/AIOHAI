#!/usr/bin/env python3
"""
Proxy Admin API — REST API for companion app admin actions.

Provides HTTP endpoints for the companion app to manage:
- Security level configuration (read/write with gate constraints)
- Change request log (view/apply with NFC gating)
- Session status (active sessions, history)
- Proxy lifecycle (health, restart signals)
- Backup and restore

All endpoints enforce:
- API secret authentication (same mechanism as FIDO2 server)
- DENY gate immutability (no endpoint can change DENY items)
- Admin role requirement for write operations

Phase 4 of Approval Gate Taxonomy v3 implementation.

Import from: aiohai.proxy.admin_api
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Optional
from urllib.parse import urlparse, parse_qs

__all__ = ['AdminAPIServer']

logger = logging.getLogger("aiohai.proxy.admin_api")


class AdminAPIServer:
    """REST API server for companion app administration.

    Runs on a separate port from the main proxy. Authenticates
    requests using a shared API secret (generated at startup,
    communicated to the companion app via secure channel).

    Usage:
        api = AdminAPIServer(
            config_manager=config_mgr,
            session_manager=session_mgr,
            change_request_log=change_log,
            matrix_adjuster=adjuster,
        )
        api.start(port=11437)  # Non-blocking, starts in background thread
        api.stop()
    """

    def __init__(self, *,
                 config_manager=None,
                 session_manager=None,
                 change_request_log=None,
                 matrix_adjuster=None,
                 fido2_server=None,
                 port: int = 11437,
                 bind_address: str = '127.0.0.1'):
        """Initialize the admin API server.

        Args:
            config_manager: ConfigManager instance for config CRUD.
            session_manager: SessionManager for session status queries.
            change_request_log: ChangeRequestLog for change request management.
            matrix_adjuster: TrustMatrixAdjuster for direct adjustment queries.
            fido2_server: FIDO2ApprovalServer for NFC-gated operations.
            port: Port to listen on (default 11437).
            bind_address: Address to bind to (default 127.0.0.1 — localhost only).
        """
        self._config_manager = config_manager
        self._session_manager = session_manager
        self._change_request_log = change_request_log
        self._matrix_adjuster = matrix_adjuster
        self._fido2_server = fido2_server
        self._port = port
        self._bind_address = bind_address

        # Generate API secret for this session
        self._api_secret = secrets.token_hex(32)
        self._server = None
        self._thread = None
        self._shutdown_requested = False

    @property
    def api_secret(self) -> str:
        """Get the API secret (for companion app handshake)."""
        return self._api_secret

    @property
    def port(self) -> int:
        return self._port

    def start(self) -> bool:
        """Start the admin API server in a background thread."""
        try:
            handler_class = self._create_handler_class()
            self._server = HTTPServer(
                (self._bind_address, self._port), handler_class
            )
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                name="aiohai-admin-api",
                daemon=True,
            )
            self._thread.start()
            logger.info(
                "Admin API started on %s:%d",
                self._bind_address, self._port,
            )
            return True
        except OSError as e:
            logger.error("Cannot start admin API: %s", e)
            return False

    def stop(self):
        """Stop the admin API server."""
        self._shutdown_requested = True
        if self._server:
            self._server.shutdown()
            logger.info("Admin API stopped")

    def _create_handler_class(self):
        """Create the request handler class with closure over server state."""
        api_server = self

        class AdminHandler(BaseHTTPRequestHandler):
            """HTTP handler for admin API requests."""

            def log_message(self, format, *args):
                pass  # Suppress default logging

            def _verify_auth(self) -> bool:
                """Verify API secret header."""
                provided = self.headers.get('X-Admin-Secret', '')
                return hmac.compare_digest(provided, api_server._api_secret)

            def _send_json(self, data: Dict, status: int = 200):
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(
                    json.dumps(data, default=str).encode('utf-8')
                )

            def _read_body(self) -> Optional[Dict]:
                content_length = int(self.headers.get('Content-Length', 0))
                if content_length > 1_000_000:  # 1MB max for admin API
                    self._send_json({'error': 'Request too large'}, 413)
                    return None
                if content_length == 0:
                    return {}
                try:
                    body = self.rfile.read(content_length)
                    return json.loads(body)
                except (json.JSONDecodeError, OSError) as e:
                    self._send_json({'error': f'Invalid JSON: {e}'}, 400)
                    return None

            def do_OPTIONS(self):
                """CORS preflight."""
                self.send_response(204)
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-Admin-Secret')
                self.end_headers()

            def do_GET(self):
                if not self._verify_auth():
                    self._send_json({'error': 'Unauthorized'}, 401)
                    return
                self._route_get()

            def do_POST(self):
                if not self._verify_auth():
                    self._send_json({'error': 'Unauthorized'}, 401)
                    return
                self._route_post()

            def do_DELETE(self):
                if not self._verify_auth():
                    self._send_json({'error': 'Unauthorized'}, 401)
                    return
                self._route_delete()

            # ---- GET routes ----

            def _route_get(self):
                path = urlparse(self.path).path

                if path == '/api/admin/health':
                    self._send_json({
                        'status': 'ok',
                        'timestamp': datetime.now().isoformat(),
                    })

                elif path == '/api/admin/config':
                    if api_server._config_manager:
                        self._send_json(
                            api_server._config_manager.get_config_snapshot()
                        )
                    else:
                        self._send_json({'error': 'Config manager not available'}, 503)

                elif path == '/api/admin/gates':
                    if api_server._config_manager:
                        self._send_json(
                            api_server._config_manager.get_gate_editor_data()
                        )
                    else:
                        self._send_json({'error': 'Config manager not available'}, 503)

                elif path == '/api/admin/overrides':
                    if api_server._matrix_adjuster:
                        self._send_json({
                            'overrides': api_server._matrix_adjuster.get_all_overrides(),
                            'has_overrides': api_server._matrix_adjuster.has_overrides(),
                        })
                    else:
                        self._send_json({'error': 'Adjuster not available'}, 503)

                elif path == '/api/admin/change-requests':
                    if api_server._change_request_log:
                        self._send_json({
                            'pending': api_server._change_request_log.get_pending(),
                            'applied': api_server._change_request_log.get_applied(),
                            'total': api_server._change_request_log.total_count,
                        })
                    else:
                        self._send_json({'error': 'Change request log not available'}, 503)

                elif path == '/api/admin/sessions':
                    if api_server._session_manager:
                        active = api_server._session_manager.get_active_sessions()
                        self._send_json({
                            'active': [s.to_dict() for s in active],
                            'count': len(active),
                        })
                    else:
                        self._send_json({'active': [], 'count': 0})

                elif path == '/api/admin/backups':
                    if api_server._config_manager:
                        self._send_json({
                            'backups': api_server._config_manager.list_backups(),
                        })
                    else:
                        self._send_json({'error': 'Config manager not available'}, 503)

                else:
                    self._send_json({'error': 'Not found'}, 404)

            # ---- POST routes ----

            def _route_post(self):
                path = urlparse(self.path).path

                if path == '/api/admin/config/apply':
                    self._handle_apply_changes()

                elif path == '/api/admin/config/reset':
                    self._handle_reset()

                elif path == '/api/admin/backups/create':
                    self._handle_create_backup()

                elif path == '/api/admin/backups/restore':
                    self._handle_restore_backup()

                elif path == '/api/admin/change-requests/apply':
                    self._handle_apply_change_requests()

                elif path == '/api/admin/change-requests/reject':
                    self._handle_reject_change_request()

                elif path == '/api/admin/sessions/end':
                    self._handle_end_session()

                else:
                    self._send_json({'error': 'Not found'}, 404)

            # ---- DELETE routes ----

            def _route_delete(self):
                path = urlparse(self.path).path

                if path.startswith('/api/admin/overrides/'):
                    key = path.split('/')[-1]
                    self._handle_remove_override(key)
                else:
                    self._send_json({'error': 'Not found'}, 404)

            # ---- POST handlers ----

            def _handle_apply_changes(self):
                """Apply batch config changes from the admin UI."""
                if not api_server._config_manager:
                    self._send_json({'error': 'Config manager not available'}, 503)
                    return

                body = self._read_body()
                if body is None:
                    return

                result = api_server._config_manager.apply_admin_changes(
                    body, admin_user='admin'
                )
                status = 200 if result.get('success') else 400
                self._send_json(result, status)

            def _handle_reset(self):
                """Reset all overrides to defaults."""
                if not api_server._config_manager:
                    self._send_json({'error': 'Config manager not available'}, 503)
                    return

                result = api_server._config_manager.reset_all_overrides()
                self._send_json(result)

            def _handle_create_backup(self):
                """Create a configuration backup."""
                if not api_server._config_manager:
                    self._send_json({'error': 'Config manager not available'}, 503)
                    return

                body = self._read_body()
                if body is None:
                    return

                path = api_server._config_manager.create_backup(
                    reason=body.get('reason', '')
                )
                if path:
                    self._send_json({'success': True, 'path': path})
                else:
                    self._send_json({'success': False, 'error': 'Backup failed'}, 500)

            def _handle_restore_backup(self):
                """Restore from a backup."""
                if not api_server._config_manager:
                    self._send_json({'error': 'Config manager not available'}, 503)
                    return

                body = self._read_body()
                if body is None:
                    return

                backup_path = body.get('path', '')
                if not backup_path:
                    self._send_json({'error': 'Missing backup path'}, 400)
                    return

                result = api_server._config_manager.restore_from_backup(
                    backup_path, admin_user='admin'
                )
                status = 200 if result.get('success') else 400
                self._send_json(result, status)

            def _handle_apply_change_requests(self):
                """Apply selected change requests (code diff + NFC gate).

                DENY gate requests are always rejected here.
                Non-DENY requests generate a code diff for admin review.
                """
                if not api_server._config_manager:
                    self._send_json({'error': 'Config manager not available'}, 503)
                    return

                body = self._read_body()
                if body is None:
                    return

                request_ids = body.get('request_ids', [])
                nfc_verified = body.get('nfc_verified', False)

                if not request_ids:
                    self._send_json({'error': 'No request IDs provided'}, 400)
                    return

                # Generate code diff
                diff_result = api_server._config_manager.generate_code_diff(
                    request_ids
                )

                if not nfc_verified and diff_result['diffs']:
                    # Return the diff for review without applying
                    self._send_json({
                        'status': 'review_required',
                        'message': 'Review the changes below, then re-submit with nfc_verified=true',
                        'diffs': diff_result['diffs'],
                        'denied': diff_result['denied'],
                        'not_found': diff_result['not_found'],
                    })
                    return

                # NFC verified — mark requests as applied
                applied = []
                errors = []
                if api_server._change_request_log:
                    for diff in diff_result['diffs']:
                        ok, msg = api_server._change_request_log.mark_applied(
                            diff['request_id'],
                            applied_by='admin',
                            code_diff=diff['code_line'],
                            nfc_verification=nfc_verified,
                        )
                        if ok:
                            applied.append(diff['request_id'])
                        else:
                            errors.append({
                                'request_id': diff['request_id'],
                                'error': msg,
                            })
                    api_server._change_request_log.save()

                self._send_json({
                    'status': 'applied',
                    'applied': applied,
                    'denied': diff_result['denied'],
                    'not_found': diff_result['not_found'],
                    'errors': errors,
                    'nfc_verified': nfc_verified,
                    'requires_restart': len(applied) > 0,
                })

            def _handle_reject_change_request(self):
                """Reject a change request (admin decided not to apply)."""
                if not api_server._change_request_log:
                    self._send_json({'error': 'Change request log not available'}, 503)
                    return

                body = self._read_body()
                if body is None:
                    return

                request_id = body.get('request_id', '')
                reason = body.get('reason', '')

                if not request_id:
                    self._send_json({'error': 'Missing request_id'}, 400)
                    return

                ok, msg = api_server._change_request_log.mark_rejected(
                    request_id, rejected_by='admin', reason=reason
                )
                api_server._change_request_log.save()

                self._send_json({
                    'success': ok,
                    'message': msg,
                })

            def _handle_end_session(self):
                """End an active elevation session."""
                if not api_server._session_manager:
                    self._send_json({'error': 'Session manager not available'}, 503)
                    return

                body = self._read_body()
                if body is None:
                    return

                session_id = body.get('session_id', '')
                if not session_id:
                    self._send_json({'error': 'Missing session_id'}, 400)
                    return

                ended = api_server._session_manager.end_session(
                    session_id, reason='admin_terminated'
                )
                self._send_json({
                    'success': ended,
                    'session_id': session_id,
                })

            def _handle_remove_override(self, key: str):
                """Remove a specific override."""
                if not api_server._matrix_adjuster:
                    self._send_json({'error': 'Adjuster not available'}, 503)
                    return

                parts = key.split(':', 1)
                if len(parts) != 2:
                    self._send_json({'error': 'Invalid key format'}, 400)
                    return

                try:
                    from aiohai.core.types import ActionCategory, TargetDomain
                    cat = ActionCategory(parts[0])
                    dom = TargetDomain(parts[1])
                    removed = api_server._matrix_adjuster.remove_adjustment(cat, dom)

                    if removed and api_server._matrix_adjuster:
                        api_server._matrix_adjuster.save_to_file()

                    self._send_json({
                        'success': removed,
                        'key': key,
                    })
                except ValueError as e:
                    self._send_json({'error': str(e)}, 400)

        return AdminHandler
