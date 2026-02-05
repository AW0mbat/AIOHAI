#!/usr/bin/env python3
"""
AIOHAI Integrations — Home Assistant Notification Bridge
=========================================================
Bridge between Home Assistant automations and the AIOHAI user interface.

Runs a lightweight HTTP server on localhost that receives webhook
notifications from HA automations and routes them to the AIOHAI
AlertManager for desktop notification display.

Also provides a snapshot proxy endpoint that securely fetches
camera snapshots from Frigate NVR without exposing Frigate directly.

Previously defined in security/security_components.py.
Extracted as Phase 4a of the monolith → layered architecture migration.

Import from: aiohai.integrations.smart_home.notification
"""

import re
import json
import logging
import threading
import http.server
import urllib.request
import urllib.error
from datetime import datetime
from typing import Dict, List

from aiohai.core.types import AlertSeverity


class HomeAssistantNotificationBridge:
    """Bridge between Home Assistant automations and the AIOHAI user interface.

    Runs a lightweight HTTP server on localhost that receives webhook
    notifications from HA automations and routes them to the AIOHAI
    AlertManager for desktop notification display.

    Also provides a snapshot proxy endpoint that securely fetches
    camera snapshots from Frigate NVR without exposing Frigate directly.
    """

    def __init__(self, alert_manager=None, port: int = 11436,
                 frigate_host: str = '127.0.0.1', frigate_port: int = 5000):
        self.alert_manager = alert_manager
        self.port = port
        self.frigate_host = frigate_host
        self.frigate_port = frigate_port
        self.notification_log: List[Dict] = []
        self.max_log_size = 500
        self._server = None
        self._thread = None
        self.logger = logging.getLogger('aiohai.notification_bridge')

    def start(self):
        """Start the notification bridge HTTP server."""
        bridge = self

        class BridgeHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                bridge.logger.debug(f"Bridge HTTP: {format % args}")

            def do_POST(self):
                if self.path == '/webhook/notify':
                    self._handle_notification()
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_GET(self):
                if self.path.startswith('/snapshot/'):
                    self._handle_snapshot()
                elif self.path == '/notifications':
                    self._handle_list_notifications()
                elif self.path == '/health':
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'status': 'ok'}).encode())
                else:
                    self.send_response(404)
                    self.end_headers()

            def _handle_notification(self):
                try:
                    content_length = int(self.headers.get('Content-Length', 0))
                    if content_length > 65536:  # 64KB max
                        self.send_response(413)
                        self.end_headers()
                        return

                    body = self.rfile.read(content_length)
                    data = json.loads(body.decode('utf-8'))

                    # Validate required fields
                    title = str(data.get('title', 'Home Assistant'))[:200]
                    message = str(data.get('message', ''))[:1000]
                    severity = str(data.get('severity', 'info')).lower()
                    source = str(data.get('source', 'homeassistant'))[:100]
                    camera = str(data.get('camera', ''))[:50]

                    # Log the notification
                    entry = {
                        'timestamp': datetime.now().isoformat(),
                        'title': title,
                        'message': message,
                        'severity': severity,
                        'source': source,
                        'camera': camera,
                    }
                    bridge.notification_log.append(entry)
                    if len(bridge.notification_log) > bridge.max_log_size:
                        bridge.notification_log = bridge.notification_log[-bridge.max_log_size:]

                    # Route to AlertManager if available
                    if bridge.alert_manager:
                        try:
                            sev_map = {
                                'info': AlertSeverity.INFO,
                                'warning': AlertSeverity.WARNING,
                                'high': AlertSeverity.HIGH,
                                'critical': AlertSeverity.CRITICAL,
                            }
                            alert_sev = sev_map.get(severity, AlertSeverity.INFO)
                            bridge.alert_manager.alert(
                                alert_sev, f"HA_{source.upper()}",
                                f"{title}: {message}",
                                {'camera': camera} if camera else {}
                            )
                        except Exception as e:
                            bridge.logger.warning(f"Alert routing failed: {e}")

                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'status': 'received'}).encode())

                except json.JSONDecodeError:
                    self.send_response(400)
                    self.end_headers()
                except Exception as e:
                    bridge.logger.error(f"Notification handling error: {e}")
                    self.send_response(500)
                    self.end_headers()

            def _handle_snapshot(self):
                """Proxy a camera snapshot from Frigate."""
                camera_name = self.path.split('/snapshot/', 1)[-1].strip('/')

                # Sanitize camera name - alphanumeric, underscore, hyphen only
                if not re.match(r'^[a-zA-Z0-9_-]+$', camera_name):
                    self.send_response(400)
                    self.end_headers()
                    return

                try:
                    frigate_url = (f"http://{bridge.frigate_host}:{bridge.frigate_port}"
                                   f"/api/{camera_name}/latest.jpg")

                    req = urllib.request.Request(frigate_url)
                    req.add_header('Host', f'{bridge.frigate_host}:{bridge.frigate_port}')

                    with urllib.request.urlopen(req, timeout=5) as resp:
                        data = resp.read(5 * 1024 * 1024)  # 5MB max
                        content_type = resp.headers.get('Content-Type', 'image/jpeg')

                    self.send_response(200)
                    self.send_header('Content-Type', content_type)
                    self.send_header('Content-Length', str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)

                except urllib.error.HTTPError as e:
                    self.send_response(e.code)
                    self.end_headers()
                except Exception as e:
                    bridge.logger.error(f"Snapshot proxy error: {e}")
                    self.send_response(502)
                    self.end_headers()

            def _handle_list_notifications(self):
                """Return recent notifications as JSON."""
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(bridge.notification_log[-50:]).encode())

        # Validate localhost-only binding
        listen_host = '127.0.0.1'

        try:
            self._server = http.server.HTTPServer((listen_host, self.port), BridgeHandler)
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                name='aiohai-notification-bridge',
                daemon=True
            )
            self._thread.start()
            self.logger.info(f"Notification bridge started on {listen_host}:{self.port}")
        except OSError as e:
            self.logger.error(f"Failed to start notification bridge: {e}")

    def stop(self):
        """Stop the notification bridge."""
        if self._server:
            self._server.shutdown()
            self._server.server_close()  # Close the socket properly
            self._server = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None


__all__ = ['HomeAssistantNotificationBridge']
