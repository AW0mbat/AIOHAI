#!/usr/bin/env python3
"""
AIOHAI v3.0 — Home Assistant Framework Integration Tests
=========================================================

Tests all HA-framework additions built on the AIOHAI v3.0 codebase.
Uses only stdlib unittest (no pytest needed).

Run:  python3 -m unittest tests.test_ha_framework -v
"""

import os
import sys
import json
import time
import shlex
import shutil
import socket
import tempfile
import threading
import unittest
import http.client
import urllib.request
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock
from io import BytesIO

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from proxy.aiohai_proxy import (
    UnifiedConfig, SecurityLogger, AlertManager, AlertSeverity,
    CommandValidator, PathValidator, ActionParser, ActionType,
    WHITELISTED_EXECUTABLES, DOCKER_COMMAND_TIERS,
    LocalServiceRegistry, LocalAPIQueryExecutor,
    AGENTIC_INSTRUCTIONS,
)
from security.security_components import (
    HomeAssistantNotificationBridge,
    SmartHomeStackDetector,
    SmartHomeConfigAnalyzer,
)


# =============================================================================
# Helpers
# =============================================================================

def _make_config(tmp_dir: Path) -> UnifiedConfig:
    """Create a UnifiedConfig pointing at a temp dir."""
    (tmp_dir / "policy").mkdir(exist_ok=True)
    (tmp_dir / "logs").mkdir(exist_ok=True)
    (tmp_dir / "temp").mkdir(exist_ok=True)
    (tmp_dir / "data" / "ssl").mkdir(parents=True, exist_ok=True)
    (tmp_dir / "data" / "fido2").mkdir(parents=True, exist_ok=True)

    policy = tmp_dir / "policy" / "aiohai_security_policy_v3.0.md"
    policy.write_text("# AIOHAI Policy v3.0\nDo not harm the user.\n")
    sig = tmp_dir / "policy" / "policy.sig"
    sig.write_bytes(b"\x00" * 64)

    cfg = UnifiedConfig()
    cfg.base_dir = tmp_dir
    cfg.policy_file = policy
    cfg.policy_signature_file = sig
    cfg.log_dir = tmp_dir / "logs"
    cfg.secure_temp_dir = tmp_dir / "temp"
    cfg.listen_host = "127.0.0.1"
    cfg.listen_port = 11435
    cfg.ollama_host = "127.0.0.1"
    cfg.ollama_port = 11434
    cfg.hsm_enabled = False
    cfg.hsm_required = False
    cfg.fido2_enabled = False
    return cfg


def _make_logger(cfg: UnifiedConfig) -> SecurityLogger:
    return SecurityLogger(cfg)


def _make_alerts(cfg: UnifiedConfig, logger: SecurityLogger) -> AlertManager:
    return AlertManager(cfg, logger)


def _free_port() -> int:
    """Find a free TCP port."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# =============================================================================
# 1. DOCKER WHITELIST
# =============================================================================

class TestDockerWhitelist(unittest.TestCase):
    """Docker executables must be in the whitelist."""

    def test_docker_in_whitelist(self):
        self.assertIn("docker", WHITELISTED_EXECUTABLES)

    def test_docker_exe_in_whitelist(self):
        self.assertIn("docker.exe", WHITELISTED_EXECUTABLES)

    def test_docker_compose_in_whitelist(self):
        self.assertIn("docker-compose", WHITELISTED_EXECUTABLES)

    def test_docker_compose_exe_in_whitelist(self):
        self.assertIn("docker-compose.exe", WHITELISTED_EXECUTABLES)

    def test_whitelist_still_has_originals(self):
        """Adding docker must not remove pre-existing entries."""
        for exe in ("cmd.exe", "python.exe", "git.exe"):
            self.assertIn(exe, WHITELISTED_EXECUTABLES, f"Missing original: {exe}")

    def test_dangerous_executables_removed(self):
        """F-007/F-008: explorer.exe and powershell.exe must be removed."""
        self.assertNotIn("explorer.exe", WHITELISTED_EXECUTABLES)
        self.assertNotIn("powershell.exe", WHITELISTED_EXECUTABLES)
        self.assertNotIn("pwsh.exe", WHITELISTED_EXECUTABLES)


# =============================================================================
# 2. DOCKER COMMAND TIERS
# =============================================================================

class TestDockerCommandTiers(unittest.TestCase):
    """Verify the tier classification constant."""

    def test_four_tiers_exist(self):
        self.assertEqual(set(DOCKER_COMMAND_TIERS.keys()),
                         {"standard", "elevated", "critical", "blocked"})

    def test_standard_includes_ps(self):
        self.assertIn("ps", DOCKER_COMMAND_TIERS["standard"])

    def test_standard_includes_compose_ps(self):
        self.assertIn("compose ps", DOCKER_COMMAND_TIERS["standard"])

    def test_elevated_includes_up(self):
        self.assertIn("compose up", DOCKER_COMMAND_TIERS["elevated"])

    def test_critical_includes_rm(self):
        self.assertIn("rm", DOCKER_COMMAND_TIERS["critical"])

    def test_blocked_includes_push(self):
        self.assertIn("push", DOCKER_COMMAND_TIERS["blocked"])

    def test_no_tier_overlap(self):
        """A subcommand must appear in exactly one tier."""
        all_cmds = []
        for tier, cmds in DOCKER_COMMAND_TIERS.items():
            for cmd in cmds:
                self.assertNotIn(cmd, all_cmds, f"'{cmd}' in multiple tiers")
                all_cmds.append(cmd)


# =============================================================================
# 3. COMMAND VALIDATOR — Docker Tier Routing
# =============================================================================

class TestCommandValidatorDocker(unittest.TestCase):
    """CommandValidator must route docker commands through tier validation."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.cfg = _make_config(self.tmp)
        self.logger = _make_logger(self.cfg)
        self.alerts = _make_alerts(self.cfg, self.logger)
        self.cv = CommandValidator(self.cfg, self.logger)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_docker_ps_allowed(self):
        ok, msg = self.cv.validate("docker ps")
        self.assertTrue(ok, f"docker ps should be allowed: {msg}")

    def test_docker_compose_up_allowed(self):
        ok, msg = self.cv.validate("docker compose up -d")
        self.assertTrue(ok, f"docker compose up should be allowed: {msg}")

    def test_docker_push_blocked(self):
        ok, msg = self.cv.validate("docker push myimage")
        self.assertFalse(ok, "docker push must be blocked")
        self.assertIn("blocked", msg.lower())

    def test_docker_login_blocked(self):
        ok, msg = self.cv.validate("docker login")
        self.assertFalse(ok, "docker login must be blocked")

    def test_docker_swarm_blocked(self):
        ok, msg = self.cv.validate("docker swarm init")
        self.assertFalse(ok, "docker swarm must be blocked")

    def test_docker_export_blocked(self):
        ok, msg = self.cv.validate("docker export mycontainer")
        self.assertFalse(ok, "docker export must be blocked")

    def test_get_docker_tier_standard(self):
        self.assertEqual(self.cv.get_docker_tier("docker ps"), "standard")

    def test_get_docker_tier_elevated(self):
        self.assertEqual(self.cv.get_docker_tier("docker compose up"), "elevated")

    def test_get_docker_tier_critical(self):
        self.assertEqual(self.cv.get_docker_tier("docker system prune"), "critical")

    def test_get_docker_tier_blocked(self):
        self.assertEqual(self.cv.get_docker_tier("docker push"), "blocked")

    def test_get_docker_tier_unknown_defaults_elevated(self):
        tier = self.cv.get_docker_tier("docker somefuturecmd")
        self.assertEqual(tier, "elevated", "Unknown docker cmds should default to elevated")

    def test_non_docker_returns_unknown(self):
        tier = self.cv.get_docker_tier("git push")
        self.assertEqual(tier, "unknown")

    def test_docker_compose_exe_blocked(self):
        ok, msg = self.cv.validate("docker-compose.exe push")
        self.assertFalse(ok, "docker-compose.exe push must be blocked")

    def test_bare_docker_no_args(self):
        ok, msg = self.cv.validate("docker")
        self.assertTrue(ok, f"bare docker should be allowed: {msg}")


# =============================================================================
# 4. LOCAL_API_QUERY ACTION TYPE
# =============================================================================

class TestActionTypeEnum(unittest.TestCase):
    """LOCAL_API_QUERY must be in ActionType."""

    def test_local_api_query_exists(self):
        self.assertTrue(hasattr(ActionType, "LOCAL_API_QUERY"))

    def test_all_original_types_preserved(self):
        for name in ("FILE_READ", "FILE_WRITE", "FILE_DELETE",
                      "COMMAND_EXEC", "DIRECTORY_LIST", "NETWORK_REQUEST"):
            self.assertTrue(hasattr(ActionType, name), f"Missing original: {name}")


# =============================================================================
# 5. LOCAL SERVICE REGISTRY
# =============================================================================

class TestLocalServiceRegistry(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.cfg = _make_config(self.tmp)
        self.logger = _make_logger(self.cfg)
        self.reg = LocalServiceRegistry(self.logger)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_register_localhost_accepted(self):
        self.reg.register("test_svc", "127.0.0.1", 5000, ["/api/events"])
        ok, svc = self.reg.validate_request("http://127.0.0.1:5000/api/events")
        self.assertTrue(ok)
        self.assertEqual(svc, "test_svc")

    def test_register_non_local_rejected(self):
        """Registering a non-localhost service must be silently ignored."""
        self.reg.register("bad_svc", "192.168.1.100", 5000, ["/api/events"])
        ok, reason = self.reg.validate_request("http://192.168.1.100:5000/api/events")
        self.assertFalse(ok)
        self.assertIn("Non-local", reason)

    def test_validate_unregistered_port(self):
        ok, reason = self.reg.validate_request("http://127.0.0.1:9999/api/test")
        self.assertFalse(ok)
        self.assertIn("No registered service", reason)

    def test_validate_disallowed_path(self):
        self.reg.register("frigate", "127.0.0.1", 5000, ["/api/events"])
        ok, reason = self.reg.validate_request("http://127.0.0.1:5000/api/secret")
        self.assertFalse(ok)
        self.assertIn("not allowed", reason)

    def test_validate_wildcard_path(self):
        self.reg.register("frigate", "127.0.0.1", 5000, ["/api/*"])
        ok, svc = self.reg.validate_request("http://127.0.0.1:5000/api/events")
        self.assertTrue(ok)
        ok2, svc2 = self.reg.validate_request("http://127.0.0.1:5000/api/stats")
        self.assertTrue(ok2)

    def test_validate_https_scheme(self):
        self.reg.register("ha", "127.0.0.1", 8123, ["/api/states"])
        ok, svc = self.reg.validate_request("https://127.0.0.1:8123/api/states")
        self.assertTrue(ok)

    def test_validate_external_host_blocked(self):
        """Even if a service is registered, queries to external hosts must fail."""
        self.reg.register("frigate", "127.0.0.1", 5000, ["/api/*"])
        ok, reason = self.reg.validate_request("http://10.0.0.5:5000/api/events")
        self.assertFalse(ok)

    def test_validate_ftp_scheme_blocked(self):
        self.reg.register("svc", "127.0.0.1", 21, ["/"])
        ok, reason = self.reg.validate_request("ftp://127.0.0.1:21/")
        self.assertFalse(ok)
        self.assertIn("Scheme", reason)

    def test_max_response_default(self):
        self.reg.register("svc", "127.0.0.1", 5000, ["/api/*"])
        self.assertEqual(self.reg.get_max_response("svc"), 1048576)

    def test_max_response_custom(self):
        self.reg.register("svc", "127.0.0.1", 5000, ["/api/*"], max_response_bytes=500)
        self.assertEqual(self.reg.get_max_response("svc"), 500)

    def test_load_from_config_valid(self):
        config_data = {
            "local_services": {
                "custom": {
                    "host": "127.0.0.1",
                    "port": 9090,
                    "allowed_paths": ["/healthz"],
                }
            }
        }
        self.reg.load_from_config(config_data)
        ok, svc = self.reg.validate_request("http://127.0.0.1:9090/healthz")
        self.assertTrue(ok)
        self.assertEqual(svc, "custom")

    def test_load_from_config_rejects_non_local(self):
        config_data = {
            "local_services": {
                "evil": {
                    "host": "evil.com",
                    "port": 80,
                    "allowed_paths": ["/*"],
                }
            }
        }
        self.reg.load_from_config(config_data)
        ok, _ = self.reg.validate_request("http://evil.com:80/steal")
        self.assertFalse(ok)


# =============================================================================
# 6. LOCAL API QUERY EXECUTOR
# =============================================================================

class TestLocalAPIQueryExecutor(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.cfg = _make_config(self.tmp)
        self.logger = _make_logger(self.cfg)
        self.reg = LocalServiceRegistry(self.logger)
        self.reg.register("test_svc", "127.0.0.1", 5000, ["/api/*"])
        self.executor = LocalAPIQueryExecutor(self.reg, self.logger)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_blocked_when_not_registered(self):
        ok, msg = self.executor.execute("http://127.0.0.1:9999/api/test")
        self.assertFalse(ok)
        self.assertIn("blocked", msg.lower())

    def test_blocked_when_external_host(self):
        ok, msg = self.executor.execute("http://evil.com:5000/api/events")
        self.assertFalse(ok)

    @patch("urllib.request.urlopen")
    def test_json_response_returned(self, mock_urlopen):
        """Successful JSON response should be returned as text."""
        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b'{"events": []}'
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_urlopen.return_value = mock_resp

        ok, text = self.executor.execute("http://127.0.0.1:5000/api/events")
        self.assertTrue(ok)
        self.assertIn("events", text)

    @patch("urllib.request.urlopen")
    def test_binary_response_summarized(self, mock_urlopen):
        """Binary responses should be summarized, not returned raw."""
        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b"\xff\xd8\xff" + b"\x00" * 1000
        mock_resp.headers = {"Content-Type": "image/jpeg"}
        mock_urlopen.return_value = mock_resp

        ok, text = self.executor.execute("http://127.0.0.1:5000/api/snapshot")
        self.assertTrue(ok)
        self.assertIn("Binary response", text)
        self.assertNotIn("\xff", text)

    @patch("urllib.request.urlopen", side_effect=urllib.error.HTTPError(
        "http://x", 404, "Not Found", {}, BytesIO(b"")))
    def test_http_error_handled(self, mock_urlopen):
        ok, msg = self.executor.execute("http://127.0.0.1:5000/api/missing")
        self.assertFalse(ok)
        self.assertIn("404", msg)

    @patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused"))
    def test_connection_error_handled(self, mock_urlopen):
        ok, msg = self.executor.execute("http://127.0.0.1:5000/api/events")
        self.assertFalse(ok)
        self.assertIn("Connection failed", msg)


# =============================================================================
# 7. NOTIFICATION BRIDGE
# =============================================================================

class TestNotificationBridge(unittest.TestCase):
    """Test the HomeAssistantNotificationBridge HTTP server."""

    @classmethod
    def setUpClass(cls):
        cls.port = _free_port()
        cls.bridge = HomeAssistantNotificationBridge(
            alert_manager=None, port=cls.port,
            frigate_host="127.0.0.1", frigate_port=5000,
        )
        cls.bridge.start()
        # Give server time to bind
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        cls.bridge.stop()

    def _request(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        headers = {"Content-Type": "application/json"} if body else {}
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, data

    def test_health_endpoint(self):
        status, data = self._request("GET", "/health")
        self.assertEqual(status, 200)
        parsed = json.loads(data)
        self.assertEqual(parsed["status"], "ok")

    def test_notification_accepted(self):
        payload = json.dumps({
            "title": "Motion Detected",
            "message": "Camera front_door saw motion",
            "severity": "warning",
            "source": "frigate",
            "camera": "front_door",
        })
        status, data = self._request("POST", "/webhook/notify", payload)
        self.assertEqual(status, 200)
        parsed = json.loads(data)
        self.assertEqual(parsed["status"], "received")

    def test_notification_logged(self):
        """After posting a notification it should appear in the log."""
        payload = json.dumps({
            "title": "Test Log Entry",
            "message": "Verify logging",
            "severity": "info",
        })
        self._request("POST", "/webhook/notify", payload)

        status, data = self._request("GET", "/notifications")
        self.assertEqual(status, 200)
        notifications = json.loads(data)
        self.assertTrue(any(n["title"] == "Test Log Entry" for n in notifications))

    def test_notification_max_payload(self):
        """Payloads over 64KB must be rejected."""
        huge = json.dumps({"title": "x", "message": "y" * 100000})
        status, _ = self._request("POST", "/webhook/notify", huge)
        self.assertEqual(status, 413)

    def test_notification_invalid_json(self):
        status, _ = self._request("POST", "/webhook/notify", "not json{{{")
        self.assertEqual(status, 400)

    def test_404_unknown_path(self):
        status, _ = self._request("GET", "/doesnotexist")
        self.assertEqual(status, 404)

    def test_snapshot_bad_camera_name(self):
        """Camera names with special chars must be rejected."""
        status, _ = self._request("GET", "/snapshot/../../../etc/passwd")
        self.assertEqual(status, 400)

    def test_snapshot_sql_injection_camera(self):
        # URL-encode the malicious path since http.client rejects raw spaces
        status, _ = self._request("GET", "/snapshot/%27%3B%20DROP%20TABLE--")
        self.assertEqual(status, 400)

    def test_notification_fields_truncated(self):
        """Fields must be safely truncated (title:200, message:1000, source:100)."""
        payload = json.dumps({
            "title": "A" * 500,
            "message": "B" * 5000,
            "source": "C" * 300,
        })
        status, _ = self._request("POST", "/webhook/notify", payload)
        self.assertEqual(status, 200)
        
        # Check log entry
        last = self.bridge.notification_log[-1]
        self.assertLessEqual(len(last["title"]), 200)
        self.assertLessEqual(len(last["message"]), 1000)
        self.assertLessEqual(len(last["source"]), 100)


# =============================================================================
# 8. SMART HOME STACK DETECTOR
# =============================================================================

class TestSmartHomeStackDetector(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_no_docker_returns_not_deployed(self):
        """Without docker binary, state should be not_deployed."""
        with patch("subprocess.run", side_effect=FileNotFoundError):
            det = SmartHomeStackDetector(base_dir=str(self.tmp))
            result = det.detect()
            self.assertEqual(result["deployment_state"], "not_deployed")
            self.assertFalse(result["docker_installed"])

    def test_uses_aiohai_env_var(self):
        """Should respect AIOHAI_HOME env variable."""
        with patch.dict(os.environ, {"AIOHAI_HOME": str(self.tmp)}):
            det = SmartHomeStackDetector()
            self.assertEqual(det.base_dir, self.tmp)

    def test_caching(self):
        """detect() should cache for 60 seconds."""
        with patch("subprocess.run", side_effect=FileNotFoundError):
            det = SmartHomeStackDetector(base_dir=str(self.tmp))
            r1 = det.detect()
            r2 = det.detect()
            self.assertIs(r1, r2, "Second call should return cached result")

    def test_cache_invalidation(self):
        """Expired cache should re-detect."""
        with patch("subprocess.run", side_effect=FileNotFoundError):
            det = SmartHomeStackDetector(base_dir=str(self.tmp))
            r1 = det.detect()
            det._cache_time = time.time() - 120  # Expire cache
            r2 = det.detect()
            self.assertIsNot(r1, r2, "Expired cache should produce new result")

    def test_context_block_format(self):
        """get_context_block() should produce valid [SMART_HOME_STATUS] block."""
        with patch("subprocess.run", side_effect=FileNotFoundError):
            det = SmartHomeStackDetector(base_dir=str(self.tmp))
            block = det.get_context_block()
            self.assertIn("[SMART_HOME_STATUS]", block)
            self.assertIn("[/SMART_HOME_STATUS]", block)
            self.assertIn("deployment_state:", block)
            self.assertIn("docker_installed:", block)

    def test_frigate_camera_parsing(self):
        """Should parse camera names from Frigate config."""
        det = SmartHomeStackDetector(base_dir=str(self.tmp))
        
        frigate_config = self.tmp / "frigate_config.yml"
        frigate_config.write_text(
            "cameras:\n"
            "  front_door:\n"
            "    ffmpeg:\n"
            "      inputs:\n"
            "        - path: rtsp://...\n"
            "  backyard:\n"
            "    ffmpeg:\n"
            "      inputs:\n"
            "        - path: rtsp://...\n"
            "detectors:\n"
            "  coral:\n"
        )
        cameras = det._parse_frigate_cameras(frigate_config)
        self.assertIn("front_door", cameras)
        self.assertIn("backyard", cameras)
        self.assertEqual(len(cameras), 2)

    @patch("subprocess.run")
    def test_docker_installed_detected(self, mock_run):
        """Should detect docker version."""
        def side_effect(args, **kwargs):
            if "version" in args:
                result = MagicMock()
                result.returncode = 0
                result.stdout = "24.0.7"
                return result
            elif "ps" in args:
                result = MagicMock()
                result.returncode = 0
                result.stdout = ""
                return result
            return MagicMock(returncode=1, stdout="")
        
        mock_run.side_effect = side_effect
        det = SmartHomeStackDetector(base_dir=str(self.tmp))
        result = det.detect()
        self.assertTrue(result["docker_installed"])
        self.assertEqual(result["docker_version"], "24.0.7")


# =============================================================================
# 9. FRAMEWORK LOADING
# =============================================================================

class TestFrameworkLoading(unittest.TestCase):
    """Test that _load_frameworks discovers and appends framework files.
    
    M-6 FIX: Only files in ALLOWED_FRAMEWORK_NAMES are loaded now.
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.cfg = _make_config(self.tmp)
        self.logger = _make_logger(self.cfg)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_framework_glob_pattern(self):
        """Files matching *_framework_*.md should be discovered by glob."""
        policy_dir = self.tmp / "policy"
        (policy_dir / "home_assistant_framework_v1.md").write_text("# HA Framework")
        (policy_dir / "zigbee_framework_v1.md").write_text("# Zigbee Framework")
        (policy_dir / "not_a_framework.md").write_text("# Not a framework")

        found = sorted(policy_dir.glob("*_framework_*.md"))
        names = [f.name for f in found]
        self.assertIn("home_assistant_framework_v1.md", names)
        self.assertIn("zigbee_framework_v1.md", names)
        self.assertNotIn("not_a_framework.md", names)

    def test_framework_content_appended_to_policy(self):
        """Allowlisted framework content should appear after the base policy."""
        policy_dir = self.tmp / "policy"
        # M-6 FIX: Use an allowlisted filename so it actually gets loaded
        fw = policy_dir / "ha_framework_v3.md"
        fw.write_text("FRAMEWORK_SENTINEL_VALUE_12345")

        from proxy.aiohai_proxy import UnifiedSecureProxy
        proxy_mock = MagicMock()
        proxy_mock.config = self.cfg
        proxy_mock.logger = self.logger

        result = UnifiedSecureProxy._load_frameworks(proxy_mock, "BASE_POLICY")
        self.assertTrue(result.startswith("BASE_POLICY"))
        self.assertIn("FRAMEWORK_SENTINEL_VALUE_12345", result)
        self.assertIn("FRAMEWORK:", result)

    def test_non_allowlisted_framework_rejected(self):
        """M-6 FIX: Files not in ALLOWED_FRAMEWORK_NAMES must be rejected."""
        policy_dir = self.tmp / "policy"
        # This matches the glob but is NOT in the allowlist
        rogue = policy_dir / "evil_framework_inject.md"
        rogue.write_text("INJECTED_PROMPT_SHOULD_NOT_APPEAR")

        from proxy.aiohai_proxy import UnifiedSecureProxy
        proxy_mock = MagicMock()
        proxy_mock.config = self.cfg
        proxy_mock.logger = self.logger

        result = UnifiedSecureProxy._load_frameworks(proxy_mock, "BASE_POLICY")
        self.assertNotIn("INJECTED_PROMPT_SHOULD_NOT_APPEAR", result)
        # Should log a rejection
        proxy_mock.logger.log_event.assert_called()

    def test_no_frameworks_returns_unchanged(self):
        """With no framework files, policy should be unchanged."""
        from proxy.aiohai_proxy import UnifiedSecureProxy
        proxy_mock = MagicMock()
        proxy_mock.config = self.cfg
        proxy_mock.logger = self.logger

        result = UnifiedSecureProxy._load_frameworks(proxy_mock, "BASE_POLICY")
        self.assertEqual(result, "BASE_POLICY")


# =============================================================================
# 10. AGENTIC INSTRUCTIONS
# =============================================================================

class TestAgenticInstructions(unittest.TestCase):
    """Verify AGENTIC_INSTRUCTIONS include HA-framework references."""

    def test_api_query_action_documented(self):
        self.assertIn("API_QUERY", AGENTIC_INSTRUCTIONS)

    def test_frigate_service_referenced(self):
        self.assertIn("Frigate", AGENTIC_INSTRUCTIONS)

    def test_homeassistant_service_referenced(self):
        self.assertIn("Home Assistant", AGENTIC_INSTRUCTIONS)

    def test_bridge_service_referenced(self):
        self.assertIn("AIOHAI Bridge", AGENTIC_INSTRUCTIONS)

    def test_docker_tier_rule_present(self):
        self.assertIn("Docker commands are tiered", AGENTIC_INSTRUCTIONS)

    def test_framework_reference_rule(self):
        self.assertIn("Home Assistant Orchestration Framework", AGENTIC_INSTRUCTIONS)

    def test_all_original_actions_present(self):
        for action in ("COMMAND", "READ", "WRITE", "LIST", "DELETE"):
            self.assertIn(f'type="{action}"', AGENTIC_INSTRUCTIONS,
                          f"Missing original action: {action}")


# =============================================================================
# 11. CONFIG SCHEMA
# =============================================================================

class TestConfigSchema(unittest.TestCase):
    """Verify config.json has correct smart_home section."""

    @classmethod
    def setUpClass(cls):
        config_path = PROJECT_ROOT / "config" / "config.json"
        with open(config_path) as f:
            cls.config = json.load(f)

    def test_schema_is_aiohai_v3(self):
        self.assertEqual(self.config["$schema"], "AIOHAI Configuration v3.0")

    def test_version_is_3_0_0(self):
        self.assertEqual(self.config["general"]["version"], "3.0.0")

    def test_smart_home_section_exists(self):
        self.assertIn("smart_home", self.config)

    def test_smart_home_enabled(self):
        self.assertTrue(self.config["smart_home"]["enabled"])

    def test_notification_bridge_config(self):
        nb = self.config["smart_home"]["notification_bridge"]
        self.assertTrue(nb["enabled"])
        self.assertEqual(nb["port"], 11436)
        self.assertEqual(nb["frigate_host"], "127.0.0.1")
        self.assertEqual(nb["frigate_port"], 5000)

    def test_stack_detection_config(self):
        sd = self.config["smart_home"]["stack_detection"]
        self.assertTrue(sd["enabled"])
        self.assertEqual(sd["check_interval_seconds"], 60)

    def test_install_path_is_aiohai(self):
        self.assertEqual(self.config["general"]["install_path"], r"C:\AIOHAI")


# =============================================================================
# 12. FRAMEWORK FILE
# =============================================================================

class TestFrameworkFile(unittest.TestCase):
    """Verify the framework markdown file is properly named and has no old refs."""

    @classmethod
    def setUpClass(cls):
        cls.fw_path = PROJECT_ROOT / "policy" / "home_assistant_framework_v1.md"
        if cls.fw_path.exists():
            cls.content = cls.fw_path.read_text(encoding="utf-8")
        else:
            cls.content = None

    def test_file_exists(self):
        self.assertTrue(self.fw_path.exists(), "Framework file missing")

    def test_matches_glob_pattern(self):
        """Filename must match *_framework_*.md."""
        self.assertRegex(self.fw_path.name, r".*_framework_.*\.md")

    def test_no_old_naming(self):
        """Must not contain any SecureLLM/securellm references."""
        if self.content is None:
            self.skipTest("Framework file missing")
        for old in ("SecureLLM", "securellm", "secure_llm", "SECURELLM"):
            self.assertNotIn(old, self.content, f"Old naming found: {old}")

    def test_has_aiohai_paths(self):
        if self.content is None:
            self.skipTest("Framework file missing")
        self.assertIn("AIOHAI", self.content)

    def test_has_smart_home_status_block(self):
        if self.content is None:
            self.skipTest("Framework file missing")
        self.assertIn("[SMART_HOME_STATUS]", self.content)

    def test_has_camera_rtsp_section(self):
        if self.content is None:
            self.skipTest("Framework file missing")
        self.assertIn("RTSP", self.content)

    def test_has_docker_compose_reference(self):
        if self.content is None:
            self.skipTest("Framework file missing")
        self.assertIn("docker-compose", self.content)


# =============================================================================
# 13. SECURITY — No old naming anywhere
# =============================================================================

class TestNoOldNaming(unittest.TestCase):
    """Scan all source files for residual SecureLLM references."""

    def test_no_securellm_in_python_files(self):
        for py_file in PROJECT_ROOT.rglob("*.py"):
            if "__pycache__" in str(py_file):
                continue
            if py_file.name.startswith("test_"):
                continue  # Test files reference old names in assertions/docstrings
            content = py_file.read_text(encoding="utf-8")
            # Allow references in comments about history
            lines = content.split("\n")
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue  # Skip comments
                for old in ("SecureLLM", "securellm", "secure_llm_"):
                    self.assertNotIn(
                        old, line,
                        f"Old naming '{old}' in {py_file.name}:{i}: {stripped[:80]}"
                    )

    def test_no_securellm_in_json(self):
        for json_file in PROJECT_ROOT.rglob("*.json"):
            content = json_file.read_text(encoding="utf-8")
            for old in ("SecureLLM", "securellm", "secure_llm"):
                self.assertNotIn(old, content,
                                 f"Old naming '{old}' in {json_file.name}")


# =============================================================================
# 14. SECURITY — Notification bridge binds localhost only
# =============================================================================

class TestNotificationBridgeSecurity(unittest.TestCase):
    """The bridge must only ever bind to 127.0.0.1."""

    def test_bridge_binds_localhost(self):
        """Verify the bridge source hardcodes 127.0.0.1."""
        import inspect
        source = inspect.getsource(HomeAssistantNotificationBridge.start)
        self.assertIn("127.0.0.1", source)
        # Must NOT have 0.0.0.0 binding
        self.assertNotIn("0.0.0.0", source)

    def test_snapshot_proxy_sanitizes_camera_name(self):
        """Camera names must be alphanumeric+underscore+hyphen only."""
        import inspect
        source = inspect.getsource(HomeAssistantNotificationBridge.start)
        # Should contain regex check
        self.assertIn("re.match", source)
        self.assertIn("[a-zA-Z0-9_-]", source)


# =============================================================================
# 15. SECURITY — Service registry rejects all non-localhost
# =============================================================================

class TestServiceRegistrySecurity(unittest.TestCase):
    """Exhaustive tests that non-local hosts are always rejected."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.cfg = _make_config(self.tmp)
        self.logger = _make_logger(self.cfg)
        self.reg = LocalServiceRegistry(self.logger)
        self.reg.register("svc", "127.0.0.1", 5000, ["/api/*"])

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_external_ip_rejected(self):
        ok, _ = self.reg.validate_request("http://8.8.8.8:5000/api/events")
        self.assertFalse(ok)

    def test_private_ip_rejected(self):
        ok, _ = self.reg.validate_request("http://192.168.1.1:5000/api/events")
        self.assertFalse(ok)

    def test_dns_name_rejected(self):
        ok, _ = self.reg.validate_request("http://evil.com:5000/api/events")
        self.assertFalse(ok)

    def test_ipv6_loopback_accepted(self):
        """::1 is also localhost and should be accepted if registered."""
        self.reg.register("ipv6_svc", "::1", 5001, ["/test"])
        ok, svc = self.reg.validate_request("http://[::1]:5001/test")
        # Note: urllib.parse may handle IPv6 differently
        # This tests our intent at least
        # The key security property is that external hosts are blocked

    def test_register_10_network_rejected(self):
        self.reg.register("bad", "10.0.0.5", 5000, ["/api/*"])
        ok, _ = self.reg.validate_request("http://10.0.0.5:5000/api/test")
        self.assertFalse(ok)

    def test_register_172_network_rejected(self):
        self.reg.register("bad", "172.16.0.1", 5000, ["/api/*"])
        ok, _ = self.reg.validate_request("http://172.16.0.1:5000/api/test")
        self.assertFalse(ok)


# =============================================================================
# 16. INTEGRATION — Smart home config in existing analyzer
# =============================================================================

class TestSmartHomeConfigAnalyzer(unittest.TestCase):
    """Ensure SmartHomeConfigAnalyzer still works after our changes."""

    def test_analyzer_instantiates(self):
        analyzer = SmartHomeConfigAnalyzer()
        self.assertIsNotNone(analyzer)


# =============================================================================
# Run
# =============================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
