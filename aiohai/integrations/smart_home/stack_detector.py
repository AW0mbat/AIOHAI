#!/usr/bin/env python3
"""
AIOHAI Integrations — Smart Home Stack Detector
=================================================
Detects the current state of the smart home stack on the local system.

Checks for Docker, Home Assistant, Frigate NVR, and Mosquitto MQTT
installations and generates a context block for the system prompt.

Deployment states:
  - not_deployed: No containers or config files found
  - partial: Some components found but not all running
  - running: All detected components are running
  - stopped: Components exist but containers are stopped

Previously defined in security/security_components.py.
Extracted as Phase 4a of the monolith → layered architecture migration.

Import from: aiohai.integrations.smart_home.stack_detector
"""

import os
import re
import time
import logging
import subprocess
import urllib.request
from pathlib import Path
from typing import Dict, List


class SmartHomeStackDetector:
    """Detects the current state of the smart home stack on the local system.

    Checks for Docker, Home Assistant, Frigate NVR, and Mosquitto MQTT
    installations and generates a context block for the system prompt.

    Deployment states:
      - not_deployed: No containers or config files found
      - partial: Some components found but not all running
      - running: All detected components are running
      - stopped: Components exist but containers are stopped
    """

    def __init__(self, base_dir: str = None):
        self.base_dir = Path(base_dir) if base_dir else Path(os.environ.get('AIOHAI_HOME', r'C:\AIOHAI'))
        self.logger = logging.getLogger('aiohai.stack_detector')
        self._cache = None
        self._cache_time = 0
        self._cache_ttl = 60  # seconds

    def detect(self) -> Dict:
        """Run full detection and return results."""
        now = time.time()
        if self._cache and (now - self._cache_time) < self._cache_ttl:
            return self._cache

        result = {
            'docker_installed': False,
            'docker_version': None,
            'containers': {},
            'config_files': {},
            'services': {},
            'deployment_state': 'not_deployed',
            'cameras': [],
        }

        # Check Docker
        try:
            docker_check = subprocess.run(
                ['docker', 'version', '--format', '{{.Server.Version}}'],
                capture_output=True, text=True, timeout=10
            )
            if docker_check.returncode == 0:
                result['docker_installed'] = True
                result['docker_version'] = docker_check.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        if not result['docker_installed']:
            self._cache = result
            self._cache_time = now
            return result

        # Check for known containers
        try:
            ps_result = subprocess.run(
                ['docker', 'ps', '-a', '--format', '{{.Names}}|{{.Status}}|{{.Image}}'],
                capture_output=True, text=True, timeout=10
            )
            if ps_result.returncode == 0:
                known_containers = {
                    'homeassistant': ['homeassistant', 'home-assistant', 'hass'],
                    'frigate': ['frigate'],
                    'mosquitto': ['mosquitto', 'mqtt', 'eclipse-mosquitto'],
                }
                for line in ps_result.stdout.strip().split('\n'):
                    if not line.strip():
                        continue
                    parts = line.split('|', 2)
                    if len(parts) < 3:
                        continue
                    name, status, image = parts[0].strip(), parts[1].strip(), parts[2].strip()
                    name_lower = name.lower()

                    for service, patterns in known_containers.items():
                        if any(p in name_lower or p in image.lower() for p in patterns):
                            is_running = status.lower().startswith('up')
                            result['containers'][service] = {
                                'name': name,
                                'status': 'running' if is_running else 'stopped',
                                'image': image,
                            }
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            self.logger.warning(f"Docker ps failed: {e}")

        # Scan for config files
        search_dirs = [
            self.base_dir,
            self.base_dir / 'homeassistant',
            self.base_dir / 'frigate',
            Path.home() / 'homeassistant',
            Path.home() / 'frigate',
        ]

        config_patterns = {
            'ha_config': ['configuration.yaml'],
            'frigate_config': ['config.yml', 'frigate.yml'],
            'docker_compose': ['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml'],
        }

        for search_dir in search_dirs:
            if not search_dir.exists():
                continue
            try:
                for config_type, filenames in config_patterns.items():
                    if config_type in result['config_files']:
                        continue
                    for fn in filenames:
                        candidate = search_dir / fn
                        if candidate.exists():
                            result['config_files'][config_type] = str(candidate)

                            # Parse cameras from Frigate config
                            if config_type == 'frigate_config':
                                result['cameras'] = self._parse_frigate_cameras(candidate)
            except PermissionError:
                continue

        # Check service health via HTTP
        service_checks = {
            'frigate': ('127.0.0.1', 5000, '/api/version'),
            'homeassistant': ('127.0.0.1', 8123, '/api/config'),
        }

        for svc_name, (host, port, path) in service_checks.items():
            try:
                url = f"http://{host}:{port}{path}"
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, timeout=3) as resp:
                    if resp.status == 200:
                        result['services'][svc_name] = 'healthy'
                    else:
                        result['services'][svc_name] = f'http_{resp.status}'
            except Exception:
                result['services'][svc_name] = 'unreachable'

        # Classify deployment state
        has_containers = len(result['containers']) > 0
        has_configs = len(result['config_files']) > 0
        all_running = all(
            c['status'] == 'running' for c in result['containers'].values()
        ) if has_containers else False

        if not has_containers and not has_configs:
            result['deployment_state'] = 'not_deployed'
        elif all_running and has_containers:
            result['deployment_state'] = 'running'
        elif has_containers and not all_running:
            result['deployment_state'] = 'stopped'
        else:
            result['deployment_state'] = 'partial'

        self._cache = result
        self._cache_time = now
        return result

    def _parse_frigate_cameras(self, config_path: Path) -> List[str]:
        """Parse camera names from Frigate config (simple regex, no YAML dep)."""
        cameras = []
        try:
            content = config_path.read_text(encoding='utf-8')
            in_cameras = False
            indent_level = None

            for line in content.split('\n'):
                stripped = line.strip()
                if stripped == 'cameras:':
                    in_cameras = True
                    indent_level = len(line) - len(line.lstrip())
                    continue

                if in_cameras and stripped and not stripped.startswith('#'):
                    current_indent = len(line) - len(line.lstrip())
                    if current_indent <= indent_level and stripped != '':
                        break  # Exited cameras section

                    if current_indent == indent_level + 2 and stripped.endswith(':'):
                        cam_name = stripped.rstrip(':').strip()
                        if re.match(r'^[a-zA-Z0-9_-]+$', cam_name):
                            cameras.append(cam_name)
        except Exception as e:
            self.logger.warning(f"Failed to parse Frigate cameras: {e}")

        return cameras

    def get_context_block(self) -> str:
        """Generate a context block for system prompt injection."""
        status = self.detect()

        lines = [
            '[SMART_HOME_STATUS]',
            f'deployment_state: {status["deployment_state"]}',
            f'docker_installed: {status["docker_installed"]}',
        ]

        if status['docker_version']:
            lines.append(f'docker_version: {status["docker_version"]}')

        if status['containers']:
            lines.append('containers:')
            for svc, info in status['containers'].items():
                lines.append(f'  {svc}: {info["status"]} ({info["image"]})')

        if status['config_files']:
            lines.append('config_files:')
            for cfg_type, path in status['config_files'].items():
                lines.append(f'  {cfg_type}: {path}')

        if status['cameras']:
            lines.append(f'cameras: {", ".join(status["cameras"])}')

        if status['services']:
            lines.append('service_health:')
            for svc, health in status['services'].items():
                lines.append(f'  {svc}: {health}')

        lines.append('[/SMART_HOME_STATUS]')

        return '\n'.join(lines)


__all__ = ['SmartHomeStackDetector']
