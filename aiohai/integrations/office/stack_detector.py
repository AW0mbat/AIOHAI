#!/usr/bin/env python3
"""
AIOHAI Integrations — Office Stack Detector
=============================================
Auto-detect installed Microsoft Office applications, Python Office libraries,
COM availability, and Graph API configuration.

Generates an [OFFICE_STATUS] context block injected into the system prompt
so the local model knows what capabilities are available.

Previously defined in security/security_components.py.
Extracted as Phase 4b of the monolith → layered architecture migration.

Import from: aiohai.integrations.office.stack_detector
"""

import os
import sys
import json
import time
import logging
from pathlib import Path
from typing import Dict


class OfficeStackDetector:
    """
    Auto-detect installed Microsoft Office applications, Python Office libraries,
    COM availability, and Graph API configuration.

    Generates an [OFFICE_STATUS] context block injected into the system prompt
    so the local model knows what capabilities are available.
    """

    # Python libraries to probe
    PYTHON_LIBS = {
        'python_docx': 'docx',
        'openpyxl': 'openpyxl',
        'python_pptx': 'pptx',
        'comtypes': 'comtypes',
    }

    # Office executables to search for (Windows)
    OFFICE_APPS = {
        'word': ['WINWORD.EXE', 'winword'],
        'excel': ['EXCEL.EXE', 'excel'],
        'powerpoint': ['POWERPNT.EXE', 'powerpnt'],
    }

    # Common Office install paths on Windows
    OFFICE_PATHS = [
        r'C:\Program Files\Microsoft Office',
        r'C:\Program Files (x86)\Microsoft Office',
        r'C:\Program Files\Microsoft Office 15',
        r'C:\Program Files\Microsoft Office 16',
    ]

    def __init__(self, base_dir: str = None, cache_ttl: int = 120):
        if base_dir:
            self.base_dir = Path(base_dir)
        elif os.environ.get('AIOHAI_HOME'):
            self.base_dir = Path(os.environ['AIOHAI_HOME'])
        else:
            self.base_dir = Path(os.path.expanduser('~'))

        self._cache = None
        self._cache_time = 0
        self._cache_ttl = cache_ttl
        self.logger = logging.getLogger('aiohai.office_detector')

    def detect(self) -> Dict:
        """Run full detection and return status dict."""
        now = time.time()
        if self._cache and (now - self._cache_time) < self._cache_ttl:
            return self._cache

        result = {
            'detection_state': 'not_available',
            'libraries': {},
            'office_apps': {},
            'document_directories': {},
            'graph_api': {'configured': False},
            'platform': sys.platform,
        }

        # Detect Python libraries
        lib_count = 0
        for display_name, import_name in self.PYTHON_LIBS.items():
            try:
                mod = __import__(import_name)
                version = getattr(mod, '__version__', 'unknown')
                result['libraries'][display_name] = {
                    'installed': True,
                    'version': version,
                }
                lib_count += 1
            except ImportError:
                result['libraries'][display_name] = {
                    'installed': False,
                    'version': None,
                }

        # Detect Office applications (Windows only)
        if sys.platform == 'win32':
            result['office_apps'] = self._detect_office_windows()
        else:
            for app in self.OFFICE_APPS:
                result['office_apps'][app] = {
                    'installed': False,
                    'version': None,
                    'note': 'Office app detection is Windows-only',
                }

        # Detect document directories
        result['document_directories'] = self._detect_doc_dirs()

        # Detect Graph API configuration
        result['graph_api'] = self._detect_graph_config()

        # Determine overall state
        core_libs = ['python_docx', 'openpyxl', 'python_pptx']
        core_installed = sum(1 for lib in core_libs
                            if result['libraries'].get(lib, {}).get('installed'))

        if core_installed == len(core_libs):
            result['detection_state'] = 'ready'
        elif core_installed > 0:
            result['detection_state'] = 'partial'
        else:
            result['detection_state'] = 'not_available'

        self._cache = result
        self._cache_time = now
        self.logger.info(f"Office detection: {result['detection_state']} "
                         f"({core_installed}/{len(core_libs)} core libs)")
        return result

    def _detect_office_windows(self) -> Dict:
        """Detect Office apps on Windows via registry or file search."""
        apps = {}
        for app_name, exe_names in self.OFFICE_APPS.items():
            found = False
            for search_path in self.OFFICE_PATHS:
                p = Path(search_path)
                if p.exists():
                    for exe in exe_names:
                        matches = list(p.rglob(exe))
                        if matches:
                            version = self._get_office_version(matches[0])
                            apps[app_name] = {
                                'installed': True,
                                'version': version,
                                'path': str(matches[0]),
                            }
                            found = True
                            break
                if found:
                    break
            if not found:
                apps[app_name] = {'installed': False, 'version': None}
        return apps

    def _get_office_version(self, exe_path: Path) -> str:
        """Extract Office version from the executable path."""
        path_str = str(exe_path)
        # Try to extract version from path (e.g., Office16, Office15)
        for marker in ['Office16', 'Office15', 'Office14', 'Office12']:
            if marker in path_str:
                version_map = {
                    'Office16': '16.x (2016/2019/365)',
                    'Office15': '15.x (2013)',
                    'Office14': '14.x (2010)',
                    'Office12': '12.x (2007)',
                }
                return version_map.get(marker, 'unknown')
        return 'unknown'

    def _detect_doc_dirs(self) -> Dict:
        """Find standard document directories."""
        dirs = {}
        home = Path.home()

        candidates = {
            'documents': [home / 'Documents', home / 'My Documents'],
            'desktop': [home / 'Desktop'],
            'downloads': [home / 'Downloads'],
        }

        for name, paths in candidates.items():
            for p in paths:
                if p.exists():
                    dirs[name] = str(p)
                    break
            else:
                dirs[name] = None

        return dirs

    def _detect_graph_config(self) -> Dict:
        """Check if Microsoft Graph API is configured."""
        config = {
            'configured': False,
            'tenant_id': None,
            'client_id': None,
            'scopes': [],
        }

        # Check for config file
        graph_config = self.base_dir / 'config' / 'graph_api.json'
        if graph_config.exists():
            try:
                with open(graph_config, encoding='utf-8') as f:
                    data = json.load(f)
                config['configured'] = bool(data.get('tenant_id') and data.get('client_id'))
                config['tenant_id'] = '[set]' if data.get('tenant_id') else '[not set]'
                config['client_id'] = '[set]' if data.get('client_id') else '[not set]'
                config['scopes'] = data.get('scopes', [])
            except (json.JSONDecodeError, OSError):
                pass

        # Also check environment variables
        if os.environ.get('AIOHAI_GRAPH_TENANT_ID'):
            config['configured'] = True
            config['tenant_id'] = '[set via env]'

        return config

    def get_context_block(self) -> str:
        """Generate the [OFFICE_STATUS] block for system prompt injection."""
        status = self.detect()

        lines = ['## [OFFICE_STATUS]']
        lines.append(f"detection_state: {status['detection_state']}")

        lines.append('libraries:')
        for lib, info in status['libraries'].items():
            if info['installed']:
                lines.append(f"  {lib}: installed ({info['version']})")
            else:
                if lib == 'comtypes' and sys.platform != 'win32':
                    lines.append(f"  {lib}: not_applicable (linux)")
                else:
                    lines.append(f"  {lib}: not_installed")

        lines.append('office_apps:')
        for app, info in status['office_apps'].items():
            if info['installed']:
                lines.append(f"  {app}: installed ({info.get('version', 'unknown')})")
            else:
                lines.append(f"  {app}: not_found")

        lines.append('document_directories:')
        for name, path in status['document_directories'].items():
            if path:
                lines.append(f"  {name}: {path}")
            else:
                lines.append(f"  {name}: not_found")

        graph = status['graph_api']
        lines.append('graph_api:')
        lines.append(f"  configured: {str(graph['configured']).lower()}")
        if graph['configured']:
            lines.append(f"  tenant_id: {graph['tenant_id']}")
            lines.append(f"  scopes: {', '.join(graph['scopes']) if graph['scopes'] else 'none'}")

        lines.append('## [/OFFICE_STATUS]')
        return '\n'.join(lines)


__all__ = ['OfficeStackDetector']
