#!/usr/bin/env python3
"""
AIOHAI Core Access — Target Classifier
========================================
Pattern-based classification of action targets into TargetDomain values.

Given a target string (file path, command, HA entity, API endpoint, etc.)
and contextual hints, determines which TargetDomain it belongs to.

This is the "noun" dimension of action classification — paired with
ActionCategory (the "verb" dimension) to look up the approval level
in the tier matrix.

Phase 1 of Approval Gate Taxonomy v3 implementation.

Import from: aiohai.core.access.target_classifier
"""

import os
import re
from typing import Optional

from aiohai.core.types import TargetDomain
from aiohai.core.constants import IS_WINDOWS

__all__ = ['TargetClassifier']


# =============================================================================
# PATTERN SETS — Ordered by specificity (most specific first)
# =============================================================================

# Windows user profile directory — computed once, lowercased for matching
_USER_PROFILE = os.path.expanduser('~').lower() if IS_WINDOWS else ''


def _fs_patterns():
    """Build filesystem domain classification patterns.

    Returns list of (compiled_regex, TargetDomain) tuples.
    Order matters — first match wins.
    """
    patterns = []

    def _add(regex_str, domain):
        patterns.append((re.compile(regex_str, re.IGNORECASE), domain))

    # --- FS_CRED: Credential stores (DENY gate in matrix) ---
    _add(r'[/\\]\.ssh[/\\]', TargetDomain.FS_CRED)
    _add(r'[/\\]\.gnupg[/\\]', TargetDomain.FS_CRED)
    _add(r'[/\\]\.aws[/\\]', TargetDomain.FS_CRED)
    _add(r'[/\\]\.azure[/\\]', TargetDomain.FS_CRED)
    _add(r'[/\\]\.kube[/\\]', TargetDomain.FS_CRED)
    _add(r'[/\\]\.docker[/\\]', TargetDomain.FS_CRED)
    _add(r'\.git-credentials', TargetDomain.FS_CRED)
    _add(r'\.npmrc$', TargetDomain.FS_CRED)
    _add(r'\.pypirc$', TargetDomain.FS_CRED)
    _add(r'\.netrc$', TargetDomain.FS_CRED)
    _add(r'id_rsa', TargetDomain.FS_CRED)
    _add(r'id_ed25519', TargetDomain.FS_CRED)
    _add(r'id_ecdsa', TargetDomain.FS_CRED)
    _add(r'authorized_keys', TargetDomain.FS_CRED)
    _add(r'\.pem$', TargetDomain.FS_CRED)
    _add(r'\.key$', TargetDomain.FS_CRED)
    _add(r'\.pfx$', TargetDomain.FS_CRED)
    _add(r'\.p12$', TargetDomain.FS_CRED)
    _add(r'\.keystore$', TargetDomain.FS_CRED)
    _add(r'\.env$', TargetDomain.FS_CRED)
    _add(r'\.env\.', TargetDomain.FS_CRED)
    _add(r'\.envrc$', TargetDomain.FS_CRED)
    _add(r'login\s*data', TargetDomain.FS_CRED)
    _add(r'web\s*data', TargetDomain.FS_CRED)
    _add(r'local\s*state', TargetDomain.FS_CRED)
    _add(r'logins\.json', TargetDomain.FS_CRED)
    _add(r'\.kdbx$', TargetDomain.FS_CRED)
    _add(r'keepass', TargetDomain.FS_CRED)
    _add(r'1password', TargetDomain.FS_CRED)
    _add(r'bitwarden', TargetDomain.FS_CRED)
    _add(r'passwords?\.csv', TargetDomain.FS_CRED)
    _add(r'passwords?\.xlsx?', TargetDomain.FS_CRED)
    _add(r'wallet\.dat', TargetDomain.FS_CRED)
    _add(r'[/\\]bitcoin[/\\]', TargetDomain.FS_CRED)
    _add(r'[/\\]ethereum[/\\]', TargetDomain.FS_CRED)
    _add(r'seed.*phrase', TargetDomain.FS_CRED)
    _add(r'recovery.*phrase', TargetDomain.FS_CRED)
    _add(r'cookies', TargetDomain.FS_CRED)

    # --- FS_SYSTEM: OS system directories (DENY gate in matrix) ---
    _add(r'[/\\]windows[/\\]system32', TargetDomain.FS_SYSTEM)
    _add(r'[/\\]windows[/\\]syswow64', TargetDomain.FS_SYSTEM)
    _add(r'[/\\]windows[/\\]winsxs', TargetDomain.FS_SYSTEM)
    _add(r'[/\\]sam$', TargetDomain.FS_SYSTEM)
    _add(r'[/\\]security$', TargetDomain.FS_SYSTEM)
    _add(r'ntds\.dit', TargetDomain.FS_SYSTEM)
    _add(r'[/\\]etc[/\\]passwd', TargetDomain.FS_SYSTEM)
    _add(r'[/\\]etc[/\\]shadow', TargetDomain.FS_SYSTEM)
    _add(r'[/\\]boot[/\\]', TargetDomain.FS_SYSTEM)
    _add(r'[/\\]program\s*files', TargetDomain.FS_SYSTEM)
    # Startup/persistence locations
    _add(r'start\s*menu.*startup', TargetDomain.FS_SYSTEM)
    _add(r'appdata.*microsoft.*windows.*start\s*menu', TargetDomain.FS_SYSTEM)

    # --- FS_AIOHAI: AIOHAI's own files ---
    _add(r'[/\\]aiohai[/\\]', TargetDomain.FS_AIOHAI)

    # --- FS_NET: Network-related files ---
    _add(r'[/\\]etc[/\\]hosts$', TargetDomain.FS_NET)
    _add(r'[/\\]drivers[/\\]etc[/\\]hosts$', TargetDomain.FS_NET)
    _add(r'[/\\]etc[/\\]resolv\.conf$', TargetDomain.FS_NET)
    _add(r'\.ssh[/\\]config$', TargetDomain.FS_NET)
    _add(r'[/\\]etc[/\\]network', TargetDomain.FS_NET)

    # --- FS_APPCONF: Application config files ---
    _add(r'appdata[/\\]roaming', TargetDomain.FS_APPCONF)
    _add(r'appdata[/\\]local', TargetDomain.FS_APPCONF)
    _add(r'[/\\]\.config[/\\]', TargetDomain.FS_APPCONF)
    _add(r'\.vscode[/\\]', TargetDomain.FS_APPCONF)
    _add(r'\.idea[/\\]', TargetDomain.FS_APPCONF)
    # Office persistence/template directories (high risk subset of appconf)
    _add(r'appdata.*microsoft.*templates', TargetDomain.FS_APPCONF)
    _add(r'appdata.*microsoft.*excel.*xlstart', TargetDomain.FS_APPCONF)
    _add(r'appdata.*microsoft.*word.*startup', TargetDomain.FS_APPCONF)
    _add(r'normal\.dotm$', TargetDomain.FS_APPCONF)
    _add(r'personal\.xlsb$', TargetDomain.FS_APPCONF)
    # Outlook data stores
    _add(r'\.pst$', TargetDomain.FS_APPCONF)
    _add(r'\.ost$', TargetDomain.FS_APPCONF)

    # --- FS_DOC_SENS: Sensitive documents (financial, medical, legal) ---
    _add(r'turbotax', TargetDomain.FS_DOC_SENS)
    _add(r'taxact', TargetDomain.FS_DOC_SENS)
    _add(r'h&r\s*block', TargetDomain.FS_DOC_SENS)
    _add(r'[/\\]tax\s*return', TargetDomain.FS_DOC_SENS)
    _add(r'[/\\]taxes[/\\]', TargetDomain.FS_DOC_SENS)
    _add(r'quicken', TargetDomain.FS_DOC_SENS)
    _add(r'[/\\]qdata[/\\]', TargetDomain.FS_DOC_SENS)
    _add(r'\.qdf$', TargetDomain.FS_DOC_SENS)
    _add(r'\.qfx$', TargetDomain.FS_DOC_SENS)
    _add(r'quickbooks', TargetDomain.FS_DOC_SENS)
    _add(r'\.qbw$', TargetDomain.FS_DOC_SENS)
    _add(r'\.qbb$', TargetDomain.FS_DOC_SENS)
    _add(r'gnucash', TargetDomain.FS_DOC_SENS)
    _add(r'moneydance', TargetDomain.FS_DOC_SENS)
    _add(r'bank.*statement', TargetDomain.FS_DOC_SENS)
    _add(r'financial.*record', TargetDomain.FS_DOC_SENS)
    _add(r'[/\\]fidelity[/\\]', TargetDomain.FS_DOC_SENS)
    _add(r'[/\\]schwab[/\\]', TargetDomain.FS_DOC_SENS)
    _add(r'[/\\]vanguard[/\\]', TargetDomain.FS_DOC_SENS)
    # Sensitive doc content patterns (from OperationClassifier)
    _add(r'payroll', TargetDomain.FS_DOC_SENS)
    _add(r'salary', TargetDomain.FS_DOC_SENS)
    _add(r'personnel', TargetDomain.FS_DOC_SENS)
    _add(r'hr[_\-\s]', TargetDomain.FS_DOC_SENS)
    _add(r'human.?resources', TargetDomain.FS_DOC_SENS)
    _add(r'performance.?review', TargetDomain.FS_DOC_SENS)
    _add(r'medical', TargetDomain.FS_DOC_SENS)
    _add(r'health.*record', TargetDomain.FS_DOC_SENS)
    _add(r'insurance.*claim', TargetDomain.FS_DOC_SENS)
    _add(r'nda', TargetDomain.FS_DOC_SENS)
    _add(r'confidential', TargetDomain.FS_DOC_SENS)
    # Generic credential/secret file names
    _add(r'credential', TargetDomain.FS_DOC_SENS)
    _add(r'password', TargetDomain.FS_DOC_SENS)
    _add(r'passwd', TargetDomain.FS_DOC_SENS)
    _add(r'secret', TargetDomain.FS_DOC_SENS)

    # --- FS_TEMP: Temp directories ---
    _add(r'[/\\]temp[/\\]', TargetDomain.FS_TEMP)
    _add(r'[/\\]tmp[/\\]', TargetDomain.FS_TEMP)
    _add(r'[/\\]appdata[/\\]local[/\\]temp[/\\]', TargetDomain.FS_TEMP)

    # --- FS_DL: Downloads ---
    _add(r'[/\\]downloads[/\\]', TargetDomain.FS_DL)
    _add(r'[/\\]download[/\\]', TargetDomain.FS_DL)

    # --- FS_DESK: Desktop ---
    _add(r'[/\\]desktop[/\\]', TargetDomain.FS_DESK)

    # --- FS_MEDIA: Pictures, Music, Videos ---
    _add(r'[/\\]pictures[/\\]', TargetDomain.FS_MEDIA)
    _add(r'[/\\]photos[/\\]', TargetDomain.FS_MEDIA)
    _add(r'[/\\]music[/\\]', TargetDomain.FS_MEDIA)
    _add(r'[/\\]videos[/\\]', TargetDomain.FS_MEDIA)
    _add(r'[/\\]movies[/\\]', TargetDomain.FS_MEDIA)

    # --- FS_DOC: Documents (general, must be AFTER FS_DOC_SENS) ---
    _add(r'[/\\]documents[/\\]', TargetDomain.FS_DOC)
    _add(r'[/\\]onedrive[/\\]', TargetDomain.FS_DOC)

    return patterns


def _cmd_patterns():
    """Build command domain classification patterns.

    Returns list of (compiled_regex, TargetDomain) tuples.
    """
    patterns = []

    def _add(regex_str, domain):
        patterns.append((re.compile(regex_str, re.IGNORECASE), domain))

    # --- CMD_ADMIN: Admin/system commands (DENY gate in matrix) ---
    _add(r'\breg\b\s+(add|delete|query)', TargetDomain.CMD_ADMIN)
    _add(r'\bbcdedit\b', TargetDomain.CMD_ADMIN)
    _add(r'\bsfc\b', TargetDomain.CMD_ADMIN)
    _add(r'\bdism\b', TargetDomain.CMD_ADMIN)
    _add(r'\btakeown\b', TargetDomain.CMD_ADMIN)
    _add(r'\bicacls\b', TargetDomain.CMD_ADMIN)
    _add(r'\bwmic\b', TargetDomain.CMD_ADMIN)
    _add(r'\bsc\b\s+(create|delete)', TargetDomain.CMD_ADMIN)
    _add(r'\bnet\b\s+(user|localgroup)', TargetDomain.CMD_ADMIN)
    _add(r'\bgpupdate\b', TargetDomain.CMD_ADMIN)
    _add(r'\bshutdown\b', TargetDomain.CMD_ADMIN)

    # --- CMD_DISK: Disk commands (DENY gate in matrix) ---
    _add(r'\bdiskpart\b', TargetDomain.CMD_DISK)
    _add(r'\bformat\b\s+[a-z]:', TargetDomain.CMD_DISK)
    _add(r'\bchkdsk\b', TargetDomain.CMD_DISK)
    _add(r'\bfsutil\b', TargetDomain.CMD_DISK)
    _add(r'\bmklink\b', TargetDomain.CMD_DISK)

    # --- CMD_NET: Network commands (DENY gate in matrix) ---
    _add(r'\bnetsh\b', TargetDomain.CMD_NET)
    _add(r'\broute\b\s+(add|delete|change)', TargetDomain.CMD_NET)
    _add(r'\barp\b\s+-[sd]', TargetDomain.CMD_NET)
    _add(r'\bnslookup\b', TargetDomain.CMD_NET)

    # --- CMD_SVC: Service management ---
    _add(r'\bsc\b\s+(start|stop|config|query)', TargetDomain.CMD_SVC)
    _add(r'\bnet\b\s+(start|stop)', TargetDomain.CMD_SVC)
    _add(r'(start|stop|restart)-service', TargetDomain.CMD_SVC)
    _add(r'\bsystemctl\b', TargetDomain.CMD_SVC)

    # --- CMD_INST: Software installation ---
    _add(r'\bwinget\b\s+install', TargetDomain.CMD_INST)
    _add(r'\bchoco\b\s+install', TargetDomain.CMD_INST)
    _add(r'\bpip\b\s+install', TargetDomain.CMD_INST)
    _add(r'\bnpm\b\s+install', TargetDomain.CMD_INST)
    _add(r'\bapt\b\s+(install|remove)', TargetDomain.CMD_INST)
    _add(r'\bmsiexec\b', TargetDomain.CMD_INST)

    # --- CMD_SCRIPT: Script execution ---
    _add(r'\bpython\b', TargetDomain.CMD_SCRIPT)
    _add(r'\bnode\b', TargetDomain.CMD_SCRIPT)
    _add(r'\bpowershell\b.*-file', TargetDomain.CMD_SCRIPT)
    _add(r'\.ps1\b', TargetDomain.CMD_SCRIPT)
    _add(r'\.py\b', TargetDomain.CMD_SCRIPT)
    _add(r'\.bat\b', TargetDomain.CMD_SCRIPT)
    _add(r'\.cmd\b', TargetDomain.CMD_SCRIPT)
    _add(r'\.sh\b', TargetDomain.CMD_SCRIPT)
    _add(r'\bcscript\b', TargetDomain.CMD_SCRIPT)
    _add(r'\bwscript\b', TargetDomain.CMD_SCRIPT)

    # --- CMD_FOPS: File operation commands ---
    _add(r'\bcopy\b', TargetDomain.CMD_FOPS)
    _add(r'\bxcopy\b', TargetDomain.CMD_FOPS)
    _add(r'\brobocopy\b', TargetDomain.CMD_FOPS)
    _add(r'\bmove\b', TargetDomain.CMD_FOPS)
    _add(r'\brename\b', TargetDomain.CMD_FOPS)
    _add(r'\bren\b\s', TargetDomain.CMD_FOPS)
    _add(r'\bdel\b\s', TargetDomain.CMD_FOPS)
    _add(r'\brmdir\b', TargetDomain.CMD_FOPS)
    _add(r'\bmkdir\b', TargetDomain.CMD_FOPS)
    _add(r'copy-item', TargetDomain.CMD_FOPS)
    _add(r'move-item', TargetDomain.CMD_FOPS)
    _add(r'remove-item', TargetDomain.CMD_FOPS)
    _add(r'new-item', TargetDomain.CMD_FOPS)

    # --- CMD_INFO: Informational commands (lowest risk) ---
    _add(r'\bsysteminfo\b', TargetDomain.CMD_INFO)
    _add(r'\bwhoami\b', TargetDomain.CMD_INFO)
    _add(r'\bhostname\b', TargetDomain.CMD_INFO)
    _add(r'\bipconfig\b', TargetDomain.CMD_INFO)
    _add(r'\bifconfig\b', TargetDomain.CMD_INFO)
    _add(r'\bping\b', TargetDomain.CMD_INFO)
    _add(r'\btracert\b', TargetDomain.CMD_INFO)
    _add(r'\btraceroute\b', TargetDomain.CMD_INFO)
    _add(r'\bdir\b\s', TargetDomain.CMD_INFO)
    _add(r'\bls\b\s', TargetDomain.CMD_INFO)
    _add(r'\btype\b\s', TargetDomain.CMD_INFO)
    _add(r'\bcat\b\s', TargetDomain.CMD_INFO)
    _add(r'\bget-content\b', TargetDomain.CMD_INFO)
    _add(r'\bget-childitem\b', TargetDomain.CMD_INFO)
    _add(r'\bget-process\b', TargetDomain.CMD_INFO)
    _add(r'\btasklist\b', TargetDomain.CMD_INFO)
    _add(r'\becho\b', TargetDomain.CMD_INFO)
    _add(r'\bdate\b', TargetDomain.CMD_INFO)
    _add(r'\btime\b\s*/t', TargetDomain.CMD_INFO)
    _add(r'\bollama\b\s+(list|show|ps)', TargetDomain.CMD_INFO)

    return patterns


def _ha_patterns():
    """Build Home Assistant entity domain classification patterns.

    Returns list of (compiled_regex, TargetDomain) tuples.
    HA entity IDs follow the pattern 'domain.entity_id'.
    """
    patterns = []

    def _add(regex_str, domain):
        patterns.append((re.compile(regex_str, re.IGNORECASE), domain))

    _add(r'^(sensor|binary_sensor)\.', TargetDomain.HA_SENS)
    _add(r'^(person|device_tracker)\.', TargetDomain.HA_PRES)
    _add(r'^light\.', TargetDomain.HA_LIGHT)
    _add(r'^media_player\.', TargetDomain.HA_MEDIA)
    _add(r'^climate\.', TargetDomain.HA_CLIM)
    _add(r'^(fan|humidifier)\.', TargetDomain.HA_CLIM)
    _add(r'^cover\..*garage', TargetDomain.HA_GARAGE)
    _add(r'^cover\.', TargetDomain.HA_COVER)
    _add(r'^lock\.', TargetDomain.HA_LOCK)
    _add(r'^alarm_control_panel\.', TargetDomain.HA_ALARM)
    _add(r'^camera\.', TargetDomain.HA_CAM)
    _add(r'^notify\.', TargetDomain.HA_NOTIFY)
    _add(r'^scene\.', TargetDomain.HA_SCENE)
    _add(r'^automation\.', TargetDomain.HA_AUTO)
    _add(r'^script\.', TargetDomain.HA_SCRIPT)
    _add(r'^(input_boolean|input_number|input_text|input_select|input_datetime|counter|timer)\.', TargetDomain.HA_HELPER)
    _add(r'^switch\.', TargetDomain.HA_HELPER)  # generic switches default to helper
    # Configuration endpoints
    _add(r'/api/config', TargetDomain.HA_CONF)
    _add(r'/api/services/', TargetDomain.HA_CONF)

    return patterns


def _off_patterns():
    """Build Office domain classification patterns.

    Returns list of (compiled_regex, TargetDomain) tuples.
    """
    patterns = []

    def _add(regex_str, domain):
        patterns.append((re.compile(regex_str, re.IGNORECASE), domain))

    # Macros must be checked before general docs
    _add(r'\.xlsm$', TargetDomain.OFF_MACRO)
    _add(r'\.docm$', TargetDomain.OFF_MACRO)
    _add(r'\.pptm$', TargetDomain.OFF_MACRO)
    _add(r'macro', TargetDomain.OFF_MACRO)
    _add(r'vba', TargetDomain.OFF_MACRO)

    # Office documents
    _add(r'\.(docx?|xlsx?|pptx?|odt|ods|odp|csv|tsv)$', TargetDomain.OFF_DOC)

    # Email
    _add(r'graph\.microsoft\.com.*/messages', TargetDomain.OFF_EREAD)
    _add(r'graph\.microsoft\.com.*/sendMail', TargetDomain.OFF_ESEND)
    _add(r'graph\.microsoft\.com.*/send$', TargetDomain.OFF_ESEND)

    # Calendar
    _add(r'graph\.microsoft\.com.*/calendar', TargetDomain.OFF_CAL)
    _add(r'graph\.microsoft\.com.*/events', TargetDomain.OFF_CAL)

    # Contacts
    _add(r'graph\.microsoft\.com.*/contacts', TargetDomain.OFF_CONT)
    _add(r'graph\.microsoft\.com.*/people', TargetDomain.OFF_CONT)

    return patterns


# Compile pattern sets once at module load
_FS_PATTERNS = _fs_patterns()
_CMD_PATTERNS = _cmd_patterns()
_HA_PATTERNS = _ha_patterns()
_OFF_PATTERNS = _off_patterns()


# =============================================================================
# CLASSIFIER
# =============================================================================

class TargetClassifier:
    """Classify action targets into TargetDomain values.

    Supports four target families:
    - Filesystem paths (FS_*)
    - Commands (CMD_*)
    - Home Assistant entities/APIs (HA_*)
    - Office documents/APIs (OFF_*)

    Usage:
        domain = TargetClassifier.classify("C:/Users/admin/Documents/report.docx")
        # Returns TargetDomain.FS_DOC

        domain = TargetClassifier.classify("light.living_room", hint="ha")
        # Returns TargetDomain.HA_LIGHT

        domain = TargetClassifier.classify("systeminfo", hint="command")
        # Returns TargetDomain.CMD_INFO
    """

    @classmethod
    def classify(cls, target: str, hint: Optional[str] = None,
                 action_type: Optional[str] = None) -> TargetDomain:
        """Classify a target string into a TargetDomain.

        Args:
            target: The target string (file path, command, entity ID, etc.)
            hint: Optional hint about what kind of target this is.
                  One of: 'file', 'command', 'ha', 'office', 'api'.
                  If not provided, the classifier tries all pattern sets.
            action_type: Optional legacy action type string for context.

        Returns:
            The TargetDomain for this target. Returns TargetDomain.UNKNOWN
            if no pattern matches.
        """
        if not target:
            return TargetDomain.UNKNOWN

        # Normalize the target for matching
        normalized = target.strip()

        # Use hint to select pattern sets to check
        if hint == 'command' or action_type in ('COMMAND', 'COMMAND_EXEC'):
            return cls._match_first(normalized, _CMD_PATTERNS)

        if hint == 'ha':
            return cls._match_first(normalized, _HA_PATTERNS)

        if hint == 'office':
            return cls._match_first(normalized, _OFF_PATTERNS)

        if hint == 'api' or action_type in ('API_QUERY', 'LOCAL_API_QUERY'):
            # API targets could be HA or Office
            domain = cls._match_first(normalized, _HA_PATTERNS)
            if domain != TargetDomain.UNKNOWN:
                return domain
            domain = cls._match_first(normalized, _OFF_PATTERNS)
            if domain != TargetDomain.UNKNOWN:
                return domain
            return TargetDomain.UNKNOWN

        if hint == 'file' or action_type in (
                'READ', 'WRITE', 'DELETE', 'LIST',
                'FILE_READ', 'FILE_WRITE', 'FILE_DELETE', 'DIRECTORY_LIST'):
            # For file operations, check filesystem domains first.
            # Only fall back to Office document detection (by extension)
            # if no filesystem domain matched.
            domain = cls._match_first(normalized, _FS_PATTERNS)
            if domain != TargetDomain.UNKNOWN:
                return domain
            domain = cls._match_first(normalized, _OFF_PATTERNS)
            if domain != TargetDomain.UNKNOWN:
                return domain
            return TargetDomain.UNKNOWN

        # No hint — try all pattern sets in order:
        # 1. HA entities (entity IDs have distinctive format)
        # 2. Office (Graph API URLs, file extensions)
        # 3. Filesystem (broadest patterns)
        # 4. Commands (if nothing else matches)
        for pattern_set in [_HA_PATTERNS, _OFF_PATTERNS, _FS_PATTERNS, _CMD_PATTERNS]:
            domain = cls._match_first(normalized, pattern_set)
            if domain != TargetDomain.UNKNOWN:
                return domain

        return TargetDomain.UNKNOWN

    @classmethod
    def classify_for_legacy(cls, action_type: str, target: str) -> TargetDomain:
        """Convenience method for classifying with a legacy action type string.

        Maps legacy action types to the appropriate hint for pattern matching.
        """
        hint_map = {
            'READ': 'file', 'WRITE': 'file', 'DELETE': 'file', 'LIST': 'file',
            'FILE_READ': 'file', 'FILE_WRITE': 'file',
            'FILE_DELETE': 'file', 'DIRECTORY_LIST': 'file',
            'COMMAND': 'command', 'COMMAND_EXEC': 'command',
            'API_QUERY': 'api', 'LOCAL_API_QUERY': 'api',
            'DOCUMENT_OP': 'office',
        }
        hint = hint_map.get(action_type)
        return cls.classify(target, hint=hint, action_type=action_type)

    @staticmethod
    def _match_first(target: str, patterns) -> TargetDomain:
        """Return the first matching domain, or UNKNOWN."""
        for regex, domain in patterns:
            if regex.search(target):
                return domain
        return TargetDomain.UNKNOWN
