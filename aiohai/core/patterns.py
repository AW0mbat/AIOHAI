"""
AIOHAI Security Patterns — Single Source of Truth
===================================================
All regex patterns used for security validation across the proxy.
Previously duplicated between proxy/aiohai_proxy.py and
security/security_components.py. Now centralized here.

Import from: aiohai.core.patterns
"""

# =============================================================================
# PATH PATTERNS
# =============================================================================

# HARD BLOCKED: Never accessible regardless of approval tier.
# Attack infrastructure, OS internals, and credential stores.
BLOCKED_PATH_PATTERNS = [
    # SSH / cloud infrastructure credentials
    r'(?i).*[/\\]\.ssh[/\\].*', r'(?i).*[/\\]\.gnupg[/\\].*', r'(?i).*[/\\]\.aws[/\\].*',
    r'(?i).*[/\\]\.azure[/\\].*', r'(?i).*[/\\]\.kube[/\\].*', r'(?i).*[/\\]\.docker[/\\].*',
    r'(?i).*\.git-credentials.*', r'(?i).*\.npmrc$', r'(?i).*\.pypirc$', r'(?i).*\.netrc$',
    r'(?i).*id_rsa.*', r'(?i).*id_ed25519.*', r'(?i).*id_ecdsa.*', r'(?i).*authorized_keys.*',
    # Browser credential databases
    r'(?i).*login\s*data.*', r'(?i).*web\s*data.*', r'(?i).*local\s*state.*',
    r'(?i).*logins\.json.*',
    # Key files
    r'(?i).*\.pem$', r'(?i).*\.key$', r'(?i).*\.pfx$', r'(?i).*\.p12$', r'(?i).*\.keystore$',
    # Environment secret files
    r'(?i).*\.env$', r'(?i).*\.env\..*', r'(?i).*\.envrc$',
    # OS internals (SAM, SECURITY, Active Directory)
    r'(?i).*[/\\]windows[/\\]system32[/\\]config[/\\].*',
    r'(?i).*[/\\]sam$', r'(?i).*[/\\]security$', r'(?i).*[/\\]system$', r'(?i).*ntds\.dit.*',
    # Persistence locations
    r'(?i).*\\start\s*menu\\programs\\startup.*',
    r'(?i).*\\appdata\\roaming\\microsoft\\windows\\start\s*menu.*',
    # Office persistence / template directories (macro backdoor vectors)
    r'(?i).*\\appdata\\roaming\\microsoft\\templates.*',
    r'(?i).*\\appdata\\roaming\\microsoft\\excel\\xlstart.*',
    r'(?i).*\\appdata\\roaming\\microsoft\\word\\startup.*',
    r'(?i).*\\appdata\\roaming\\microsoft\\addins.*',
    r'(?i).*normal\.dotm$',
    r'(?i).*personal\.xlsb$',
    # Outlook data stores
    r'(?i).*\.pst$', r'(?i).*\.ost$',
    # Office MRU tracking
    r'(?i).*\\appdata\\roaming\\microsoft\\office\\recent.*',
    # COM add-in directories
    r'(?i).*\\appdata\\local\\microsoft\\office.*\\addins.*',
]

# TIER 3: Accessible ONLY via FIDO2 hardware approval.
# Sensitive personal data with legitimate AI use cases.
TIER3_PATH_PATTERNS = [
    # Financial software and data
    r'(?i)turbotax', r'(?i)taxact', r'(?i)h&r\s*block', r'(?i)taxcut',
    r'(?i)\\tax\s*return', r'(?i)\\taxes\\',
    r'(?i)quicken', r'(?i)\\qdata\\', r'(?i)\.qdf$', r'(?i)\.qfx$',
    r'(?i)quickbooks', r'(?i)\.qbw$', r'(?i)\.qbb$',
    r'(?i)\\mint\\', r'(?i)\\ynab\\', r'(?i)\.ynab4$',
    r'(?i)gnucash', r'(?i)moneydance',
    r'(?i)bank.*statement', r'(?i)financial.*record',
    r'(?i)\\fidelity\\', r'(?i)\\schwab\\', r'(?i)\\vanguard\\',
    # Password manager vaults
    r'(?i).*\.kdbx$', r'(?i).*keepass.*', r'(?i).*1password.*', r'(?i).*bitwarden.*',
    r'(?i)passwords?\.csv', r'(?i)passwords?\.xlsx?',
    # Cryptocurrency wallets
    r'(?i)wallet\.dat', r'(?i)\\bitcoin\\', r'(?i)\\ethereum\\',
    r'(?i)seed.*phrase', r'(?i)recovery.*phrase',
    # Generic credential/secret files
    r'(?i).*credential.*', r'(?i).*password.*', r'(?i).*passwd.*', r'(?i).*secret.*',
    # Browser cookies
    r'(?i).*cookies.*',
]

# =============================================================================
# COMMAND PATTERNS
# =============================================================================

# Master list: (regex, severity, CWE, description)
# severity is a string matching Severity enum names to avoid importing types.py.
# BLOCKED_COMMAND_PATTERNS is derived from this list automatically.
# StaticSecurityAnalyzer imports this directly for scoring/reporting.
COMMAND_ANALYSIS_PATTERNS = [
    # PowerShell encoded — ALL abbreviations
    (r'(?i)-e\s+[A-Za-z0-9+/=]{10,}', 'CRITICAL', 'CWE-78', 'Encoded command'),
    (r'(?i)-en\s+[A-Za-z0-9+/=]{10,}', 'CRITICAL', 'CWE-78', 'Encoded command'),
    (r'(?i)-enc\s+[A-Za-z0-9+/=]{10,}', 'CRITICAL', 'CWE-78', 'Encoded command'),
    (r'(?i)-enco', 'CRITICAL', 'CWE-78', 'Encoded command prefix'),
    (r'(?i)-encod', 'CRITICAL', 'CWE-78', 'Encoded command prefix'),
    (r'(?i)-encode', 'CRITICAL', 'CWE-78', 'Encoded command prefix'),
    (r'(?i)-encodedcommand', 'CRITICAL', 'CWE-78', 'Encoded command'),
    # PowerShell dangerous
    (r'(?i)invoke-expression', 'CRITICAL', 'CWE-78', 'PowerShell IEX'),
    (r'(?i)\biex\s*[\(\"\'$]', 'CRITICAL', 'CWE-78', 'PowerShell IEX alias'),
    (r'(?i)\[scriptblock\]::create', 'CRITICAL', 'CWE-78', 'Dynamic script block'),
    (r'(?i)add-type.*-typedefinition', 'HIGH', 'CWE-78', 'C# compilation'),
    (r'(?i)new-object.*net\.webclient', 'HIGH', 'CWE-78', 'WebClient instantiation'),
    (r'(?i)downloadstring', 'CRITICAL', 'CWE-78', 'Remote download + execute'),
    (r'(?i)downloadfile', 'HIGH', 'CWE-78', 'File download'),
    (r'(?i)invoke-webrequest.*\|\s*iex', 'CRITICAL', 'CWE-78', 'Download + execute'),
    (r'(?i)start-bitstransfer', 'HIGH', 'CWE-78', 'BITS download'),
    (r'(?i)-windowstyle\s+hidden', 'HIGH', 'CWE-78', 'Hidden window'),
    (r'(?i)\[convert\]::frombase64', 'HIGH', 'CWE-506', 'Base64 decoding'),
    (r'(?i)frombase64string', 'HIGH', 'CWE-506', 'Base64 decoding'),
    (r'(?i)\[System\.Reflection\.Assembly\]::Load', 'CRITICAL', 'CWE-78', 'Assembly loading'),
    # Defense evasion
    (r'(?i)set-mppreference.*-disable', 'CRITICAL', 'CWE-78', 'Defender disable'),
    (r'(?i)add-mppreference.*-exclusion', 'HIGH', 'CWE-78', 'Defender exclusion'),
    (r'(?i)-executionpolicy\s+(bypass|unrestricted)', 'CRITICAL', 'CWE-78', 'Policy bypass'),
    (r'(?i)amsiutils', 'CRITICAL', 'CWE-78', 'AMSI bypass'),
    (r'(?i)amsiinitfailed', 'CRITICAL', 'CWE-78', 'AMSI bypass'),
    (r'(?i)\[ref\]\.assembly\.gettype.*amsi', 'CRITICAL', 'CWE-78', 'AMSI bypass via reflection'),
    # CMD dangerous
    (r'(?i)certutil.*-urlcache', 'CRITICAL', 'CWE-78', 'certutil download'),
    (r'(?i)certutil.*-encode', 'HIGH', 'CWE-506', 'certutil encode'),
    (r'(?i)certutil.*-decode', 'HIGH', 'CWE-506', 'certutil decode'),
    (r'(?i)bitsadmin.*/transfer', 'HIGH', 'CWE-78', 'BITS download'),
    (r'(?i)\bmshta\b', 'CRITICAL', 'CWE-78', 'MSHTA execution'),
    (r'(?i)rundll32.*javascript', 'CRITICAL', 'CWE-78', 'rundll32 JavaScript'),
    (r'(?i)regsvr32.*/s', 'HIGH', 'CWE-78', 'Silent DLL registration'),
    (r'(?i)\bbcdedit\b', 'CRITICAL', 'CWE-78', 'Boot config modification'),
    (r'(?i)\bdiskpart\b', 'CRITICAL', 'CWE-78', 'Disk partition modification'),
    (r'(?i)format\s+[a-z]:', 'CRITICAL', 'CWE-78', 'Drive formatting'),
    # Persistence — COMPREHENSIVE
    (r'(?i)schtasks.*/create', 'HIGH', 'CWE-78', 'Scheduled task creation'),
    (r'(?i)\bsc\s+create\b', 'HIGH', 'CWE-78', 'Service creation'),
    (r'(?i)new-service', 'HIGH', 'CWE-78', 'PowerShell service creation'),
    (r'(?i)reg\s+add.*\\run', 'HIGH', 'CWE-78', 'Registry Run key'),
    (r'(?i)new-itemproperty.*\\run', 'HIGH', 'CWE-78', 'Registry Run via PowerShell'),
    (r'(?i)set-wmiinstance.*__eventfilter', 'CRITICAL', 'CWE-78', 'WMI event subscription'),
    (r'(?i)\\start\s*menu\\programs\\startup', 'HIGH', 'CWE-78', 'Startup folder persistence'),
    (r'(?i)\$profile', 'HIGH', 'CWE-78', 'PowerShell profile modification'),
    (r'(?i)\\currentversion\\explorer\\shell', 'HIGH', 'CWE-78', 'Shell folders modification'),
    (r'(?i)userinit', 'HIGH', 'CWE-78', 'Userinit key modification'),
    (r'(?i)winlogon\\shell', 'HIGH', 'CWE-78', 'Winlogon shell modification'),
    # WMI abuse
    (r'(?i)wmic.*process.*call.*create', 'HIGH', 'CWE-78', 'WMI process creation'),
    (r'(?i)invoke-wmimethod.*win32_process', 'HIGH', 'CWE-78', 'WMI process via PowerShell'),
    # Credential theft
    (r'(?i)mimikatz', 'CRITICAL', 'CWE-78', 'Mimikatz credential dump'),
    (r'(?i)sekurlsa', 'CRITICAL', 'CWE-78', 'Credential dumping'),
    (r'(?i)procdump.*lsass', 'CRITICAL', 'CWE-78', 'LSASS process dump'),
    # Privilege escalation
    (r'(?i)net\s+user.*\/add', 'HIGH', 'CWE-78', 'User creation'),
    (r'(?i)net\s+localgroup.*admin', 'CRITICAL', 'CWE-78', 'Admin group modification'),
    # Obfuscation patterns
    (r'(?i)bytes\.fromhex', 'HIGH', 'CWE-506', 'Hex-encoded payload'),
    (r'(?i)codecs\.decode\s*\([^)]+,\s*["\']rot', 'HIGH', 'CWE-506', 'ROT13 obfuscation'),
    (r'(?i)\[char\]\s*\d+(?:\s*\+\s*\[char\]\s*\d+){3,}', 'HIGH', 'CWE-506', 'PowerShell char assembly'),
    (r'(?i)chr\s*\(\s*\d+\s*\)(?:\s*\+\s*chr\s*\(\s*\d+\s*\)){3,}', 'HIGH', 'CWE-506', 'Char code assembly'),
    (r'(?i)zlib\.decompress', 'CRITICAL', 'CWE-506', 'Compressed payload'),
    (r'(?i)gzip\.decompress', 'CRITICAL', 'CWE-506', 'Compressed payload'),
    (r'(?i)bz2\.decompress', 'CRITICAL', 'CWE-506', 'Compressed payload'),
    (r'(?i)lzma\.decompress', 'CRITICAL', 'CWE-506', 'Compressed payload'),
    # Clipboard — COMPREHENSIVE
    (r'(?i)\bclip\b', 'MEDIUM', 'CWE-200', 'Clipboard access'),
    (r'(?i)set-clipboard', 'MEDIUM', 'CWE-200', 'Clipboard write'),
    (r'(?i)get-clipboard', 'MEDIUM', 'CWE-200', 'Clipboard read'),
    (r'(?i)\[System\.Windows\.Forms\.Clipboard\]', 'MEDIUM', 'CWE-200', '.NET Clipboard access'),
    (r'(?i)Add-Type.*System\.Windows\.Forms.*Clipboard', 'MEDIUM', 'CWE-200', 'Clipboard type loading'),
    (r'(?i)\bpyperclip\b', 'MEDIUM', 'CWE-200', 'Python clipboard module'),
    (r'(?i)\bxerox\b', 'MEDIUM', 'CWE-200', 'Python clipboard module'),
    (r'(?i)import\s+pyperclip', 'MEDIUM', 'CWE-200', 'Clipboard import'),
    (r'(?i)import\s+clipboard', 'MEDIUM', 'CWE-200', 'Clipboard import'),
    (r'(?i)Clipboard\.SetText', 'MEDIUM', 'CWE-200', '.NET Clipboard write'),
    (r'(?i)Clipboard\.GetText', 'MEDIUM', 'CWE-200', '.NET Clipboard read'),
    (r'(?i)OpenClipboard', 'MEDIUM', 'CWE-200', 'Win32 Clipboard access'),
    (r'(?i)SetClipboardData', 'MEDIUM', 'CWE-200', 'Win32 Clipboard write'),
    (r'(?i)GetClipboardData', 'MEDIUM', 'CWE-200', 'Win32 Clipboard read'),
    (r'(?i)\bxclip\b', 'MEDIUM', 'CWE-200', 'Linux clipboard'),
    (r'(?i)\bxsel\b', 'MEDIUM', 'CWE-200', 'Linux clipboard'),
]

# Flat list derived from COMMAND_ANALYSIS_PATTERNS — used by CommandValidator
# for hard-blocking (no severity needed, just block/allow).
BLOCKED_COMMAND_PATTERNS = [p[0] for p in COMMAND_ANALYSIS_PATTERNS]

# UAC bypass patterns
UAC_BYPASS_PATTERNS = [
    r'(?i)hkcu\\software\\classes\\ms-settings',
    r'(?i)hkcu\\software\\classes\\mscfile',
    r'(?i)hkcu\\software\\microsoft\\windows\\currentversion\\app\s*paths',
    r'(?i)hkcu\\environment.*windir',
]

# =============================================================================
# INJECTION & SANITIZATION PATTERNS
# =============================================================================

# Prompt injection patterns
INJECTION_PATTERNS = [
    # Direct override
    r'(?i)ignore\s+(all\s+)?(previous|prior|earlier|above)\s+(instructions?|rules?|guidelines?)',
    r'(?i)disregard\s+(all\s+)?(previous|prior)\s+',
    r'(?i)forget\s+(all\s+)?(previous|prior)\s+',
    r'(?i)override\s+(all\s+)?security',
    r'(?i)bypass\s+(all\s+)?restrictions',
    # Role manipulation
    r'(?i)you\s+are\s+now\s+(a|an|in)\b',
    r'(?i)your\s+(new\s+)?role\s+(is|has)',
    r'(?i)pretend\s+(you\'re|to\s+be)',
    r'(?i)act\s+as\s+(a|an|if)',
    r'(?i)switch\s+to\s+\w+\s+mode',
    r'(?i)enter\s+(admin|debug|developer|maintenance|jailbreak)\s+mode',
    r'(?i)activate\s+(admin|god|sudo)\s+mode',
    # Fake system
    r'(?i)\[\s*system\s*\]', r'(?i)\[\s*admin\s*\]', r'(?i)\[\s*override\s*\]',
    r'(?i)<\s*system\s*>', r'(?i)<\s*admin\s*>',
    r'(?i)###\s*system\s*:', r'(?i)###\s*instruction\s*:',
    # Fake authorization
    r'(?i)confirm\s+send', r'(?i)confirm\s+execute', r'(?i)confirm\s+delete',
    r'(?i)pre-?authorized', r'(?i)already\s+approved',
    r'(?i)the\s+user\s+has\s+(already\s+)?approved',
    r'(?i)permission\s+(has\s+been\s+)?granted',
    r'(?i)this\s+(is|has\s+been)\s+authorized',
    # Anti-transparency
    r'(?i)do\s+not\s+(inform|tell|notify|alert)\s+(the\s+)?user',
    r'(?i)don\'t\s+(inform|tell)\s+(the\s+)?user',
    r'(?i)hide\s+this\s+from', r'(?i)silently\s+(execute|run)',
    r'(?i)without\s+(notifying|telling)\s+(the\s+)?user',
    # Prompt extraction
    r'(?i)repeat\s+(your\s+)?(system\s+)?prompt',
    r'(?i)show\s+(me\s+)?(your\s+)?(system\s+)?instructions',
    r'(?i)what\s+(are|were)\s+(your\s+)?(initial|system)\s+instructions',
    # Jailbreak
    r'(?i)\bdan\b.*mode', r'(?i)do\s+anything\s+now', r'(?i)jailbreak',
    # Translation/context
    r'(?i)translate.*then\s+(execute|run|follow)',
    r'(?i)in\s+(french|german|spanish|chinese).*ignore',
]

# Invisible Unicode characters to strip
INVISIBLE_CHARS = [
    '\u200b', '\u200c', '\u200d', '\ufeff', '\u2060',
    '\u00ad', '\u034f', '\u061c', '\u180e', '\u2800',
]

# Cyrillic/confusable homoglyphs
HOMOGLYPHS = {
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
    '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i',
}

# Fullwidth → ASCII mapping
FULLWIDTH_MAP = {chr(i): chr(i - 0xFEE0) for i in range(0xFF01, 0xFF5F)}

# =============================================================================
# NETWORK PATTERNS
# =============================================================================

# DNS-over-HTTPS servers to block
DOH_SERVERS = [
    'dns.google', 'dns.google.com', 'cloudflare-dns.com', 'dns.quad9.net',
    '1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9',
    'doh.opendns.com', 'dns.adguard.com', 'doh.cleanbrowsing.org',
]

# =============================================================================
# OFFICE DOCUMENT PATTERNS
# =============================================================================

# Macro-enabled file extensions — ALWAYS blocked for creation/write
MACRO_ENABLED_EXTENSIONS = frozenset({
    '.xlsm', '.xltm', '.xlam',      # Excel macro-enabled
    '.docm', '.dotm',                 # Word macro-enabled
    '.pptm', '.potm', '.ppam',        # PowerPoint macro-enabled
    '.xlsb',                           # Excel binary (can contain macros)
})

# Safe Office extensions for creation
SAFE_OFFICE_EXTENSIONS = frozenset({
    '.docx', '.xlsx', '.pptx',        # Standard Office
    '.dotx', '.xltx', '.potx',        # Templates (no macros)
    '.csv', '.tsv', '.txt',            # Plain data
    '.pdf',                            # Read-only output
})

# Extensions to content-scan for PII/formulas
OFFICE_SCANNABLE_EXTENSIONS = frozenset({
    '.docx', '.xlsx', '.pptx', '.csv', '.tsv',
    '.dotx', '.xltx', '.potx', '.doc', '.xls', '.ppt',
})

# Excel formulas that can execute commands or exfiltrate data
BLOCKED_EXCEL_FORMULAS = [
    r'(?i)=\s*WEBSERVICE\s*\(',
    r'(?i)=\s*FILTERXML\s*\(',
    r'(?i)=\s*RTD\s*\(',
    r'(?i)=\s*SQL\.REQUEST\s*\(',
    r'(?i)=\s*CALL\s*\(',
    r'(?i)=\s*REGISTER\.ID\s*\(',
    # DDE command execution
    r'(?i)=\s*\w+\|[\'\"]?/[Cc]',
    r'(?i)=\s*cmd\s*\|',
    r'(?i)=\s*msexcel\s*\|',
    r'(?i)=\s*dde\s*\(',
    # External references (UNC paths)
    r'(?i)=\s*[\'\"]\\\\[^\\]+\\',
]

# Embedded file types blocked in Office documents
BLOCKED_EMBED_EXTENSIONS = frozenset({
    '.exe', '.dll', '.bat', '.cmd', '.ps1', '.psm1',
    '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh',
    '.scr', '.com', '.msi', '.msp', '.cpl', '.hta',
    '.inf', '.reg', '.rgs', '.sct', '.shb', '.pif',
})

# =============================================================================
# GRAPH API PATTERNS
# =============================================================================

# Graph API endpoints that are ALWAYS blocked
BLOCKED_GRAPH_ENDPOINTS = [
    r'/me/sendMail',
    r'/me/messages/.*/send',
    r'/me/drive/items/.*/invite',
    r'/me/drive/items/.*/permissions',
    r'/groups/.*/drive',
    r'/admin/',
    r'/directory/',
    r'/users/.*/memberOf',
    r'/organization/',
]

# Graph API scopes that are too broad
BLOCKED_GRAPH_SCOPES = frozenset({
    'Directory.ReadWrite.All',
    'Mail.Send',
    'Mail.ReadWrite',
    'Sites.FullControl.All',
    'Group.ReadWrite.All',
    'User.ReadWrite.All',
    'RoleManagement.ReadWrite.Directory',
})

# =============================================================================
# DOCKER PATTERNS
# =============================================================================

# Trusted Docker registries for smart home stack
TRUSTED_DOCKER_REGISTRIES = [
    'ghcr.io/home-assistant/',
    'ghcr.io/blakeblackshear/',
    'ghcr.io/koush/',
    'ghcr.io/esphome/',
    'docker.io/library/',
    'docker.io/homeassistant/',
    'docker.io/linuxserver/',
    'docker.io/portainer/',
    'lscr.io/linuxserver/',
    'homeassistant/',
    'eclipse-mosquitto',
    'postgres:',
    'redis:',
    'mariadb:',
    'mysql:',
    'mongo:',
    'influxdb:',
    'grafana/',
]
