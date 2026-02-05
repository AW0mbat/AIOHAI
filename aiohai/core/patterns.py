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

# Financial path patterns (superset used by SensitiveOperationDetector)
FINANCIAL_PATH_PATTERNS = [
    # Tax software
    r'(?i)turbotax', r'(?i)taxact', r'(?i)h&r\s*block', r'(?i)taxcut',
    r'(?i)\\tax\s*return', r'(?i)\\taxes\\',
    # Financial software
    r'(?i)quicken', r'(?i)\\qdata\\', r'(?i)\.qdf$', r'(?i)\.qfx$',
    r'(?i)quickbooks', r'(?i)\.qbw$', r'(?i)\.qbb$',
    r'(?i)\\mint\\', r'(?i)\\ynab\\', r'(?i)\.ynab4$',
    r'(?i)gnucash', r'(?i)moneydance', r'(?i)\\money\\',
    # Banking/financial exports
    r'(?i)bank.*statement', r'(?i)financial.*record',
    r'(?i)account.*export', r'(?i)transaction.*history',
    r'(?i)passwords?\.csv', r'(?i)passwords?\.xlsx?',
    r'(?i)password.*export', r'(?i)credential.*export',
    r'(?i)\\statements?\\', r'(?i)\\banking\\',
    # Investment
    r'(?i)\\fidelity\\', r'(?i)\\schwab\\', r'(?i)\\vanguard\\',
    r'(?i)\\etrade\\', r'(?i)\\robinhood\\',
    r'(?i)brokerage.*statement', r'(?i)investment.*record',
    r'(?i)\\portfolio\\',
    # Crypto wallets
    r'(?i)wallet\.dat', r'(?i)\\bitcoin\\', r'(?i)\\ethereum\\',
    r'(?i)\\crypto\\', r'(?i)seed.*phrase', r'(?i)recovery.*phrase',
    # Insurance/medical
    r'(?i)insurance.*claim', r'(?i)medical.*bill',
    r'(?i)\\insurance\\', r'(?i)\\claims\\',
]

# =============================================================================
# COMMAND PATTERNS
# =============================================================================

# Commands that are ALWAYS blocked
BLOCKED_COMMAND_PATTERNS = [
    # PowerShell encoded — ALL abbreviations
    r'(?i)-e\s+[A-Za-z0-9+/=]{10,}', r'(?i)-en\s+[A-Za-z0-9+/=]{10,}',
    r'(?i)-enc\s+[A-Za-z0-9+/=]{10,}', r'(?i)-enco', r'(?i)-encod',
    r'(?i)-encode', r'(?i)-encodedcommand',
    # PowerShell dangerous
    r'(?i)invoke-expression', r'(?i)\biex\s*[\(\"\'$]',
    r'(?i)\[scriptblock\]::create', r'(?i)add-type.*-typedefinition',
    r'(?i)new-object.*net\.webclient', r'(?i)downloadstring', r'(?i)downloadfile',
    r'(?i)invoke-webrequest.*\|\s*iex', r'(?i)start-bitstransfer',
    r'(?i)-windowstyle\s+hidden', r'(?i)\[convert\]::frombase64',
    r'(?i)\[System\.Reflection\.Assembly\]::Load',
    # Defense evasion
    r'(?i)set-mppreference.*-disable', r'(?i)add-mppreference.*-exclusion',
    r'(?i)-executionpolicy\s+(bypass|unrestricted)',
    r'(?i)amsiutils', r'(?i)amsiinitfailed', r'(?i)\[ref\]\.assembly\.gettype.*amsi',
    # CMD dangerous
    r'(?i)certutil.*-urlcache', r'(?i)certutil.*-encode', r'(?i)certutil.*-decode',
    r'(?i)bitsadmin.*/transfer', r'(?i)\bmshta\b',
    r'(?i)rundll32.*javascript', r'(?i)regsvr32.*/s',
    r'(?i)\bbcdedit\b', r'(?i)\bdiskpart\b', r'(?i)format\s+[a-z]:',
    # Persistence — COMPREHENSIVE
    r'(?i)schtasks.*/create', r'(?i)\bsc\s+create\b', r'(?i)new-service',
    r'(?i)reg\s+add.*\\run', r'(?i)new-itemproperty.*\\run',
    r'(?i)set-wmiinstance.*__eventfilter',
    r'(?i)\\start\s*menu\\programs\\startup',
    r'(?i)\$profile',
    r'(?i)\\currentversion\\explorer\\shell',
    r'(?i)userinit', r'(?i)winlogon\\shell',
    # WMI abuse
    r'(?i)wmic.*process.*call.*create', r'(?i)invoke-wmimethod.*win32_process',
    # Credential theft
    r'(?i)mimikatz', r'(?i)sekurlsa', r'(?i)procdump.*lsass',
    # Privilege escalation
    r'(?i)net\s+user.*\/add', r'(?i)net\s+localgroup.*admin',
    # Obfuscation patterns
    r'(?i)bytes\.fromhex',
    r'(?i)codecs\.decode\s*\([^)]+,\s*["\']rot',
    r'(?i)\[char\]\s*\d+(?:\s*\+\s*\[char\]\s*\d+){3,}',
    r'(?i)chr\s*\(\s*\d+\s*\)(?:\s*\+\s*chr\s*\(\s*\d+\s*\)){3,}',
    r'(?i)zlib\.decompress', r'(?i)gzip\.decompress',
    r'(?i)bz2\.decompress', r'(?i)lzma\.decompress',
    # Clipboard — COMPREHENSIVE
    r'(?i)\bclip\b', r'(?i)set-clipboard', r'(?i)get-clipboard',
    r'(?i)\[System\.Windows\.Forms\.Clipboard\]',
    r'(?i)Add-Type.*System\.Windows\.Forms.*Clipboard',
    r'(?i)\bpyperclip\b', r'(?i)\bxerox\b',
    r'(?i)import\s+pyperclip', r'(?i)import\s+clipboard',
    r'(?i)Clipboard\.SetText', r'(?i)Clipboard\.GetText',
    r'(?i)OpenClipboard', r'(?i)SetClipboardData', r'(?i)GetClipboardData',
    r'(?i)\bxclip\b', r'(?i)\bxsel\b',
]

# UAC bypass patterns
UAC_BYPASS_PATTERNS = [
    r'(?i)hkcu\\software\\classes\\ms-settings',
    r'(?i)hkcu\\software\\classes\\mscfile',
    r'(?i)hkcu\\software\\microsoft\\windows\\currentversion\\app\s*paths',
    r'(?i)hkcu\\environment.*windir',
]

# Clipboard blocking patterns (extended set used by SensitiveOperationDetector)
CLIPBOARD_BLOCK_PATTERNS = [
    # PowerShell clipboard
    r'(?i)\bclip\b', r'(?i)set-clipboard', r'(?i)get-clipboard',
    r'(?i)\[System\.Windows\.Forms\.Clipboard\]',
    r'(?i)Add-Type.*System\.Windows\.Forms.*Clipboard',
    # Python clipboard modules
    r'(?i)\bpyperclip\b', r'(?i)\bxerox\b', r'(?i)\bclipboard\b',
    r'(?i)import\s+pyperclip', r'(?i)import\s+clipboard',
    r'(?i)from\s+xerox\s+import',
    # .NET clipboard
    r'(?i)System\.Windows\.Clipboard',
    r'(?i)Clipboard\.SetText', r'(?i)Clipboard\.GetText',
    r'(?i)Clipboard\.SetData', r'(?i)Clipboard\.GetData',
    # Win32 API
    r'(?i)OpenClipboard', r'(?i)SetClipboardData', r'(?i)GetClipboardData',
    r'(?i)EmptyClipboard', r'(?i)CloseClipboard',
    # Linux clipboard
    r'(?i)\bxclip\b', r'(?i)\bxsel\b',
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
