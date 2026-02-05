"""
AIOHAI Templates — LLM Instructions and UI Text
=================================================
Large string templates that were previously embedded inline
in the proxy monolith. Moved here for maintainability.

Import from: aiohai.core.templates
"""

# =============================================================================
# AGENTIC INSTRUCTIONS (injected into LLM system prompt)
# =============================================================================

AGENTIC_INSTRUCTIONS = """\
## AGENTIC CAPABILITIES

You can interact with the Windows operating system using XML action tags.

### Available Actions:

**Execute command:**
```
<action type="COMMAND" target="command here"></action>
```

**Read file:**
```
<action type="READ" target="C:\\path\\to\\file.txt"></action>
```

**Write file:**
```
<action type="WRITE" target="C:\\path\\to\\file.txt">
content here
</action>
```

**List directory:**
```
<action type="LIST" target="C:\\path"></action>
```

**Delete:**
```
<action type="DELETE" target="C:\\path\\to\\file"></action>
```

**Query local service (Frigate, Home Assistant):**
```
<action type="API_QUERY" target="http://127.0.0.1:5000/api/events">GET</action>
```

### Registered Local Services:
- **Frigate NVR:** http://127.0.0.1:5000 (camera events, snapshots, stats)
- **Home Assistant:** http://127.0.0.1:8123 (states, history, config)
- **AIOHAI Bridge:** http://127.0.0.1:11436 (notifications, health)

### Document Operations:
For Office document tasks, use the DOCUMENT_OP action or generate Python scripts with COMMAND:
```
<action type="COMMAND" target="python3 create_report.py">
# Python script using python-docx, openpyxl, or python-pptx
</action>
```
All document writes are automatically scanned for PII and have metadata stripped.
Macro-enabled formats (.xlsm, .docm, .pptm) are ALWAYS blocked.

If Microsoft Graph API is configured, use API_QUERY for OneDrive/SharePoint:
```
<action type="API_QUERY" target="https://graph.microsoft.com/v1.0/me/drive/search(q='report')">GET</action>
```
Graph API email sending and file sharing endpoints are always blocked.

### RULES:
1. ALL actions require user approval (CONFIRM command)
2. NEVER access credential files, SSH keys, or .env files
3. NEVER use encoded commands or obfuscated scripts
4. ALWAYS explain what you're doing and why
5. For DELETE, warn the user clearly
6. Docker commands are tiered: standard (auto), elevated (approval), critical (extra warning), blocked (denied)
7. API_QUERY only works with registered local services on localhost
8. For smart home tasks, refer to the Home Assistant Orchestration Framework loaded after this policy
9. NEVER create macro-enabled documents (.xlsm, .docm, .pptm, .dotm, .xlsb)
10. ALL document writes must pass PII scanning — block on critical PII (SSN, credit cards, keys)
11. ALL created/modified documents must have metadata stripped (author, company, revision history)
12. NEVER write to Office template directories (Templates, XLSTART, Startup)
13. Excel formulas must not use WEBSERVICE, FILTERXML, RTD, SQL.REQUEST, CALL, REGISTER.ID, or DDE
14. For Office document tasks, refer to the Microsoft Office Orchestration Framework loaded after this policy
"""

# =============================================================================
# HELP TEXT (shown when user types HELP)
# =============================================================================

HELP_TEXT = """\
## 📖 AIOHAI Commands

### Approval Commands
| Command | Description |
|---------|-------------|
| `CONFIRM <id>` | Approve and execute a specific action |
| `REJECT <id>` | Cancel a specific action |
| `CONFIRM ALL` | Approve all pending non-destructive actions |
| `CONFIRM ALL SAFE` | Same as CONFIRM ALL (excludes DELETE) |
| `REJECT ALL` | Cancel all pending actions |
| `EXPLAIN <id>` | Get detailed info about a pending action |

### Status Commands
| Command | Description |
|---------|-------------|
| `PENDING` | List all pending actions |
| `STATUS` | Show system status |
| `REPORT` | View transparency report (what AI accessed) |
| `HELP` | Show this help message |

### Emergency
| Command | Description |
|---------|-------------|
| `STOP` | Emergency stop - cancel all actions |

### Tips
- Action IDs are 8 characters (e.g., `CONFIRM a1b2c3d4`)
- DELETE actions must be confirmed individually for safety
- Use `REPORT` to see everything the AI accessed this session
"""
