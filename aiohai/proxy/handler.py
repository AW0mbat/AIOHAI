#!/usr/bin/env python3
"""
Proxy Handler — HTTP request handling with full security integration.

Handles incoming HTTP requests from Open WebUI, intercepts chat messages,
processes LLM responses for action tags, manages the approval workflow,
and forwards clean requests to Ollama.

Phase 5 extraction from proxy/aiohai_proxy.py.
"""

import json
import os
import re
import urllib.request
import urllib.error
from datetime import datetime
from http.server import BaseHTTPRequestHandler
from typing import Dict, Optional, Tuple

from aiohai.core.types import AlertSeverity, Verdict
from aiohai.core.patterns import OFFICE_SCANNABLE_EXTENSIONS
from aiohai.core.templates import HELP_TEXT
from aiohai.proxy.action_parser import ActionParser

__all__ = ['UnifiedProxyHandler']


class UnifiedProxyHandler(BaseHTTPRequestHandler):
    """HTTP handler with full security integration and transparency."""

    # Class-level attributes wired by UnifiedSecureProxy.start()
    config = None
    logger = None
    alerts = None
    sanitizer = None
    executor = None
    approval_mgr = None
    security_policy: str = ""
    agentic_instructions: str = ""
    dual_verifier = None
    pii_protector = None
    transparency_tracker = None
    credential_redactor = None
    sensitive_detector = None
    api_query_executor = None
    graph_api_registry = None
    ollama_breaker = None
    hsm_manager = None
    fido2_client = None
    fido2_server = None
    integrity_verifier = None

    def log_message(self, format, *args):
        pass  # Suppress default logging

    def do_GET(self):
        self._forward_request('GET')

    def do_POST(self):
        # Block all requests if policy tampering detected
        if hasattr(self, 'integrity_verifier') and self.integrity_verifier \
                and self.integrity_verifier.is_locked_down:
            self.send_response(503)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                'error': 'Service locked down due to policy integrity violation. '
                         'Restart required.'
            }).encode())
            return

        if self.path in ['/api/chat', '/api/generate']:
            self._handle_chat()
        else:
            self._forward_request('POST')

    def do_DELETE(self):
        self._forward_request('DELETE')

    def _handle_chat(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else b''

        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            self._forward_request('POST', body)
            return

        # Extract user message
        user_message = ""
        if 'prompt' in data:
            user_message = data['prompt']
        elif 'messages' in data and data['messages']:
            last = data['messages'][-1]
            if isinstance(last, dict):
                user_message = last.get('content', '')

        # Check control commands
        ctrl = self._check_control(user_message)
        if ctrl:
            self._send_chat_response(ctrl)
            return

        # Sanitize
        sanitized, warnings, trust = self.sanitizer.sanitize(user_message, "user")

        # Update message
        if 'prompt' in data:
            data['prompt'] = sanitized
        elif 'messages' in data and data['messages']:
            data['messages'][-1]['content'] = sanitized

        # Inject system prompt
        combined = self.security_policy + "\n\n" + self.agentic_instructions
        if 'system' in data:
            data['system'] = combined + "\n\n---\n\n" + data['system']
        else:
            data['system'] = combined

        # Forward to Ollama
        response = self._call_ollama(json.dumps(data).encode())
        if response is None:
            self._send_error(502, "Ollama connection failed")
            return

        # Extract AI text
        ai_text = ""
        if 'response' in response:
            ai_text = response['response']
        elif 'message' in response:
            ai_text = response['message'].get('content', '')

        # Check PII in response
        if self.pii_protector:
            pii_check = self.pii_protector.check_response_for_pii(ai_text)
            if pii_check['should_block']:
                self.logger.log_event("PII_IN_RESPONSE", AlertSeverity.HIGH,
                                     {'types': pii_check['pii_types']})
                ai_text += ("\n\n⚠️ **Warning:** This response may contain "
                            "sensitive information.")

        # Process actions
        processed = self._process_response(ai_text, user_message)

        # Update
        if 'response' in response:
            response['response'] = processed
        elif 'message' in response:
            response['message']['content'] = processed

        self._send_json_response(response)

    def _check_control(self, msg: str) -> Optional[str]:
        m = msg.strip().upper()

        # CONFIRM ALL - but not for destructive actions
        if m == 'CONFIRM ALL':
            # Check for destructive actions first
            if self.approval_mgr.has_destructive_pending():
                destructive = self.approval_mgr.get_destructive_pending()
                lines = ["⚠️ **Cannot batch-approve DELETE actions for safety.**\n"]
                lines.append(
                    "The following DELETE action(s) must be confirmed individually:\n")
                for aid, action in destructive.items():
                    lines.append(
                        f"- `CONFIRM {aid[:8]}` to delete "
                        f"`{os.path.basename(action['target'])}`")
                lines.append(
                    "\nOther non-destructive actions can be confirmed with "
                    "`CONFIRM ALL SAFE`")
                return "\n".join(lines)
            return self._execute_all_pending()

        # CONFIRM ALL SAFE - only non-destructive
        if m == 'CONFIRM ALL SAFE':
            return self._execute_all_pending(skip_destructive=True)

        # REJECT ALL
        if m == 'REJECT ALL':
            count = self.approval_mgr.clear_all()
            if count == 0:
                return "✅ No pending actions to reject."
            if self.transparency_tracker:
                self.transparency_tracker.record_approval(False)
            return f"❌ Rejected and cleared **{count}** pending action(s)."

        # CONFIRM single
        match = re.match(r'^CONFIRM\s+([A-Fa-f0-9]+)$', m)
        if match:
            if self.transparency_tracker:
                self.transparency_tracker.record_approval(True)
            return self._execute_approved(match.group(1).lower())

        # REJECT single
        match = re.match(r'^REJECT\s+([A-Fa-f0-9]+)$', m)
        if match:
            aid = match.group(1).lower()
            if self.approval_mgr.reject(aid):
                if self.transparency_tracker:
                    self.transparency_tracker.record_approval(False)
                return f"❌ Action `{aid}` rejected."
            return f"⚠️ No action: `{aid}`"

        # EXPLAIN - get details about pending action
        match = re.match(r'^EXPLAIN\s+([A-Fa-f0-9]+)$', m)
        if match:
            return self._explain_action(match.group(1).lower())

        # REPORT - transparency report
        if m == 'REPORT':
            if self.transparency_tracker:
                return self.transparency_tracker.generate_report()
            return "ℹ️ Transparency tracking not enabled for this session."

        # PENDING
        if m == 'PENDING':
            pending = self.approval_mgr.get_all_pending()
            if not pending:
                return "✅ No pending actions."
            lines = ["**Pending Actions:**\n"]
            lines.append("| Type | Target | ID | Sensitive |")
            lines.append("|------|--------|-----|-----------|")
            for aid, a in pending.items():
                short_id = aid[:8]
                icon = "🔴" if a['type'] == "DELETE" else "⚠️"
                short_target = os.path.basename(a['target']) or a['target']
                if len(short_target) > 25:
                    short_target = short_target[:22] + "..."
                sensitivity = "⚠️ Yes" if a.get('sensitivity') else "—"
                lines.append(
                    f"| {icon} {a['type']} | `{short_target}` | "
                    f"`{short_id}` | {sensitivity} |")
            lines.append("\n✅ `CONFIRM ALL` · ❌ `REJECT ALL`")
            lines.append(
                "\nOr confirm/reject individually: "
                "`CONFIRM <id>` · `REJECT <id>`")
            lines.append("\nTo see details: `EXPLAIN <id>`")
            return "\n".join(lines)

        # STOP
        if m in ['STOP', 'ABORT', 'HALT', 'EMERGENCY STOP']:
            count = self.approval_mgr.clear_all()
            self.alerts.alert(AlertSeverity.WARNING, "EMERGENCY_STOP",
                              f"Cleared {count}")
            return f"🛑 **EMERGENCY STOP** — Cleared {count} action(s)."

        # STATUS
        if m == 'STATUS':
            pending_count = len(self.approval_mgr.get_all_pending())
            stats = {
                'session': self.logger.session_id[:8],
                'blocked': self.logger.stats.get('blocked', 0),
                'pending': pending_count,
            }
            return (f"**System Status:**\n```json\n"
                    f"{json.dumps(stats, indent=2)}\n```")

        # HELP - show available commands
        if m == 'HELP':
            return self._show_help()

        return None

    def _explain_action(self, approval_id: str) -> str:
        """Provide detailed explanation of a pending action."""
        pending = self.approval_mgr.get_all_pending()

        # Find matching action
        found_action = None
        found_id = None
        for aid, action in pending.items():
            if aid.startswith(approval_id) or aid == approval_id:
                found_action = action
                found_id = aid
                break

        if not found_action:
            return f"⚠️ No pending action found with ID `{approval_id}`"

        lines = [f"## 🔍 Action Details — `{found_id[:8]}`\n"]
        lines.append(f"**Type:** {found_action['type']}")
        lines.append(f"**Target:** `{found_action['target']}`")
        lines.append(f"**Created:** {found_action['created']}")
        lines.append(f"**Expires:** {found_action['expires']}")

        # Sensitivity info
        if found_action.get('sensitivity'):
            lines.append("\n### ⚠️ Sensitivity Warning")
            for s in found_action['sensitivity']:
                lines.append(
                    f"- {s['icon']} **{s['category'].upper()}** ({s['severity']})")

        # Content preview (redacted)
        if found_action.get('content'):
            content = found_action['content']
            if self.credential_redactor:
                preview = self.credential_redactor.redact_for_preview(content, 200)
            else:
                preview = content[:200] + ('...' if len(content) > 200 else '')
            lines.append(f"\n### Content Preview (credentials redacted)")
            lines.append(f"```\n{preview}\n```")

        # What this action will do
        lines.append("\n### What This Action Will Do")
        if found_action['type'] == 'COMMAND':
            lines.append(
                f"Execute the command `{found_action['target'][:50]}` on your system.")
        elif found_action['type'] == 'READ':
            lines.append(
                f"Read and display the contents of "
                f"`{os.path.basename(found_action['target'])}`.")
        elif found_action['type'] == 'WRITE':
            lines.append(
                f"Create or overwrite the file "
                f"`{os.path.basename(found_action['target'])}`.")
        elif found_action['type'] == 'DELETE':
            lines.append(
                f"**PERMANENTLY DELETE** "
                f"`{os.path.basename(found_action['target'])}`. "
                f"This cannot be undone!")
        elif found_action['type'] == 'LIST':
            lines.append(
                f"List the contents of directory `{found_action['target']}`.")

        lines.append(
            f"\n✅ `CONFIRM {found_id[:8]}` · ❌ `REJECT {found_id[:8]}`")

        return "\n".join(lines)

    def _show_help(self) -> str:
        """Show available user commands."""
        return HELP_TEXT

    def _execute_all_pending(self, skip_destructive: bool = False) -> str:
        """Execute all pending actions in sequence, optionally skipping destructive."""
        pending = self.approval_mgr.get_all_pending()

        if not pending:
            return "✅ No pending actions to execute."

        # Filter out destructive if requested
        if skip_destructive:
            pending = {k: v for k, v in pending.items() if v['type'] != 'DELETE'}
            if not pending:
                return "✅ No non-destructive actions to execute."

        # SECURITY FIX (F-001): Separate tier3 actions — cannot be batch-approved
        tier3_actions = {k: v for k, v in pending.items()
                         if v.get('tier3_required')}
        normal_actions = {k: v for k, v in pending.items()
                          if not v.get('tier3_required')}

        results = []

        if tier3_actions:
            results.append(
                f"⚠️ **{len(tier3_actions)} action(s) require hardware approval "
                f"and cannot be batch-confirmed:**\n")
            for aid, action in tier3_actions.items():
                short_id = aid[:8]
                results.append(
                    f"  🔐 `{short_id}` **{action['type']}** — "
                    f"`{os.path.basename(action['target'])}`")
            results.append(
                f"\nConfirm these individually with `CONFIRM <id>` "
                f"(hardware key tap required).\n")

        if not normal_actions:
            if tier3_actions:
                return "\n".join(results)
            return "✅ No pending actions to execute."

        results.append(f"**Executing {len(normal_actions)} action(s)...**\n")

        success_count = 0
        fail_count = 0

        for aid, action in list(normal_actions.items()):
            short_id = aid[:8]
            atype = action['type']
            target = action['target']
            content = action['content']

            # Remove from pending
            self.approval_mgr.reject(aid)

            # Execute based on type
            if atype == 'COMMAND':
                ok, out = self.executor.execute_command(target)
                status = "✅" if ok else "❌"
                cmd_preview = target[:40] + ('...' if len(target) > 40 else '')
                results.append(
                    f"{status} `{short_id}` **COMMAND** — `{cmd_preview}`")
                if not ok:
                    results.append(f"   Error: {out[:100]}")
                    fail_count += 1
                else:
                    success_count += 1

            elif atype == 'READ':
                ok, out = self.executor.read_file(target)
                status = "✅" if ok else "❌"
                results.append(
                    f"{status} `{short_id}` **READ** — "
                    f"`{os.path.basename(target)}`")
                if ok:
                    success_count += 1
                else:
                    fail_count += 1

            elif atype == 'WRITE':
                ok, out = self.executor.write_file(target, content)
                status = "✅" if ok else "❌"
                results.append(
                    f"{status} `{short_id}` **WRITE** — "
                    f"`{os.path.basename(target)}`")
                if ok:
                    success_count += 1
                else:
                    results.append(f"   Error: {out[:100]}")
                    fail_count += 1

            elif atype == 'LIST':
                ok, out = self.executor.list_directory(target)
                status = "✅" if ok else "❌"
                results.append(
                    f"{status} `{short_id}` **LIST** — "
                    f"`{os.path.basename(target) or target}`")
                if ok:
                    success_count += 1
                else:
                    fail_count += 1

            elif atype == 'DELETE':
                # This should only execute if skip_destructive is False
                ok, out = self.executor.delete_file(target)
                status = "✅" if ok else "❌"
                results.append(
                    f"{status} `{short_id}` **DELETE** — "
                    f"`{os.path.basename(target)}`")
                if ok:
                    success_count += 1
                else:
                    results.append(f"   Error: {out[:100]}")
                    fail_count += 1

        results.append(
            f"\n**Complete:** {success_count} succeeded, {fail_count} failed")

        return "\n".join(results)

    def _require_hardware_approval(self, action: dict) -> Tuple[bool, str]:
        """Block until FIDO2 hardware approval is received, or return failure.

        Returns:
            (True, "") if hardware approval granted
            (False, user_message) if denied, timed out, or unavailable
        """
        fido2 = getattr(self, 'fido2_client', None)
        if fido2 is None:
            # FIDO2 not available — fail closed, never fall through to chat approval
            return False, (
                "❌ **Hardware approval required but FIDO2 is not available.**\n\n"
                "This action targets sensitive data and requires a physical security "
                "key or biometric verification. Please ensure your FIDO2 device is "
                "configured and the approval server is running "
                "(`--no-fido2` was not used)."
            )

        atype = action['type']
        target = action.get('target', '')

        try:
            # Create the hardware approval request
            # H-4 FIX: Sanitize content preview before sending to FIDO2 UI
            raw_preview = (action.get('content', '') or '')[:200]
            if hasattr(self, 'content_sanitizer') and self.content_sanitizer:
                sanitized_preview = self.content_sanitizer.sanitize(raw_preview)
            else:
                # Fallback: strip non-basic characters
                sanitized_preview = re.sub(
                    r'[^\w\s.,;:!?\-/\\()\'\"=+]', '', raw_preview)

            req = fido2.request_approval(
                operation_type=atype,
                target=target,
                description=f"{atype} on {os.path.basename(target)}",
                tier=3,
                metadata={'content_preview': sanitized_preview}
            )
            request_id = req.get('request_id', '')
            approval_url = req.get('approval_url', '')

            self.logger.log_event("FIDO2_REQUESTED", AlertSeverity.INFO, {
                'action_type': atype, 'target': target[:200],
                'request_id': request_id[:16],
            })

            # Poll until approved, rejected, or timeout
            timeout = getattr(self.config, 'fido2_poll_timeout', 300)
            result = fido2.wait_for_approval(
                request_id,
                timeout_seconds=timeout,
                poll_interval=1.0,
            )

            status = result.get('status', 'unknown')

            if status == 'approved':
                self.logger.log_event("FIDO2_APPROVED", AlertSeverity.INFO, {
                    'action_type': atype, 'target': target[:200],
                    'approved_by': result.get('approved_by', 'unknown'),
                    'authenticator': result.get('authenticator_used', 'unknown'),
                })
                return True, ""

            elif status == 'rejected':
                self.logger.log_event("FIDO2_REJECTED", AlertSeverity.WARNING, {
                    'action_type': atype, 'target': target[:200],
                })
                return False, ("❌ Hardware approval **rejected**. "
                               "Action will not execute.")

            else:  # expired, timeout, error
                self.logger.log_event("FIDO2_TIMEOUT", AlertSeverity.WARNING, {
                    'action_type': atype, 'target': target[:200],
                    'status': status,
                })
                return False, (
                    f"⏰ Hardware approval **timed out** ({timeout}s). "
                    f"Action will not execute. Re-request and try again."
                )

        except Exception as e:
            self.logger.log_event("FIDO2_ERROR", AlertSeverity.HIGH, {
                'action_type': atype, 'target': target[:200],
                'error': str(e),
            })
            return False, (f"❌ Hardware approval failed: {e}\n\n"
                           f"Action will not execute.")

    def _execute_approved(self, aid: str) -> str:
        action = self.approval_mgr.approve(aid,
                                            session_id=self.logger.session_id)
        if not action:
            return f"⚠️ No action: `{aid}` (expired?)"

        atype = action['type']
        target = action['target']
        content = action['content']

        # SECURITY FIX (F-001): Enforce FIDO2 hardware approval for Tier 3
        if action.get('tier3_required'):
            approved, message = self._require_hardware_approval(action)
            if not approved:
                return message

        # Dual LLM verification
        if self.dual_verifier and self.config.enable_dual_llm:
            result = self.dual_verifier.verify_action(
                atype, target, content, "user request")
            if result.verdict == Verdict.BLOCKED:
                self.logger.log_blocked("DUAL_LLM", target, result.reasoning)
                return (f"❌ Blocked by security verification:\n"
                        f"{result.reasoning}")
            elif result.verdict == Verdict.DANGEROUS:
                return (f"⚠️ **High Risk Action**\n"
                        f"Concerns: {', '.join(result.concerns)}\n\n"
                        f"Type `FORCE {aid}` to proceed anyway.")

        if atype == 'COMMAND':
            ok, out = self.executor.execute_command(target)
            return f"**Command Result:**\n```\n{out}\n```"
        elif atype == 'READ':
            ok, out = self.executor.read_file(target)
            return (f"**File `{target}`:**\n```\n{out}\n```" if ok else out)
        elif atype == 'WRITE':
            ok, out = self.executor.write_file(target, content)
            return out
        elif atype == 'LIST':
            ok, out = self.executor.list_directory(target)
            return out
        elif atype == 'DELETE':
            ok, out = self.executor.delete_file(target)
            return out
        elif atype == 'API_QUERY':
            return self._execute_api_query(action)

        return f"⚠️ Unknown: {atype}"

    def _execute_api_query(self, action: dict) -> str:
        """Execute an API_QUERY action against local services or Graph API."""
        target = action['target']
        content = action['content']
        method = (content or 'GET').strip().upper()
        is_graph = target.lower().startswith('https://graph.microsoft.com')

        if is_graph:
            return self._execute_graph_api_query(target, method)
        else:
            return self._execute_local_api_query(target, method)

    def _execute_graph_api_query(self, target: str, method: str) -> str:
        """Execute a Graph API query."""
        if not self.graph_api_registry:
            return "❌ Graph API is not configured."

        # Re-validate (defense in depth)
        graph_path = target.split('graph.microsoft.com', 1)[-1]
        if '/v1.0' in graph_path:
            graph_path = graph_path.split('/v1.0', 1)[-1]
        elif '/beta' in graph_path:
            graph_path = graph_path.split('/beta', 1)[-1]

        allowed, tier_or_reason, _ = self.graph_api_registry.validate_request(
            method, graph_path)
        if not allowed:
            self.logger.log_blocked("API_QUERY_GRAPH", target, tier_or_reason)
            return f"❌ Graph API blocked: {tier_or_reason}"

        try:
            req = urllib.request.Request(target, method=method)
            req.add_header('Accept', 'application/json')
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = resp.read(10 * 1024 * 1024)  # 10MB cap
                text = data.decode('utf-8', errors='replace')
                if self.pii_protector:
                    text = self.pii_protector.redact(text)
                self.logger.log_action("API_QUERY", target, "SUCCESS",
                                       {'service': 'graph_api', 'bytes': len(data)})
                if self.transparency_tracker:
                    self.transparency_tracker.record_api_query(
                        'graph_api', target, success=True)
                return f"**Graph API Response:**\n```json\n{text}\n```"
        except Exception as e:
            self.logger.log_action("API_QUERY", target, "ERROR",
                                   {'error': str(e)})
            if self.transparency_tracker:
                self.transparency_tracker.record_api_query(
                    'graph_api', target, success=False)
            return f"❌ Graph API error: {e}"

    def _execute_local_api_query(self, target: str, method: str) -> str:
        """Execute a local service API query."""
        if not self.api_query_executor:
            return "❌ Local API query executor is not available."
        ok, result = self.api_query_executor.execute(target, method=method)
        if ok:
            return f"**API Response:**\n```\n{result}\n```"
        else:
            return f"❌ API query failed: {result}"

    def _process_response(self, response: str, user_request: str) -> str:
        """Process LLM response: extract actions, validate, create approval cards."""
        actions = ActionParser.parse(response)
        clean = ActionParser.strip_actions(response)

        if not actions:
            return response

        lines = []
        action_ids = []

        for a in actions:
            atype, target, content = a['type'], a['target'], a['content']

            # ----- Pre-approval validation -----
            tier3_required = False
            self._pending_pii_warning = None

            if atype in ('READ', 'WRITE', 'DELETE', 'LIST') and target:
                result = self._pre_validate_file_action(atype, target, content)
                if result is None:
                    continue  # Was blocked — message already appended to lines
                tier3_required, lines_to_add = result
                lines.extend(lines_to_add)

            elif atype == 'COMMAND' and target:
                is_safe, reason = self.executor.command_validator.validate(target)
                if not is_safe:
                    self.logger.log_blocked("PRE_APPROVAL_COMMAND", target, reason)
                    lines.append(
                        f"\n\n---\n### 🚫 Blocked: COMMAND"
                        f"\n\nCommand rejected by security policy: **{reason}**"
                    )
                    continue
                tier3_required = False
                self._pending_pii_warning = None

            elif atype == 'API_QUERY' and target:
                result = self._pre_validate_api_query(atype, target, content)
                if result is None:
                    continue  # Blocked
                tier3_required, _ = result

            else:
                tier3_required = False
                self._pending_pii_warning = None

            # ----- Create approval request -----
            try:
                # H-5 FIX: Always pass session_id to enforce session binding
                aid = self.approval_mgr.create_request(
                    atype, target, content,
                    session_id=self.logger.session_id
                )
            except Exception as e:
                lines.append(f"\n\n---\n### 🚫 Action Blocked\n\n{str(e)}")
                continue

            # Tag the pending approval with tier-3 if needed
            if tier3_required:
                with self.approval_mgr.lock:
                    if aid in self.approval_mgr.pending:
                        self.approval_mgr.pending[aid]['tier3_required'] = True

            short_id = aid[:8]
            action_ids.append((short_id, atype, target))
            card = self._format_action_card(atype, target, content, short_id)

            # Prepend tier-3 warning to the action card
            if tier3_required:
                tier3_reason = ""
                if self._pending_pii_warning:
                    tier3_reason = (
                        f"\n\n{self._pending_pii_warning}"
                        f"\n\nThis document contains sensitive data. "
                    )
                else:
                    tier3_reason = (
                        f"\n\nThis action targets sensitive data. "
                    )
                card = (
                    f"\n\n---\n### 🔐 Hardware Approval Required"
                    f"{tier3_reason}"
                    f"Approval requires "
                    f"**FIDO2 hardware key tap** or **biometric verification**."
                    + card
                )
            elif self._pending_pii_warning:
                # Non-critical PII — show warning but don't require FIDO2
                card = (
                    f"\n\n---\n### ⚠️ Document Content Notice"
                    f"\n\n{self._pending_pii_warning}"
                    + card
                )

            lines.append(card)

        if len(action_ids) > 1:
            lines.append(self._format_action_summary(action_ids))

        return clean + "".join(lines)

    def _pre_validate_file_action(self, atype: str, target: str,
                                   content: str):
        """Pre-validate a file action (READ/WRITE/DELETE/LIST).

        Returns None if blocked (caller should skip this action).
        Returns (tier3_required, extra_lines) if valid.
        """
        is_safe, resolved, reason = self.executor.path_validator.validate(target)
        if not is_safe:
            self.logger.log_blocked(f"PRE_APPROVAL_{atype}", target, reason)
            # Return None to signal blocked - but we need to communicate the line
            # Use a side-effect pattern matching the monolith
            return None  # Caller checks for None

        # Tier-3 paths: still create approval but tag it for FIDO2
        tier3_required = (reason == "Tier 3 required")

        # GAP 8 FIX: Block macro-enabled extensions at pre-approval
        if atype == 'WRITE' and self.executor.macro_blocker:
            ext_ok, ext_reason = self.executor.macro_blocker.check_extension(target)
            if not ext_ok:
                self.logger.log_blocked("PRE_APPROVAL_MACRO", target, ext_reason)
                return None

        # GAP 7 FIX: PII pre-scan for Office documents → TIER 3 escalation
        target_ext = os.path.splitext(target)[1].lower()
        if (atype == 'WRITE' and target_ext in OFFICE_SCANNABLE_EXTENSIONS
                and self.executor.doc_scanner and content):
            pre_scan = self.executor.doc_scanner.scan(
                content, file_type=target_ext,
                filename=os.path.basename(target))
            if pre_scan.get('should_block'):
                tier3_required = True
                pii_summary = self.executor.doc_scanner.get_scan_summary(pre_scan)
                self._pending_pii_warning = pii_summary
            elif pre_scan.get('findings'):
                self._pending_pii_warning = \
                    self.executor.doc_scanner.get_scan_summary(pre_scan)
            else:
                self._pending_pii_warning = None
        else:
            self._pending_pii_warning = None

        return tier3_required, []

    def _pre_validate_api_query(self, atype: str, target: str, content: str):
        """Pre-validate an API_QUERY action.

        Returns None if blocked, (tier3_required, []) if valid.
        """
        is_graph = target.lower().startswith('https://graph.microsoft.com')

        if is_graph:
            if not self.graph_api_registry:
                self.logger.log_blocked("PRE_APPROVAL_API_QUERY", target,
                                        "Graph API not configured")
                return None

            method = (content or 'GET').strip().upper()
            graph_path = target.split('graph.microsoft.com', 1)[-1]
            if '/v1.0' in graph_path:
                graph_path = graph_path.split('/v1.0', 1)[-1]
            elif '/beta' in graph_path:
                graph_path = graph_path.split('/beta', 1)[-1]

            allowed, tier_or_reason, _ = \
                self.graph_api_registry.validate_request(method, graph_path)
            if not allowed:
                self.logger.log_blocked("PRE_APPROVAL_API_QUERY", target,
                                        tier_or_reason)
                return None
            tier3_required = (tier_or_reason == 'TIER_3')
        else:
            if not self.api_query_executor:
                self.logger.log_blocked("PRE_APPROVAL_API_QUERY", target,
                                        "Local API query executor not initialized")
                return None
            is_valid, svc_or_reason = \
                self.api_query_executor.registry.validate_request(target)
            if not is_valid:
                self.logger.log_blocked("PRE_APPROVAL_API_QUERY", target,
                                        svc_or_reason)
                return None
            tier3_required = False

        self._pending_pii_warning = None
        return tier3_required, []

    def _format_action_card(self, atype: str, target: str, content: str,
                             short_id: str) -> str:
        """Format a single action into a user-facing approval card."""
        # Check sensitivity
        sensitivity_warning = ""
        if self.sensitive_detector:
            matches = self.sensitive_detector.detect(target, content)
            if matches:
                sensitivity_warning = (
                    f"\n\n{self.sensitive_detector.format_warning(matches)}")

        confirm_line = (f"✅ `CONFIRM {short_id}` · ❌ `REJECT {short_id}` "
                        f"· ❓ `EXPLAIN {short_id}`")

        action_configs = {
            'COMMAND': {
                'icon': '⚠️', 'verb': 'Execute a system command',
                'desc': self._summarize_command(target),
            },
            'READ': {
                'icon': '⚠️', 'verb': 'Read a file from disk',
                'desc': (f"Open and display the contents of "
                         f"`{os.path.basename(target)}`"),
            },
            'WRITE': {
                'icon': '⚠️', 'verb': 'Create or overwrite a file',
                'desc': self._format_write_preview(target, content),
            },
            'LIST': {
                'icon': '⚠️', 'verb': 'Show directory contents',
                'desc': (f"List all files and folders in "
                         f"`{os.path.basename(target) or target}`"),
            },
            'DELETE': {
                'icon': '🔴', 'verb': 'Permanently remove file or folder',
                'desc': (f"**⚠️ This action is irreversible!**\n\n"
                         f"Delete `{os.path.basename(target)}`"),
            },
            'API_QUERY': {
                'icon': '🌐', 'verb': 'Query a local or cloud service',
                'desc': (f"Send `{(content or 'GET').strip().upper()}` "
                         f"request to `{target}`"),
            },
        }

        cfg = action_configs.get(atype, {
            'icon': '⚠️', 'verb': atype, 'desc': target
        })

        # L-6 FIX: Docker command tier classification
        docker_tier_line = ""
        if atype == 'COMMAND' and target.strip().lower().startswith('docker'):
            docker_tier = self._get_docker_tier(target)
            if docker_tier:
                tier_icons = {
                    'standard': '🟢', 'elevated': '🟡', 'critical': '🔴'}
                docker_tier_line = (
                    f"\n⚓ **Docker Tier:** "
                    f"{tier_icons.get(docker_tier, '⚪')} "
                    f"{docker_tier.upper()}"
                )

        return (f"\n\n---\n"
                f"### {cfg['icon']} {atype} — {cfg['verb']}\n\n"
                f"{cfg['desc']}{docker_tier_line}{sensitivity_warning}\n\n"
                f"```\n📋 {target}\n🔑 {short_id}\n```\n\n"
                f"{confirm_line}")

    def _get_docker_tier(self, command: str) -> Optional[str]:
        """Determine the Docker command tier for display purposes."""
        if (hasattr(self, 'executor') and self.executor and
                self.executor.command_validator):
            tier = self.executor.command_validator.get_docker_tier(command)
            return tier if tier != 'unknown' else None
        return None

    def _format_write_preview(self, target: str, content: str) -> str:
        """Format write action with credential-redacted preview."""
        if self.credential_redactor:
            preview = self.credential_redactor.redact_for_preview(content, 100)
        else:
            preview = (content[:100].replace('\n', ' ')
                       + ('...' if len(content) > 100 else ''))
        return (f"Write {len(content)} bytes to "
                f"`{os.path.basename(target)}`\n\n**Preview:** {preview}")

    def _format_action_summary(self, action_ids: list) -> str:
        """Format the multi-action summary table with batch commands."""
        has_destructive = any(atype == 'DELETE'
                              for _, atype, _ in action_ids)

        lines = ["\n\n---\n### 📋 Summary — Multiple Actions Pending\n"]
        lines.append("| # | Type | Target | ID |")
        lines.append("|---|------|--------|-----|")

        for i, (sid, atype, target) in enumerate(action_ids, 1):
            icon = "🔴" if atype == "DELETE" else "⚠️"
            short_target = os.path.basename(target) or target
            if len(short_target) > 30:
                short_target = short_target[:27] + "..."
            lines.append(
                f"| {i} | {icon} {atype} | `{short_target}` | `{sid}` |")

        lines.append("\n**Batch Commands:**\n")

        if has_destructive:
            lines.append(
                "✅ `CONFIRM ALL SAFE` — Approve non-destructive actions only\n")
            lines.append("❌ `REJECT ALL` — Cancel all pending actions\n")
            lines.append(
                "\n⚠️ **Warning:** DELETE actions must be confirmed "
                "individually for safety.")
        else:
            lines.append(
                "✅ `CONFIRM ALL` — Approve and execute all actions "
                "in sequence\n")
            lines.append("❌ `REJECT ALL` — Cancel all pending actions\n")

        return "\n".join(lines)

    def _summarize_command(self, command: str) -> str:
        """Generate a plain-English summary of a command."""
        cmd_lower = command.lower()

        summaries = [
            ('mkdir', "Create new folder(s)"),
            ('dir', "List directory contents"), ('ls', "List directory contents"),
            ('cd', "Change directory"),
            ('copy', "Copy file(s)"), ('cp', "Copy file(s)"),
            ('move', "Move or rename file(s)"), ('mv', "Move or rename file(s)"),
            ('del', "Delete file(s)"), ('rm', "Delete file(s)"),
            ('type', "Display file contents"), ('cat', "Display file contents"),
            ('echo', "Print text or write to file"),
            ('ipconfig', "Show network configuration"),
            ('ifconfig', "Show network configuration"),
            ('ping', "Test network connectivity"),
            ('docker', "Run Docker command"),
            ('git', "Run Git command"),
            ('pip', "Package manager command"), ('npm', "Package manager command"),
            ('python', "Run Python script or command"),
            ('powershell', "Run PowerShell command"),
        ]

        for prefix, desc in summaries:
            if cmd_lower.startswith(prefix):
                return desc

        if 'systeminfo' in cmd_lower:
            return "Get system information"
        if 'tasklist' in cmd_lower:
            return "List running processes"
        if 'netstat' in cmd_lower:
            return "Show network connections"

        first_word = command.split()[0] if command.split() else "command"
        return f"Execute `{first_word}`"

    def _call_ollama(self, body: bytes) -> Optional[Dict]:
        # M-8 FIX: Check circuit breaker before attempting request
        breaker = getattr(self.__class__, 'ollama_breaker', None)
        if breaker and not breaker.can_request():
            self.logger.log_event("OLLAMA_CIRCUIT_OPEN", AlertSeverity.WARNING,
                                  {'reason': 'Circuit breaker open after '
                                             'consecutive failures'})
            return None

        url = (f"http://{self.config.ollama_host}:{self.config.ollama_port}"
               f"{self.path}")
        try:
            req = urllib.request.Request(url, data=body, method='POST')
            req.add_header('Content-Type', 'application/json')
            with urllib.request.urlopen(req, timeout=300) as resp:
                result = json.loads(resp.read())
                if breaker:
                    breaker.record_success()
                return result
        except Exception as e:
            if breaker:
                breaker.record_failure()
            self.logger.log_event("OLLAMA_ERROR", AlertSeverity.HIGH,
                                  {'error': str(e)})
            return None

    def _forward_request(self, method: str, body: bytes = None):
        if body is None:
            cl = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(cl) if cl > 0 else b''

        url = (f"http://{self.config.ollama_host}:{self.config.ollama_port}"
               f"{self.path}")
        try:
            req = urllib.request.Request(
                url, data=body if body else None, method=method)
            req.add_header('Content-Type', 'application/json')
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = resp.read()
                self.send_response(resp.status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', len(data))
                self.end_headers()
                self.wfile.write(data)
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            data = e.read()
            self.send_header('Content-Length', len(data))
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            self._send_error(502, str(e))

    def _send_chat_response(self, text: str):
        resp = {'model': 'aiohai', 'created_at': datetime.now().isoformat(),
                'response': text, 'done': True}
        self._send_json_response(resp)

    def _send_json_response(self, data: Dict):
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, code: int, msg: str):
        body = json.dumps({'error': msg}).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)
