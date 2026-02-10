# AIOHAI v5.3.0 Changelog — Session Elevation (Phase 2)

> **Release:** v5.3.0
> **Phase:** Approval Gate Taxonomy v3 — Phase 2 (Session Elevation)
> **Date:** 2026-02-09
> **Baseline:** v5.2.0 (Phase 1 — Gate Model + 15-Level Taxonomy)
> **Test results:** 83 new Phase 2 tests passing + 183 Phase 1/1b tests passing

---

## Summary

Phase 2 implements **session elevation** — the "gate is a door" model from the
Approval Gate Taxonomy v3 specification. When a batch of gate-level actions is
needed, the user authenticates ONCE at the gate level to "open the door."
Subsequent actions within the same narrowly-scoped session drop to SOFTWARE or
PASSIVE level. When the session ends, the door closes and the next action
requires fresh gate-level authentication.

Session elevation is NOT permanent gate demotion. The action's default gate
assignment never changes.

---

## New Files

| File | Lines | Description |
|------|-------|-------------|
| `aiohai/core/trust/__init__.py` | 12 | Trust package init |
| `aiohai/core/trust/session.py` | ~430 | `SessionManager`, `ElevationSession`, `SessionScope` |
| `aiohai/core/trust/session_store.py` | ~150 | JSONL append-only persistence for session audit trail |
| `tests/test_taxonomy_v3_phase2.py` | ~540 | 83 tests covering full session lifecycle |
| `changelogs/CHANGELOG_5.3.0.md` | — | This file |

## Modified Files

| File | Changes |
|------|---------|
| `aiohai/proxy/approval.py` | Added `check_session_elevation()` and `build_session_plan()` methods; `__init__` accepts `session_manager` kwarg |
| `aiohai/proxy/handler.py` | Session elevation check in action processing flow; `SESSION`/`ENDSESSION` user commands; session circuit-breaker on REJECT; `HandlerContext` gains `session_manager` slot |
| `aiohai/proxy/orchestrator.py` | Wires `SessionManager` + `SessionStore` into `ApprovalManager` and `HandlerContext` |
| `aiohai/core/version.py` | Version bump: `5.0.0` → `5.3.0` |

---

## Feature Details

### SessionManager (`aiohai/core/trust/session.py`)

Core class managing elevation sessions with strict scope, time, and count bounds.

**Key behaviors:**
- **open_session()** — Creates a session after user authenticates at gate level.
  Validates scope, gate type, elevated level constraints.
- **check_elevation()** — O(1) lookup via scope index. Returns elevated level if
  a matching active session exists, None otherwise.
- **use_session_action()** — Records action execution, closes session on exhaustion.
- **build_session_plan()** — Analyzes a list of parsed actions to determine if a
  session plan should be suggested (requires 2+ non-passive actions).
- **expand_scope()** — Adds (category, domain) pairs to an existing session.

**Strict defaults (from spec):**
- Max 10 actions per session
- Max 15 minutes per session
- Minimum elevated level for hardware gates: CONFIRM_QUICK (level 10)
- Default elevated level: NOTIFY_AND_PROCEED (level 11)

**Circuit breakers:**
- User REJECT → session closes immediately
- User UNDO → session closes immediately
- 2+ execution failures → session closes
- Action count exhausted → session closes
- Time expired → session closes
- Proxy restart → all sessions close

**Scope isolation:**
- No scope creep: TRANSFER:FS_DOC_SENS does NOT cover DELETE:FS_DOC_SENS
- No stacking: opening a new session for overlapping scope replaces the old one
- Non-overlapping sessions coexist

**Validation:**
- Empty scope rejected
- DENY gate sessions rejected
- PASSIVE gate sessions rejected (already auto-execute)
- Hardware gate minimum level enforced (≥ CONFIRM_QUICK)
- Elevated level must be less restrictive than the gate

### SessionStore (`aiohai/core/trust/session_store.py`)

Append-only JSONL persistence for session audit trail. Thread-safe.
Creates log file at `$AIOHAI_HOME/config/session_log.jsonl`.

### Handler Integration

The action processing flow now checks for session elevation between the
PASSIVE auto-execute path and the approval card creation path:

```
PASSIVE level → auto-execute (unchanged)
↓
Session elevation check → if elevated to PASSIVE, auto-execute
                        → if elevated to SOFTWARE, use elevated level for approval card
↓
Create approval card at gate level (unchanged)
```

### User Commands

- `SESSION` / `SESSIONS` — Show active elevation sessions with scope, countdown, and actions remaining
- `ENDSESSION <id>` — Close a specific session by prefix match
- `ENDSESSION ALL` — Close all active sessions

### REJECT Circuit Breaker

When a user REJECTs an action, the handler checks if the action's (category, domain)
is covered by an active session. If so, the session is immediately closed via
`record_rejection()`. This prevents continued auto-execution when the user signals
something is wrong.

---

## Architecture Notes

- **Dependency direction preserved:** `core/trust/` → `core/types` only. No upward dependencies.
  `proxy/approval` and `proxy/handler` import from `core/trust/` (correct direction).
- **Thread safety:** All SessionManager methods acquire `self._lock`. The scope index
  provides O(1) lookup without scanning all sessions.
- **No public interface changes:** `ApprovalManager.create_request()`, `approve()`,
  `reject()`, `get_all_pending()` signatures unchanged. `session_manager` is an
  optional kwarg with None default.
- **Backward compatible:** Without a SessionManager wired in, all behavior is
  identical to v5.2.0. Session elevation is opt-in.

---

## What This Does NOT Do

1. Does not implement the companion app UI (SessionControls.tsx, SessionStatusBar.tsx) — that's Phase 4.
2. Does not implement "Allow Similar" expansion in approval cards — requires frontend changes.
3. Does not implement session plan presentation in the chat UI — the `build_session_plan()` method is available but not yet wired to generate plan cards in LLM response processing.
4. Does not modify the FIDO2 authentication flow — sessions are opened programmatically; the gate-level authentication is assumed to have already happened.
5. Does not implement runtime trust matrix adjustments — that's Phase 3.
