# AIOHAI v5.4.0 Changelog — Phase 3: Runtime Trust Matrix Adjustments

**Release date:** 2026-02-09
**Predecessor:** v5.3.0 (Phase 2 — Session Elevation)
**Spec:** Approval Gate Taxonomy v3, Sections 7–8

---

## Summary

Phase 3 implements runtime trust matrix adjustments and the change request log. Users and admins can now adjust approval levels within gate boundaries at runtime, and requests that require code-level changes are logged for later review and application.

---

## New Files

| File | Lines | Purpose |
|------|-------|---------|
| `aiohai/core/trust/matrix_adjuster.py` | ~750 | `TrustMatrixAdjuster` — validates and applies runtime trust matrix adjustments with strict gate boundary enforcement |
| `aiohai/core/trust/change_request_log.py` | ~400 | `ChangeRequestLog` — persistence for gate-level change requests that cannot be applied at runtime |
| `tests/test_taxonomy_v3_phase3.py` | ~600 | Phase 3 test suite (47 tests) |
| `changelogs/CHANGELOG_5.4.0.md` | — | This file |

## Modified Files

| File | What Changed |
|------|-------------|
| `aiohai/proxy/handler.py` | Added SETLEVEL, OVERRIDES, CHANGEREQUESTS commands; `_propose_trust_adjustment()`, `_show_overrides()`, `_show_change_requests()` methods; `HandlerContext` gains `matrix_adjuster` and `change_request_log` slots |
| `aiohai/proxy/orchestrator.py` | Phase 3 initialization: creates `ChangeRequestLog` and `TrustMatrixAdjuster`, loads overrides, wires into `HandlerContext` |
| `aiohai/core/trust/__init__.py` | Updated docstring to document Phase 3 modules |
| `aiohai/core/version.py` | Version bump: `5.3.0` → `5.4.0` |

---

## Feature Details

### TrustMatrixAdjuster

Core runtime adjustment engine. Validates every proposed change against gate boundary rules before applying.

**Gate boundary enforcement (immutable invariants):**
- DENY gate (levels 0-1): NEVER changeable — always rejected with `boundary='DENY_GATE'`
- PHYSICAL → BIOMETRIC/SOFTWARE/PASSIVE demotion: always rejected with `boundary='PHYSICAL_TO_*'`
- BIOMETRIC → SOFTWARE/PASSIVE demotion: always rejected with `boundary='BIOMETRIC_TO_*'`
- Within-gate review depth changes: always allowed
- Gate promotions (more restrictive): always allowed

**Proposal API:**
- `propose_adjustment(category, domain, level, reason)` → `AdjustmentResult`
- `propose_from_natural_language(category_str, domain_str, level_int, reason)` → `AdjustmentResult`
- Returns allowed/rejected with explanation, alternatives for rejected proposals

**Application API:**
- `apply_adjustment(result)` → bool — applies validated adjustment
- `remove_adjustment(category, domain)` → bool — reverts to default
- `reset_all()` → int — removes all overrides, returns count
- `get_current_level(category, domain)` → ApprovalLevel — returns effective level (override or default)
- `get_all_overrides()` → dict — all active overrides

**Classification management:**
- `set_path_classification(path, domain, reason)` — map filesystem paths to domains
- `add_command(command, domain, reason)` — classify commands
- `set_ha_entity_override(entity_id, domain, reason)` — override HA entity domains
- `set_session_defaults(max_actions, max_duration_minutes, default_elevated_level)` — adjust session elevation parameters

**Persistence:**
- `save_to_file()` / `load_from_file()` — atomic JSON with timestamped backups
- Schema version: "3.0"
- Validates overrides on load — rejects gate boundary violations

**Limits:** 200 tier overrides, 100 path classifications, 50 command additions

### ChangeRequestLog

Persistent log for requests that cannot be applied at runtime.

**API:**
- `add_request(...)` — creates entry with boundary metadata, returns request_id
- `add_from_adjustment_result(result, user)` — convenience wrapper
- `get_pending()` / `get_applied()` / `get_all()` — query requests
- `get_request(request_id)` — lookup by ID or prefix
- `mark_applied(request_id, applied_by, code_diff, nfc_verification)` — marks as applied
- `mark_rejected(request_id, rejected_by, reason)` — admin rejection
- `save()` — atomic JSON persistence

**DENY gate protection:** `mark_applied()` refuses to mark DENY gate requests as applied — returns `(False, "DENY gate items cannot be applied through this mechanism")`

**Boundary types:**
- `manual_code_edit_only` — DENY gate items
- `code_change_required` — cross-gate demotions

**Limit:** 500 requests max, auto-trims oldest non-pending

### Handler Commands

Three new user commands accessible through the chat interface:

- **SETLEVEL `<CATEGORY>` `<DOMAIN>` `<level>` `[reason]`** — Propose a trust matrix adjustment. Shows result (allowed/rejected), alternatives for rejected proposals, and logs change requests for boundary violations.
- **OVERRIDES** — Display all active trust level overrides with current/default levels and gates.
- **CHANGEREQUESTS** — Display pending change requests with boundary types and user context.

### AdjustmentResult

Structured result object returned by all proposal methods:
- `to_dict()` — JSON-serializable for API responses
- `to_change_request(user)` — generates change request log entry for rejected proposals
- Contains: `allowed`, `explanation`, `boundary_violated`, `alternatives`, `category`, `domain`, `current_level`, `requested_level`, `reason`

---

## Test Coverage

47 tests across 11 categories:
- Proposal & Validation: 13 tests (within-gate, promotions, demotions, DENY immutability, alternatives)
- Apply & Remove: 5 tests (apply, reject, remove, reset, get_all)
- Natural Language API: 5 tests (valid, invalid category/domain/level, demotion)
- Persistence: 4 tests (roundtrip, rejected overrides, backup creation, schema version)
- Change Request Log: 8 tests (add, apply, deny protection, reject, save/load, from_result)
- AdjustmentResult: 4 tests (serialization, change_request generation, none values)
- Session Defaults: 4 tests (valid, invalid bounds, non-passive level)
- Comprehensive Gate Boundary: 4 tests (all DENY, all PHYSICAL, all BIOMETRIC, all promotions)
- Handler Integration: 5 tests (context slots, SETLEVEL allowed/denied, OVERRIDES, CHANGEREQUESTS)
- Version: 1 test

Cumulative test count: Phase 1 (183) + Phase 2 (83) + Phase 3 (47) = **313 taxonomy tests**

---

## Data Files

### config/user_overrides.json (runtime, user-managed)
```json
{
  "_schema_version": "3.0",
  "tier_overrides": { "EXECUTE:HA_LIGHT": { "level": 14, "reason": "..." } },
  "gate_promotions": { "OBSERVE:FS_DOC_SENS": { "promoted_to": "BIOMETRIC", "level": 7 } },
  "session_defaults": { "max_actions": 10, "max_duration_minutes": 15 },
  "path_classifications": {},
  "command_additions": {},
  "ha_entity_overrides": {}
}
```

### config/change_requests.json (runtime, admin-managed)
```json
{
  "_schema_version": "1.0",
  "requests": [
    {
      "request_id": "req_...",
      "category": "EXECUTE", "domain": "HA_LOCK",
      "current_level": 3, "current_gate": "PHYSICAL",
      "requested_level": 9, "requested_gate": "SOFTWARE",
      "boundary_violated": "PHYSICAL_TO_SOFTWARE",
      "boundary_type": "code_change_required",
      "status": "logged"
    }
  ]
}
```

---

## Design Decisions

1. **No progressive trust.** Adjustments are explicit user decisions, not automatic learning. Repetition doesn't erode protection.

2. **Alternatives, not errors.** When a gate demotion is rejected, the system offers within-gate alternatives (e.g., BIOMETRIC_QUICK instead of SOFTWARE).

3. **DENY gate has no alternatives.** DENY items are too dangerous for any runtime path. No suggestions, no workarounds.

4. **Atomic persistence.** Writes use temp file + rename to prevent corruption. Backups created before overwrite.

5. **Validation on load.** Overrides file is validated against gate boundaries on load — invalid entries (e.g., someone manually edited the JSON to demote a gate) are rejected with specific error messages.

6. **Thread-safe.** All public methods acquire locks.

---

## Migration Notes

- No breaking changes from v5.3.0
- New `HandlerContext` slots (`matrix_adjuster`, `change_request_log`) default to None — existing code unaffected
- `config/user_overrides.json` and `config/change_requests.json` are created on first save, not at startup
- Version bump in `version.py`: `5.3.0` → `5.4.0`
