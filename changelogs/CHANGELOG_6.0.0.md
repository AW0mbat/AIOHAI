# AIOHAI v6.0.0 Changelog — Companion App Administration

**Release date:** 2026-02-10  
**Phase:** 4 of 4 (Approval Gate Taxonomy v3)

---

## Summary

Phase 4 completes the Approval Gate Taxonomy v3 implementation by adding the
companion app administration layer. Non-technical users can now manage security
levels, review change requests, monitor sessions, and perform backup/restore
operations through a graphical admin panel — all while DENY gate immutability
and gate boundary rules remain enforced in code.

---

## New Files

### Python

| File | Lines | Purpose |
|------|-------|---------|
| `aiohai/core/config_manager.py` | ~613 | Admin-facing config wrapper: snapshots, gate editor data, apply changes, backup/restore, code diff generation |
| `aiohai/proxy/admin_api.py` | ~511 | REST API server for companion app on port 11437 with API secret authentication |

### TypeScript/React

| File | Lines | Purpose |
|------|-------|---------|
| `desktop/.../admin/AdminPanel.tsx` | ~87 | Tab container for all admin sections |
| `desktop/.../admin/SecurityLevelEditor.tsx` | ~409 | Gate-grouped sliders with DENY lockout |
| `desktop/.../admin/SessionHistoryPanel.tsx` | ~205 | Active session monitoring with countdown |
| `desktop/.../admin/ProxyControl.tsx` | ~415 | Health status + change request log with NFC-gated apply |
| `desktop/.../admin/BackupRestore.tsx` | ~223 | Backup creation, listing, restoration |

### Tests

| File | Tests | Purpose |
|------|-------|---------|
| `tests/test_taxonomy_v3_phase4.py` | 48 | ConfigManager, AdminAPIServer, DENY immutability, orchestrator wiring, desktop components |

---

## Modified Files

| File | Change |
|------|--------|
| `aiohai/core/version.py` | 5.4.0 → 6.0.0 |
| `aiohai/core/trust/__init__.py` | Updated docstring for Phase 4 |
| `aiohai/proxy/orchestrator.py` | ConfigManager + AdminAPIServer init, startup, and shutdown |
| `desktop/src/renderer/App.tsx` | Added AdminPanel import and 'admin' route |
| `desktop/src/renderer/components/layout/Sidebar.tsx` | Added 'admin' to NavPage type and nav items |

---

## Admin API Server (port 11437)

Runs in a background thread. All endpoints require `X-Admin-Secret` header.

**GET:** `/api/admin/health`, `/config`, `/gates`, `/overrides`, `/change-requests`, `/sessions`, `/backups`  
**POST:** `/config/apply`, `/config/reset`, `/backups/create`, `/backups/restore`, `/change-requests/apply`, `/change-requests/reject`, `/sessions/end`  
**DELETE:** `/overrides/{CATEGORY:DOMAIN}`

### ConfigManager

Wraps TrustMatrixAdjuster and ChangeRequestLog:
- `get_config_snapshot()` — Full state with version, gates, overrides
- `get_gate_editor_data()` — Gate-grouped data for SecurityLevelEditor UI
- `apply_admin_changes()` — Batch apply with gate boundary validation
- `generate_code_diff()` — Diff generation for change request apply-with-restart
- `create_backup()` / `restore_from_backup()` — Config backup management

---

## Gate Boundary Enforcement

All Phase 4 components enforce the same invariants:

- **DENY gate (levels 0-1):** No API endpoint, no UI control, no mechanism can change. SecurityLevelEditor shows DENY items as locked display-only.
- **PHYSICAL → BIOMETRIC/SOFTWARE:** Admin API rejects; change request log records the request with "code change required" status.
- **BIOMETRIC → SOFTWARE:** Same enforcement.
- **Within-gate depth:** Freely adjustable via SecurityLevelEditor sliders.
- **Gate promotions (more restrictive):** Always allowed.

---

## Companion App Admin Panel

Four tabs accessible via the 🛡️ Admin nav item:

1. **⚙️ Security Levels** — Gate-grouped editor with review depth sliders. DENY section display-only with 🔒 icon. Category filter dropdown.
2. **🔓 Sessions** — Active elevation sessions with scope, progress bar, countdown timer, and End Session button. Auto-refreshes every 5s.
3. **🔧 Proxy Control** — Health status indicator. Change request log with select/preview/apply flow. Two-pass NFC-gated apply: review diff → confirm.
4. **💾 Backups** — Create backups with optional reason. List available backups. Restore with confirmation.

---

## Taxonomy v3 Implementation Complete

| Phase | Version | Deliverables | Status |
|-------|---------|-------------|--------|
| 1 — Gate Model | v5.2.0 | Types, TierMatrix, TargetClassifier, gate-aware approval | ✅ |
| 2 — Session Elevation | v5.3.0 | SessionManager, SessionStore, lifecycle, circuit breakers | ✅ |
| 3 — Runtime Adjustments | v5.4.0 | TrustMatrixAdjuster, ChangeRequestLog, LLM integration | ✅ |
| 4 — Companion App Admin | v6.0.0 | ConfigManager, AdminAPIServer, 5 React components | ✅ |

**Total new code across all 4 phases:** ~7,340 lines (est. from spec) across 8 Python + 7 TSX files.
