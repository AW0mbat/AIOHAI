"""
AIOHAI Core Trust — Session Elevation and Trust Matrix Adjustments.

Submodules:
- session             : SessionManager — temporary approval gate step-downs (Phase 2)
- session_store       : JSONL persistence for session audit trail (Phase 2)
- matrix_adjuster     : TrustMatrixAdjuster — runtime trust matrix adjustments (Phase 3)
- change_request_log  : ChangeRequestLog — gate-level change request persistence (Phase 3)

Phases 2-3 of Approval Gate Taxonomy v3 implementation.
"""
# O6: Import from submodules directly:
#   from aiohai.core.trust.session import SessionManager
#   from aiohai.core.trust.session_store import SessionStore
#   from aiohai.core.trust.matrix_adjuster import TrustMatrixAdjuster
#   from aiohai.core.trust.change_request_log import ChangeRequestLog
