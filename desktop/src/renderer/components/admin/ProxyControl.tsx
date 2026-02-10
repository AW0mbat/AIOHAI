import React, { useState, useEffect, useCallback } from 'react';

/**
 * ProxyControl — Proxy lifecycle management and health monitoring.
 *
 * Features:
 * - Health status display
 * - Pending change request application (with NFC gate simulation)
 * - Restart signal to proxy
 *
 * Phase 4 of Approval Gate Taxonomy v3 implementation.
 */

interface HealthStatus {
  status: string;
  timestamp: string;
}

interface ChangeRequest {
  request_id: string;
  category: string;
  domain: string;
  current_level: number;
  current_gate: string;
  requested_level: number;
  requested_gate: string;
  boundary_violated: string;
  boundary_type: string;
  user_context: string;
  status: string;
  timestamp: string;
}

interface ProxyControlProps {
  adminApiUrl: string;
  adminSecret: string;
}

const BOUNDARY_LABELS: Record<string, string> = {
  DENY_GATE: '🚫 DENY gate — manual code edit only',
  BIOMETRIC_TO_SOFTWARE: '🔒 BIOMETRIC → SOFTWARE — code change required',
  PHYSICAL_TO_BIOMETRIC: '🔒 PHYSICAL → BIOMETRIC — code change required',
  PHYSICAL_TO_SOFTWARE: '🔒 PHYSICAL → SOFTWARE — code change required',
};

export const ProxyControl: React.FC<ProxyControlProps> = ({
  adminApiUrl, adminSecret,
}) => {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [healthError, setHealthError] = useState(false);
  const [changeRequests, setChangeRequests] = useState<{
    pending: ChangeRequest[];
    applied: ChangeRequest[];
    total: number;
  }>({ pending: [], applied: [], total: 0 });
  const [loading, setLoading] = useState(true);
  const [selectedRequests, setSelectedRequests] = useState<Set<string>>(new Set());
  const [applyResult, setApplyResult] = useState<string | null>(null);
  const [applying, setApplying] = useState(false);
  const [diffPreview, setDiffPreview] = useState<any[] | null>(null);

  const fetchData = useCallback(async () => {
    try {
      const [healthResp, crResp] = await Promise.all([
        fetch(`${adminApiUrl}/api/admin/health`, {
          headers: { 'X-Admin-Secret': adminSecret },
        }),
        fetch(`${adminApiUrl}/api/admin/change-requests`, {
          headers: { 'X-Admin-Secret': adminSecret },
        }),
      ]);

      if (healthResp.ok) {
        setHealth(await healthResp.json());
        setHealthError(false);
      } else {
        setHealthError(true);
      }
      if (crResp.ok) setChangeRequests(await crResp.json());
    } catch {
      setHealthError(true);
    } finally {
      setLoading(false);
    }
  }, [adminApiUrl, adminSecret]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const toggleRequest = (id: string) => {
    setSelectedRequests(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
    setDiffPreview(null);
  };

  const handlePreviewDiff = async () => {
    if (selectedRequests.size === 0) return;
    setApplying(true);
    setApplyResult(null);

    try {
      const resp = await fetch(`${adminApiUrl}/api/admin/change-requests/apply`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Admin-Secret': adminSecret,
        },
        body: JSON.stringify({
          request_ids: Array.from(selectedRequests),
          nfc_verified: false,
        }),
      });
      const result = await resp.json();

      if (result.status === 'review_required') {
        setDiffPreview(result.diffs || []);
        if (result.denied?.length > 0) {
          setApplyResult(`⚠️ ${result.denied.length} request(s) denied (DENY gate items cannot be applied)`);
        }
      }
    } catch (e: any) {
      setApplyResult(`❌ ${e.message}`);
    } finally {
      setApplying(false);
    }
  };

  const handleConfirmApply = async () => {
    setApplying(true);
    try {
      const resp = await fetch(`${adminApiUrl}/api/admin/change-requests/apply`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Admin-Secret': adminSecret,
        },
        body: JSON.stringify({
          request_ids: Array.from(selectedRequests),
          nfc_verified: true,
        }),
      });
      const result = await resp.json();

      if (result.applied?.length > 0) {
        setApplyResult(`✅ Applied ${result.applied.length} changes. Restart required to take effect.`);
        setSelectedRequests(new Set());
        setDiffPreview(null);
        fetchData();
      } else {
        setApplyResult('⚠️ No changes applied');
      }
    } catch (e: any) {
      setApplyResult(`❌ ${e.message}`);
    } finally {
      setApplying(false);
    }
  };

  const handleRejectRequest = async (requestId: string) => {
    try {
      await fetch(`${adminApiUrl}/api/admin/change-requests/reject`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Admin-Secret': adminSecret,
        },
        body: JSON.stringify({ request_id: requestId, reason: 'Admin rejected' }),
      });
      fetchData();
    } catch (e: any) {
      setApplyResult(`❌ ${e.message}`);
    }
  };

  if (loading) return <div style={{ padding: 'var(--space-lg)', color: 'var(--text-muted)' }}>Loading...</div>;

  const isDenyGate = (cr: ChangeRequest) => cr.boundary_type === 'manual_code_edit_only';

  return (
    <div style={{ maxWidth: 800 }}>
      <h2 style={{ fontSize: 'var(--font-size-xl)', fontWeight: 700, marginBottom: 'var(--space-lg)' }}>
        🔧 Proxy Control
      </h2>

      {/* Health status */}
      <div style={{
        background: 'var(--bg-elevated)', border: '1px solid var(--border-default)',
        borderRadius: 'var(--radius-lg)', padding: 'var(--space-md)', marginBottom: 'var(--space-lg)',
        display: 'flex', alignItems: 'center', gap: 'var(--space-md)',
      }}>
        <div style={{
          width: 12, height: 12, borderRadius: '50%',
          background: healthError ? 'var(--status-down)' : 'var(--status-healthy)',
        }} />
        <div>
          <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
            Admin API: {healthError ? 'Unreachable' : 'Healthy'}
          </div>
          {health?.timestamp && (
            <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)' }}>
              Last check: {new Date(health.timestamp).toLocaleTimeString()}
            </div>
          )}
        </div>
      </div>

      {/* Change Request Log */}
      <h3 style={{ fontSize: 'var(--font-size-lg)', fontWeight: 600, marginBottom: 'var(--space-md)' }}>
        📋 Change Request Log
      </h3>

      {changeRequests.pending.length === 0 && changeRequests.applied.length === 0 ? (
        <div style={{
          background: 'var(--bg-elevated)', border: '1px solid var(--border-default)',
          borderRadius: 'var(--radius-lg)', padding: 'var(--space-xl)', textAlign: 'center',
          color: 'var(--text-muted)', marginBottom: 'var(--space-lg)',
        }}>
          No change requests. Requests are created when users attempt gate demotions that require code changes.
        </div>
      ) : (
        <>
          {/* Pending requests */}
          {changeRequests.pending.length > 0 && (
            <div style={{ marginBottom: 'var(--space-lg)' }}>
              <div style={{
                fontSize: 'var(--font-size-sm)', color: 'var(--text-secondary)',
                marginBottom: 'var(--space-sm)', fontWeight: 600,
              }}>
                Pending ({changeRequests.pending.length})
              </div>
              {changeRequests.pending.map(cr => (
                <div key={cr.request_id} style={{
                  background: 'var(--bg-elevated)', border: '1px solid var(--border-default)',
                  borderRadius: 'var(--radius-md)', padding: 'var(--space-md)',
                  marginBottom: 'var(--space-sm)',
                }}>
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-sm)' }}>
                    {!isDenyGate(cr) && (
                      <input
                        type="checkbox"
                        checked={selectedRequests.has(cr.request_id)}
                        onChange={() => toggleRequest(cr.request_id)}
                        style={{ marginTop: 3 }}
                      />
                    )}
                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-sm)' }}>
                        <span style={{
                          fontWeight: 600, fontSize: 'var(--font-size-sm)',
                          fontFamily: 'var(--font-mono)', color: 'var(--text-primary)',
                        }}>
                          {cr.category}:{cr.domain}
                        </span>
                        <span style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)' }}>
                          L{cr.current_level} ({cr.current_gate}) → L{cr.requested_level} ({cr.requested_gate})
                        </span>
                      </div>
                      {cr.user_context && (
                        <div style={{
                          fontSize: 'var(--font-size-xs)', color: 'var(--text-secondary)',
                          marginTop: 'var(--space-xs)', fontStyle: 'italic',
                        }}>
                          "{cr.user_context}"
                        </div>
                      )}
                      <div style={{
                        fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)',
                        marginTop: 'var(--space-xs)',
                      }}>
                        {BOUNDARY_LABELS[cr.boundary_violated] || cr.boundary_violated}
                      </div>
                      {isDenyGate(cr) && (
                        <div style={{
                          fontSize: 'var(--font-size-xs)', color: 'var(--status-down)',
                          marginTop: 'var(--space-xs)', fontWeight: 600,
                        }}>
                          ⚠️ DENY gate — cannot be applied through this interface
                        </div>
                      )}
                    </div>
                    <button
                      onClick={() => handleRejectRequest(cr.request_id)}
                      style={{
                        background: 'transparent', color: 'var(--text-muted)',
                        border: '1px solid var(--border-default)',
                        borderRadius: 'var(--radius-sm)', padding: '2px 8px',
                        fontSize: 'var(--font-size-xs)', cursor: 'pointer',
                      }}
                    >
                      Reject
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Diff preview */}
          {diffPreview && diffPreview.length > 0 && (
            <div style={{
              background: 'var(--bg-surface)', border: '1px solid var(--accent-primary)',
              borderRadius: 'var(--radius-md)', padding: 'var(--space-md)',
              marginBottom: 'var(--space-md)',
            }}>
              <div style={{ fontWeight: 600, marginBottom: 'var(--space-sm)', color: 'var(--text-primary)' }}>
                Code changes to apply:
              </div>
              {diffPreview.map((d: any, i: number) => (
                <div key={i} style={{
                  fontFamily: 'var(--font-mono)', fontSize: 'var(--font-size-xs)',
                  color: 'var(--accent-primary)', marginBottom: 2,
                }}>
                  {d.code_line}
                </div>
              ))}
              <div style={{
                fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)',
                marginTop: 'var(--space-sm)',
              }}>
                🔒 Requires NFC tap at server + admin credentials
              </div>
              <div style={{ display: 'flex', gap: 'var(--space-sm)', marginTop: 'var(--space-md)' }}>
                <button
                  onClick={handleConfirmApply}
                  disabled={applying}
                  style={{
                    background: 'var(--accent-primary)', color: 'var(--text-inverse)',
                    border: 'none', borderRadius: 'var(--radius-sm)',
                    padding: '6px 16px', fontWeight: 600, cursor: 'pointer',
                  }}
                >
                  {applying ? 'Applying...' : '🔐 Confirm & Apply (NFC)'}
                </button>
                <button
                  onClick={() => setDiffPreview(null)}
                  style={{
                    background: 'transparent', color: 'var(--text-secondary)',
                    border: '1px solid var(--border-default)', borderRadius: 'var(--radius-sm)',
                    padding: '6px 16px', cursor: 'pointer',
                  }}
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          {/* Apply bar */}
          {changeRequests.pending.some(cr => !isDenyGate(cr)) && !diffPreview && (
            <div style={{ marginBottom: 'var(--space-lg)' }}>
              <button
                onClick={handlePreviewDiff}
                disabled={selectedRequests.size === 0 || applying}
                style={{
                  background: selectedRequests.size > 0 ? 'var(--accent-primary)' : 'var(--bg-hover)',
                  color: selectedRequests.size > 0 ? 'var(--text-inverse)' : 'var(--text-muted)',
                  border: 'none', borderRadius: 'var(--radius-sm)',
                  padding: '6px 16px', fontWeight: 600,
                  cursor: selectedRequests.size > 0 ? 'pointer' : 'default',
                }}
              >
                Preview Changes ({selectedRequests.size})
              </button>
            </div>
          )}

          {applyResult && (
            <div style={{
              fontSize: 'var(--font-size-sm)', color: 'var(--text-secondary)',
              marginBottom: 'var(--space-md)',
            }}>
              {applyResult}
            </div>
          )}

          {/* Applied requests */}
          {changeRequests.applied.length > 0 && (
            <div>
              <div style={{
                fontSize: 'var(--font-size-sm)', color: 'var(--text-secondary)',
                marginBottom: 'var(--space-sm)', fontWeight: 600,
              }}>
                Previously applied ({changeRequests.applied.length})
              </div>
              {changeRequests.applied.map(cr => (
                <div key={cr.request_id} style={{
                  background: 'var(--bg-elevated)', border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-md)', padding: 'var(--space-sm) var(--space-md)',
                  marginBottom: 'var(--space-xs)',
                  opacity: 0.7,
                }}>
                  <span style={{
                    fontFamily: 'var(--font-mono)', fontSize: 'var(--font-size-xs)',
                    color: 'var(--text-secondary)',
                  }}>
                    ✅ {cr.category}:{cr.domain} — L{cr.current_level} → L{cr.requested_level}
                  </span>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
};

export default ProxyControl;
