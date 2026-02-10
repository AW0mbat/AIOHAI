import React, { useState, useEffect, useCallback } from 'react';

/**
 * BackupRestore — Configuration backup management.
 *
 * Features:
 * - Create backups with optional reason
 * - List existing backups with timestamps
 * - Restore from backup with confirmation
 *
 * Phase 4 of Approval Gate Taxonomy v3 implementation.
 */

interface BackupEntry {
  filename: string;
  path: string;
  timestamp: string;
  size: number;
  reason?: string;
}

interface BackupRestoreProps {
  adminApiUrl: string;
  adminSecret: string;
}

export const BackupRestore: React.FC<BackupRestoreProps> = ({
  adminApiUrl, adminSecret,
}) => {
  const [backups, setBackups] = useState<BackupEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [restoring, setRestoring] = useState(false);
  const [reason, setReason] = useState('');
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  const fetchBackups = useCallback(async () => {
    try {
      const resp = await fetch(`${adminApiUrl}/api/admin/backups`, {
        headers: { 'X-Admin-Secret': adminSecret },
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      setBackups(data.backups || []);
      setError(null);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [adminApiUrl, adminSecret]);

  useEffect(() => { fetchBackups(); }, [fetchBackups]);

  const handleCreate = async () => {
    setCreating(true);
    setStatusMsg(null);
    try {
      const resp = await fetch(`${adminApiUrl}/api/admin/backups/create`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Admin-Secret': adminSecret,
        },
        body: JSON.stringify({ reason }),
      });
      const result = await resp.json();
      if (result.success) {
        setStatusMsg('✅ Backup created');
        setReason('');
        fetchBackups();
      } else {
        setStatusMsg(`❌ ${result.error}`);
      }
    } catch (e: any) {
      setStatusMsg(`❌ ${e.message}`);
    } finally {
      setCreating(false);
    }
  };

  const handleRestore = async (path: string, filename: string) => {
    if (!confirm(`Restore from "${filename}"? This will overwrite current overrides.`)) return;
    setRestoring(true);
    setStatusMsg(null);
    try {
      const resp = await fetch(`${adminApiUrl}/api/admin/backups/restore`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Admin-Secret': adminSecret,
        },
        body: JSON.stringify({ path }),
      });
      const result = await resp.json();
      if (result.success) {
        setStatusMsg('✅ Restored successfully');
        fetchBackups();
      } else {
        setStatusMsg(`❌ ${result.error}`);
      }
    } catch (e: any) {
      setStatusMsg(`❌ ${e.message}`);
    } finally {
      setRestoring(false);
    }
  };

  if (loading) return <div style={{ padding: 'var(--space-lg)', color: 'var(--text-muted)' }}>Loading backups...</div>;

  return (
    <div style={{ maxWidth: 800 }}>
      <h2 style={{ fontSize: 'var(--font-size-xl)', fontWeight: 700, marginBottom: 'var(--space-lg)' }}>
        💾 Backup & Restore
      </h2>

      {error && (
        <div style={{ padding: 'var(--space-md)', color: 'var(--status-down)', marginBottom: 'var(--space-md)' }}>
          Error: {error}
        </div>
      )}

      {/* Create backup */}
      <div style={{
        background: 'var(--bg-elevated)', border: '1px solid var(--border-default)',
        borderRadius: 'var(--radius-lg)', padding: 'var(--space-md)', marginBottom: 'var(--space-lg)',
      }}>
        <div style={{ fontWeight: 600, marginBottom: 'var(--space-sm)', color: 'var(--text-primary)' }}>
          Create Backup
        </div>
        <div style={{ display: 'flex', gap: 'var(--space-sm)', alignItems: 'center' }}>
          <input
            type="text"
            placeholder="Reason (optional)"
            value={reason}
            onChange={e => setReason(e.target.value)}
            style={{
              flex: 1, background: 'var(--bg-base)', color: 'var(--text-primary)',
              border: '1px solid var(--border-default)', borderRadius: 'var(--radius-sm)',
              padding: '6px 10px', fontSize: 'var(--font-size-sm)',
            }}
          />
          <button
            onClick={handleCreate}
            disabled={creating}
            style={{
              background: 'var(--accent-primary)', color: 'var(--text-inverse)',
              border: 'none', borderRadius: 'var(--radius-sm)',
              padding: '6px 16px', fontWeight: 600, cursor: 'pointer',
              whiteSpace: 'nowrap',
            }}
          >
            {creating ? 'Creating...' : 'Create Backup'}
          </button>
        </div>
      </div>

      {statusMsg && (
        <div style={{
          fontSize: 'var(--font-size-sm)', color: 'var(--text-secondary)',
          marginBottom: 'var(--space-md)',
        }}>
          {statusMsg}
        </div>
      )}

      {/* Backup list */}
      {backups.length === 0 ? (
        <div style={{
          background: 'var(--bg-elevated)', border: '1px solid var(--border-default)',
          borderRadius: 'var(--radius-lg)', padding: 'var(--space-xl)', textAlign: 'center',
          color: 'var(--text-muted)',
        }}>
          No backups yet. Create one before making changes.
        </div>
      ) : (
        <div>
          <div style={{
            fontSize: 'var(--font-size-sm)', color: 'var(--text-secondary)',
            marginBottom: 'var(--space-sm)', fontWeight: 600,
          }}>
            Available backups ({backups.length})
          </div>
          {backups.map((b, i) => (
            <div key={b.path || i} style={{
              background: 'var(--bg-elevated)', border: '1px solid var(--border-default)',
              borderRadius: 'var(--radius-md)', padding: 'var(--space-sm) var(--space-md)',
              marginBottom: 'var(--space-xs)',
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            }}>
              <div>
                <div style={{
                  fontFamily: 'var(--font-mono)', fontSize: 'var(--font-size-xs)',
                  color: 'var(--text-primary)',
                }}>
                  {b.filename}
                </div>
                <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)' }}>
                  {b.timestamp ? new Date(b.timestamp).toLocaleString() : 'Unknown date'}
                  {b.reason && ` — ${b.reason}`}
                </div>
              </div>
              <button
                onClick={() => handleRestore(b.path, b.filename)}
                disabled={restoring}
                style={{
                  background: 'transparent', color: 'var(--text-secondary)',
                  border: '1px solid var(--border-default)', borderRadius: 'var(--radius-sm)',
                  padding: '2px 10px', fontSize: 'var(--font-size-xs)', cursor: 'pointer',
                }}
              >
                Restore
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default BackupRestore;
