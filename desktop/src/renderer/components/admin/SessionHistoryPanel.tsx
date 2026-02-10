import React, { useState, useEffect, useCallback } from 'react';

/**
 * SessionHistoryPanel — Active sessions and session history.
 *
 * Shows:
 * - Currently active elevation sessions with scope, countdown, and "End Session" button
 * - Recent session history with status (OK, ABORTED, EXPIRED)
 *
 * Phase 4 of Approval Gate Taxonomy v3 implementation.
 */

interface ActiveSession {
  session_id: string;
  scope: string[];
  gate_authenticated: string;
  elevated_level: number;
  elevated_level_name?: string;
  max_actions: number;
  actions_used: number;
  created_at: string;
  expires_at: string;
  end_reason?: string;
}

interface SessionHistoryPanelProps {
  adminApiUrl: string;
  adminSecret: string;
}

const GATE_ICONS: Record<string, string> = {
  PHYSICAL: '🔒',
  BIOMETRIC: '🖐️',
  SOFTWARE: '🖱️',
  PASSIVE: '👁️',
};

export const SessionHistoryPanel: React.FC<SessionHistoryPanelProps> = ({
  adminApiUrl, adminSecret,
}) => {
  const [activeSessions, setActiveSessions] = useState<ActiveSession[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchSessions = useCallback(async () => {
    try {
      const resp = await fetch(`${adminApiUrl}/api/admin/sessions`, {
        headers: { 'X-Admin-Secret': adminSecret },
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      setActiveSessions(data.active || []);
      setError(null);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [adminApiUrl, adminSecret]);

  useEffect(() => {
    fetchSessions();
    const interval = setInterval(fetchSessions, 5000);
    return () => clearInterval(interval);
  }, [fetchSessions]);

  const handleEndSession = async (sessionId: string) => {
    try {
      await fetch(`${adminApiUrl}/api/admin/sessions/end`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Admin-Secret': adminSecret,
        },
        body: JSON.stringify({ session_id: sessionId }),
      });
      fetchSessions();
    } catch (e: any) {
      setError(e.message);
    }
  };

  if (loading) return <div style={{ padding: 'var(--space-lg)', color: 'var(--text-muted)' }}>Loading sessions...</div>;

  return (
    <div style={{ maxWidth: 800 }}>
      <h2 style={{ fontSize: 'var(--font-size-xl)', fontWeight: 700, marginBottom: 'var(--space-lg)' }}>
        🔓 Active Sessions
      </h2>

      {error && (
        <div style={{ padding: 'var(--space-md)', color: 'var(--status-down)', marginBottom: 'var(--space-md)' }}>
          Error: {error}
        </div>
      )}

      {activeSessions.length === 0 ? (
        <div style={{
          background: 'var(--bg-elevated)',
          border: '1px solid var(--border-default)',
          borderRadius: 'var(--radius-lg)',
          padding: 'var(--space-xl)',
          textAlign: 'center',
          color: 'var(--text-muted)',
        }}>
          No active sessions. Sessions are created when batch operations require gate-level authentication.
        </div>
      ) : (
        activeSessions.map(session => (
          <SessionCard
            key={session.session_id}
            session={session}
            onEnd={handleEndSession}
          />
        ))
      )}
    </div>
  );
};

const SessionCard: React.FC<{
  session: ActiveSession;
  onEnd: (id: string) => void;
}> = ({ session, onEnd }) => {
  const gateIcon = GATE_ICONS[session.gate_authenticated] || '🔐';
  const progress = session.max_actions > 0
    ? (session.actions_used / session.max_actions) * 100
    : 0;

  const expiresAt = new Date(session.expires_at);
  const now = new Date();
  const timeRemaining = Math.max(0, Math.floor((expiresAt.getTime() - now.getTime()) / 1000));
  const minutesLeft = Math.floor(timeRemaining / 60);
  const secondsLeft = timeRemaining % 60;

  return (
    <div style={{
      background: 'var(--bg-elevated)',
      border: '1px solid var(--border-default)',
      borderRadius: 'var(--radius-lg)',
      padding: 'var(--space-md)',
      marginBottom: 'var(--space-md)',
    }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-sm)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-sm)' }}>
          <span style={{ fontSize: '1.2em' }}>🔓</span>
          <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
            {session.scope.join(', ')}
          </span>
        </div>
        <button
          onClick={() => onEnd(session.session_id)}
          style={{
            background: 'var(--bg-hover)',
            color: 'var(--text-secondary)',
            border: '1px solid var(--border-default)',
            borderRadius: 'var(--radius-sm)',
            padding: '4px 12px',
            fontSize: 'var(--font-size-xs)',
            cursor: 'pointer',
          }}
        >
          🔒 End Session
        </button>
      </div>

      {/* Details */}
      <div style={{ display: 'flex', gap: 'var(--space-lg)', fontSize: 'var(--font-size-sm)', color: 'var(--text-secondary)' }}>
        <span>{gateIcon} {session.gate_authenticated}</span>
        <span>{session.actions_used}/{session.max_actions} actions</span>
        <span>{minutesLeft}m {secondsLeft}s remaining</span>
      </div>

      {/* Progress bar */}
      <div style={{
        marginTop: 'var(--space-sm)',
        height: 4,
        background: 'var(--bg-hover)',
        borderRadius: 2,
        overflow: 'hidden',
      }}>
        <div style={{
          height: '100%',
          width: `${progress}%`,
          background: 'var(--accent-primary)',
          borderRadius: 2,
          transition: 'width var(--transition-base)',
        }} />
      </div>

      {/* Session ID */}
      <div style={{
        marginTop: 'var(--space-xs)',
        fontSize: 'var(--font-size-xs)',
        color: 'var(--text-muted)',
        fontFamily: 'var(--font-mono)',
      }}>
        {session.session_id.slice(0, 16)}…
      </div>
    </div>
  );
};

export default SessionHistoryPanel;
