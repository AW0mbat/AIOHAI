import React from 'react';
import type { HealthSnapshot } from '../types/electron';

interface StatusBarProps {
  health: HealthSnapshot | null;
  pendingApprovals: number;
}

export const StatusBar: React.FC<StatusBarProps> = ({ health, pendingApprovals }) => {
  const dot = (status: string | undefined) => {
    const s = status || 'unknown';
    return <span className={`status-dot ${s}`} />;
  };

  return (
    <div className="app-statusbar">
      <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
        {dot(health?.openWebUI.status)} Open WebUI
      </span>
      <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
        {dot(health?.fido2.status)} FIDO2
      </span>
      <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
        {dot(health?.ollama.status)} Ollama
      </span>

      <span style={{ marginLeft: 'auto' }}>
        {pendingApprovals > 0 ? (
          <span style={{ color: 'var(--status-down)', fontWeight: 600 }}>
            ⚠ {pendingApprovals} pending
          </span>
        ) : (
          <span style={{ color: 'var(--text-muted)' }}>No pending approvals</span>
        )}
      </span>
    </div>
  );
};
