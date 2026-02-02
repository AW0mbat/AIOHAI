import React from 'react';
import type { HealthSnapshot } from '../../types/electron';

interface DashboardViewProps {
  health: HealthSnapshot | null;
}

const ServiceCard: React.FC<{
  name: string;
  health: { status: string; latencyMs: number | null; error?: string } | undefined;
}> = ({ name, health }) => {
  const status = health?.status || 'unknown';
  const statusColors: Record<string, string> = {
    healthy: 'var(--status-healthy)',
    degraded: 'var(--status-degraded)',
    down: 'var(--status-down)',
    unknown: 'var(--status-unknown)',
  };

  return (
    <div style={{
      background: 'var(--bg-elevated)',
      border: '1px solid var(--border-default)',
      borderRadius: 'var(--radius-lg)',
      padding: 'var(--space-lg)',
      display: 'flex',
      flexDirection: 'column',
      gap: 'var(--space-sm)',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ fontWeight: 600, fontSize: 'var(--font-size-lg)' }}>{name}</span>
        <span className={`status-dot ${status}`} />
      </div>
      <div style={{
        fontFamily: 'var(--font-mono)',
        fontSize: 'var(--font-size-sm)',
        color: statusColors[status],
        textTransform: 'uppercase',
        letterSpacing: '0.08em',
        fontWeight: 600,
      }}>
        {status}
      </div>
      {health?.latencyMs !== null && health?.latencyMs !== undefined && (
        <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)' }}>
          {health.latencyMs}ms latency
        </div>
      )}
      {health?.error && (
        <div style={{
          fontSize: 'var(--font-size-xs)',
          color: 'var(--status-down)',
          fontFamily: 'var(--font-mono)',
        }}>
          {health.error}
        </div>
      )}
    </div>
  );
};

export const DashboardView: React.FC<DashboardViewProps> = ({ health }) => {
  return (
    <div>
      <h1 style={{
        fontSize: 'var(--font-size-2xl)',
        fontWeight: 700,
        marginBottom: 'var(--space-lg)',
      }}>
        Dashboard
      </h1>

      <div style={{ marginBottom: 'var(--space-lg)' }}>
        <h2 style={{
          fontSize: 'var(--font-size-base)',
          fontWeight: 600,
          color: 'var(--text-secondary)',
          textTransform: 'uppercase',
          letterSpacing: '0.1em',
          marginBottom: 'var(--space-md)',
        }}>
          Connection Health
        </h2>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: 'var(--space-md)',
        }}>
          <ServiceCard name="Open WebUI" health={health?.openWebUI} />
          <ServiceCard name="FIDO2 Server" health={health?.fido2} />
          <ServiceCard name="Ollama" health={health?.ollama} />
        </div>
      </div>

      <div style={{
        background: 'var(--bg-elevated)',
        border: '1px solid var(--border-default)',
        borderRadius: 'var(--radius-lg)',
        padding: 'var(--space-xl)',
        color: 'var(--text-muted)',
        textAlign: 'center',
      }}>
        <div style={{ fontSize: 'var(--font-size-lg)', marginBottom: 'var(--space-sm)' }}>
          Proxy Status, Transparency Reports, and Integrity Verification
        </div>
        <div style={{ fontSize: 'var(--font-size-sm)' }}>
          Coming in Phase 2
        </div>
      </div>
    </div>
  );
};
