import React from 'react';

/**
 * Placeholder components for panels not yet implemented.
 * Each will be replaced with a full implementation as we build them.
 */

const PlaceholderPanel: React.FC<{ title: string; description: string; buildOrder: number }> = ({
  title, description, buildOrder,
}) => (
  <div>
    <h1 style={{
      fontSize: 'var(--font-size-2xl)',
      fontWeight: 700,
      marginBottom: 'var(--space-lg)',
    }}>
      {title}
    </h1>
    <div style={{
      background: 'var(--bg-elevated)',
      border: '1px solid var(--border-default)',
      borderRadius: 'var(--radius-lg)',
      padding: 'var(--space-xl)',
      textAlign: 'center',
    }}>
      <div style={{
        fontSize: '3rem',
        marginBottom: 'var(--space-md)',
        opacity: 0.4,
      }}>
        🚧
      </div>
      <div style={{
        fontSize: 'var(--font-size-lg)',
        color: 'var(--text-primary)',
        marginBottom: 'var(--space-sm)',
      }}>
        {description}
      </div>
      <div style={{
        fontSize: 'var(--font-size-sm)',
        color: 'var(--text-muted)',
        fontFamily: 'var(--font-mono)',
      }}>
        Build priority: #{buildOrder} in Phase 1 sequence
      </div>
    </div>
  </div>
);

export const ChatPanel: React.FC = () => (
  <PlaceholderPanel
    title="Chat"
    description="Open WebUI chat with SSE streaming and inline approval cards"
    buildOrder={1}
  />
);

export const ApprovalsPanel: React.FC = () => (
  <PlaceholderPanel
    title="Approvals"
    description="Pending approval list with Windows Hello / FIDO2 flow"
    buildOrder={2}
  />
);

export const LogViewerPanel: React.FC = () => (
  <PlaceholderPanel
    title="Log Viewer"
    description="Live proxy log stream with severity filtering and search"
    buildOrder={3}
  />
);
