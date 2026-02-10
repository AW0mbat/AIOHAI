import React, { useState } from 'react';
import { SecurityLevelEditor } from './SecurityLevelEditor';
import { SessionHistoryPanel } from './SessionHistoryPanel';
import { ProxyControl } from './ProxyControl';
import { BackupRestore } from './BackupRestore';

/**
 * AdminPanel — Container with tab navigation for all admin sections.
 *
 * Tabs: Security Levels | Sessions | Proxy Control | Backups
 *
 * Phase 4 of Approval Gate Taxonomy v3 implementation.
 */

interface AdminPanelProps {
  adminApiUrl: string;
  adminSecret: string;
}

const TABS = [
  { id: 'levels', label: '⚙️ Security Levels', icon: '⚙️' },
  { id: 'sessions', label: '🔓 Sessions', icon: '🔓' },
  { id: 'control', label: '🔧 Proxy Control', icon: '🔧' },
  { id: 'backups', label: '💾 Backups', icon: '💾' },
] as const;

type TabId = typeof TABS[number]['id'];

export const AdminPanel: React.FC<AdminPanelProps> = ({
  adminApiUrl, adminSecret,
}) => {
  const [activeTab, setActiveTab] = useState<TabId>('levels');

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* Tab bar */}
      <div style={{
        display: 'flex', gap: 0,
        borderBottom: '1px solid var(--border-default)',
        background: 'var(--bg-surface)',
        padding: '0 var(--space-md)',
        flexShrink: 0,
      }}>
        {TABS.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            style={{
              background: 'transparent',
              color: activeTab === tab.id ? 'var(--accent-primary)' : 'var(--text-secondary)',
              border: 'none',
              borderBottom: activeTab === tab.id ? '2px solid var(--accent-primary)' : '2px solid transparent',
              padding: 'var(--space-sm) var(--space-md)',
              fontSize: 'var(--font-size-sm)',
              fontWeight: activeTab === tab.id ? 600 : 400,
              cursor: 'pointer',
              transition: 'color var(--transition-fast), border-color var(--transition-fast)',
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div style={{
        flex: 1, overflow: 'auto',
        padding: 'var(--space-lg)',
      }}>
        {activeTab === 'levels' && (
          <SecurityLevelEditor adminApiUrl={adminApiUrl} adminSecret={adminSecret} />
        )}
        {activeTab === 'sessions' && (
          <SessionHistoryPanel adminApiUrl={adminApiUrl} adminSecret={adminSecret} />
        )}
        {activeTab === 'control' && (
          <ProxyControl adminApiUrl={adminApiUrl} adminSecret={adminSecret} />
        )}
        {activeTab === 'backups' && (
          <BackupRestore adminApiUrl={adminApiUrl} adminSecret={adminSecret} />
        )}
      </div>
    </div>
  );
};

export default AdminPanel;
