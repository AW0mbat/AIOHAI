import React from 'react';

export type NavPage = 'chat' | 'approvals' | 'dashboard' | 'logs' | 'settings' | 'admin';

interface SidebarProps {
  activePage: NavPage;
  onNavigate: (page: NavPage) => void;
  pendingApprovals: number;
}

const navItems: { id: NavPage; label: string; icon: string }[] = [
  { id: 'chat',      label: 'Chat',       icon: '💬' },
  { id: 'approvals', label: 'Approvals',  icon: '🔐' },
  { id: 'dashboard', label: 'Dashboard',  icon: '📊' },
  { id: 'logs',      label: 'Logs',       icon: '📋' },
  { id: 'settings',  label: 'Settings',   icon: '⚙️' },
  { id: 'admin',     label: 'Admin',      icon: '🛡️' },
];

export const Sidebar: React.FC<SidebarProps> = ({ activePage, onNavigate, pendingApprovals }) => {
  return (
    <div className="app-sidebar">
      <div className="nav-header">
        <span className="nav-logo">AIOHAI</span>
        <span className="nav-version">Desktop</span>
      </div>

      <nav className="nav-section" style={{ flex: 1 }}>
        {navItems.map((item) => (
          <div
            key={item.id}
            className={`nav-item ${activePage === item.id ? 'active' : ''}`}
            onClick={() => onNavigate(item.id)}
          >
            <span>{item.icon}</span>
            <span>{item.label}</span>
            {item.id === 'approvals' && pendingApprovals > 0 && (
              <span className="badge">{pendingApprovals}</span>
            )}
          </div>
        ))}
      </nav>

      <div className="nav-section" style={{ borderTop: '1px solid var(--border-subtle)' }}>
        <div className="nav-item" style={{ color: 'var(--text-muted)', fontSize: 'var(--font-size-xs)' }}>
          <span className="mono">v0.1.0</span>
        </div>
      </div>
    </div>
  );
};
