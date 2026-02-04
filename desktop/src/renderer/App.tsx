import React, { useState, useMemo } from 'react';
import { Sidebar, type NavPage } from './components/layout/Sidebar';
import { StatusBar } from './components/layout/StatusBar';
import { DashboardView } from './components/dashboard/DashboardView';
import { ConnectionSetup } from './components/settings/ConnectionSetup';
import { ChatPanel } from './components/chat';
import { ApprovalsPanel, LogViewerPanel } from './components/Placeholders';
import { OpenWebUIClient } from './services/OpenWebUIClient';
import { useHealth } from './hooks/useHealth';
import './types/electron';

const App: React.FC = () => {
  const [activePage, setActivePage] = useState<NavPage>('settings');
  const health = useHealth();

  // Connection state — in Phase 2 this will be persisted via Electron safeStorage
  const [connection, setConnection] = useState<{ baseUrl: string; apiKey: string } | null>(null);

  // Create the API client when connection is configured
  const client = useMemo(() => {
    if (!connection) return null;
    return new OpenWebUIClient(connection);
  }, [connection?.baseUrl, connection?.apiKey]);

  const isConnected = connection !== null;
  const pendingApprovals = 0;

  const handleConnected = (baseUrl: string, apiKey: string) => {
    setConnection({ baseUrl, apiKey });
    setActivePage('dashboard');
  };

  const renderPage = () => {
    switch (activePage) {
      case 'chat':
        return <ChatPanel client={client} />;
      case 'approvals':
        return <ApprovalsPanel />;
      case 'dashboard':
        return <DashboardView health={health} />;
      case 'logs':
        return <LogViewerPanel />;
      case 'settings':
        return (
          <ConnectionSetup
            onConnected={handleConnected}
          />
        );
      default:
        return <DashboardView health={health} />;
    }
  };

  return (
    <div className="app-layout">
      <Sidebar
        activePage={activePage}
        onNavigate={setActivePage}
        pendingApprovals={pendingApprovals}
      />
      <div className="app-main">
        <div className="app-content">
          {renderPage()}
        </div>
        <StatusBar health={health} pendingApprovals={pendingApprovals} />
      </div>
    </div>
  );
};

export default App;
