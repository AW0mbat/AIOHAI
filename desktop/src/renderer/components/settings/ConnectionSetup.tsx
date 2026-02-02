import React, { useState } from 'react';
import { OpenWebUIClient, type ConnectionTestResult } from '../../services/OpenWebUIClient';

interface ConnectionSetupProps {
  onConnected: (baseUrl: string, apiKey: string) => void;
}

export const ConnectionSetup: React.FC<ConnectionSetupProps> = ({ onConnected }) => {
  const [baseUrl, setBaseUrl] = useState('http://localhost:8090');
  const [apiKey, setApiKey] = useState('');
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<ConnectionTestResult | null>(null);

  const handleTest = async () => {
    setTesting(true);
    setResult(null);

    const client = new OpenWebUIClient({ baseUrl, apiKey });
    const testResult = await client.testConnection();
    setResult(testResult);
    setTesting(false);
  };

  const handleConnect = () => {
    if (result?.success) {
      onConnected(baseUrl, apiKey);
    }
  };

  return (
    <div>
      <h1 style={{
        fontSize: 'var(--font-size-2xl)',
        fontWeight: 700,
        marginBottom: 'var(--space-sm)',
      }}>
        Connection Setup
      </h1>
      <p style={{
        color: 'var(--text-secondary)',
        marginBottom: 'var(--space-xl)',
        fontSize: 'var(--font-size-sm)',
      }}>
        Connect to your Open WebUI instance to get started.
      </p>

      <div style={{
        background: 'var(--bg-elevated)',
        border: '1px solid var(--border-default)',
        borderRadius: 'var(--radius-lg)',
        padding: 'var(--space-xl)',
        maxWidth: 520,
      }}>
        {/* URL Input */}
        <div style={{ marginBottom: 'var(--space-lg)' }}>
          <label style={{
            display: 'block',
            fontSize: 'var(--font-size-sm)',
            fontWeight: 600,
            color: 'var(--text-secondary)',
            marginBottom: 'var(--space-xs)',
          }}>
            Open WebUI URL
          </label>
          <input
            type="text"
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder="http://localhost:3000"
            style={{
              width: '100%',
              padding: '10px 14px',
              background: 'var(--bg-base)',
              border: '1px solid var(--border-default)',
              borderRadius: 'var(--radius-md)',
              color: 'var(--text-primary)',
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--font-size-sm)',
              outline: 'none',
            }}
            onFocus={(e) => e.target.style.borderColor = 'var(--accent-primary)'}
            onBlur={(e) => e.target.style.borderColor = 'var(--border-default)'}
          />
        </div>

        {/* API Key Input */}
        <div style={{ marginBottom: 'var(--space-lg)' }}>
          <label style={{
            display: 'block',
            fontSize: 'var(--font-size-sm)',
            fontWeight: 600,
            color: 'var(--text-secondary)',
            marginBottom: 'var(--space-xs)',
          }}>
            API Key
          </label>
          <input
            type="password"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            placeholder="sk-..."
            style={{
              width: '100%',
              padding: '10px 14px',
              background: 'var(--bg-base)',
              border: '1px solid var(--border-default)',
              borderRadius: 'var(--radius-md)',
              color: 'var(--text-primary)',
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--font-size-sm)',
              outline: 'none',
            }}
            onFocus={(e) => e.target.style.borderColor = 'var(--accent-primary)'}
            onBlur={(e) => e.target.style.borderColor = 'var(--border-default)'}
          />
          <div style={{
            fontSize: 'var(--font-size-xs)',
            color: 'var(--text-muted)',
            marginTop: 'var(--space-xs)',
          }}>
            Open WebUI → Settings → Account → API Keys → Create new secret key
          </div>
        </div>

        {/* Test Button */}
        <button
          onClick={handleTest}
          disabled={testing || !baseUrl || !apiKey}
          style={{
            width: '100%',
            padding: '12px',
            background: testing ? 'var(--bg-active)' : 'var(--accent-primary)',
            color: testing ? 'var(--text-secondary)' : 'var(--text-inverse)',
            border: 'none',
            borderRadius: 'var(--radius-md)',
            fontSize: 'var(--font-size-sm)',
            fontWeight: 600,
            fontFamily: 'var(--font-body)',
            cursor: testing ? 'wait' : 'pointer',
            transition: 'all var(--transition-fast)',
            opacity: (!baseUrl || !apiKey) ? 0.4 : 1,
          }}
        >
          {testing ? 'Testing Connection...' : 'Test Connection'}
        </button>

        {/* Result */}
        {result && (
          <div style={{
            marginTop: 'var(--space-lg)',
            padding: 'var(--space-md)',
            background: result.success ? 'rgba(0, 212, 122, 0.08)' : 'rgba(240, 64, 64, 0.08)',
            border: `1px solid ${result.success ? 'var(--status-healthy)' : 'var(--status-down)'}`,
            borderRadius: 'var(--radius-md)',
          }}>
            {result.success ? (
              <div>
                <div style={{
                  color: 'var(--status-healthy)',
                  fontWeight: 600,
                  marginBottom: 'var(--space-sm)',
                }}>
                  ✓ Connected Successfully
                </div>
                <div style={{
                  fontSize: 'var(--font-size-xs)',
                  color: 'var(--text-secondary)',
                  fontFamily: 'var(--font-mono)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 4,
                }}>
                  <span>User: {result.user}</span>
                  <span>Models available: {result.models}</span>
                  <span>Latency: {result.latencyMs}ms</span>
                </div>

                <button
                  onClick={handleConnect}
                  style={{
                    marginTop: 'var(--space-md)',
                    width: '100%',
                    padding: '12px',
                    background: 'var(--accent-primary)',
                    color: 'var(--text-inverse)',
                    border: 'none',
                    borderRadius: 'var(--radius-md)',
                    fontSize: 'var(--font-size-sm)',
                    fontWeight: 600,
                    fontFamily: 'var(--font-body)',
                    cursor: 'pointer',
                  }}
                >
                  Save & Continue →
                </button>
              </div>
            ) : (
              <div>
                <div style={{
                  color: 'var(--status-down)',
                  fontWeight: 600,
                  marginBottom: 'var(--space-sm)',
                }}>
                  ✗ Connection Failed
                </div>
                <div style={{
                  fontSize: 'var(--font-size-xs)',
                  color: 'var(--text-secondary)',
                  fontFamily: 'var(--font-mono)',
                }}>
                  {result.error}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
