import React, { useState, useEffect, useCallback } from 'react';

/**
 * SecurityLevelEditor — Gate-grouped security level editor.
 *
 * Displays actions organized by gate (DENY, PHYSICAL, BIOMETRIC, SOFTWARE, PASSIVE)
 * with sliders for review depth adjustment within each gate.
 *
 * Key constraints:
 * - DENY gate section has NO controls — display only with lock icon.
 * - PHYSICAL/BIOMETRIC: review depth sliders only. No demotion controls.
 * - SOFTWARE/PASSIVE: full depth adjustment.
 * - Gate promotion buttons always available.
 * - "Log Request" button for rejected gate demotions.
 *
 * Phase 4 of Approval Gate Taxonomy v3 implementation.
 */

interface GateItem {
  category: string;
  domain: string;
  default_level: number;
  default_level_name: string;
  current_level: number;
  current_level_name: string;
  gate: string;
  is_overridden: boolean;
}

interface GateSection {
  name: string;
  icon: string;
  items: GateItem[];
  editable: boolean | string;
}

interface GatesData {
  [gateName: string]: GateSection;
}

interface SecurityLevelEditorProps {
  adminApiUrl: string;
  adminSecret: string;
}

const LEVEL_NAMES: Record<number, string> = {
  0: 'HARDBLOCK', 1: 'SOFTBLOCK',
  2: 'PHYSICAL_DETAILED', 3: 'PHYSICAL_STANDARD', 4: 'PHYSICAL_QUICK',
  5: 'BIOMETRIC_DETAILED', 6: 'BIOMETRIC_STANDARD', 7: 'BIOMETRIC_QUICK',
  8: 'CONFIRM_DETAILED', 9: 'CONFIRM_STANDARD', 10: 'CONFIRM_QUICK',
  11: 'NOTIFY_AND_PROCEED', 12: 'LOG_ONLY', 13: 'TRANSPARENT', 14: 'SILENT',
};

const GATE_RANGES: Record<string, [number, number]> = {
  DENY: [0, 1],
  PHYSICAL: [2, 4],
  BIOMETRIC: [5, 7],
  SOFTWARE: [8, 10],
  PASSIVE: [11, 14],
};

const GATE_COLORS: Record<string, string> = {
  DENY: 'var(--status-down)',
  PHYSICAL: 'var(--severity-warning)',
  BIOMETRIC: '#b060e0',
  SOFTWARE: 'var(--accent-primary)',
  PASSIVE: 'var(--text-secondary)',
};

// Domain display names
const DOMAIN_LABELS: Record<string, string> = {
  FS_TEMP: 'Temp files', FS_DL: 'Downloads', FS_DOC: 'Documents',
  FS_DOC_SENS: 'Sensitive docs', FS_DESK: 'Desktop', FS_MEDIA: 'Media',
  FS_APPCONF: 'App config', FS_AIOHAI: 'AIOHAI files', FS_SYSTEM: 'System',
  FS_CRED: 'Credentials', FS_NET: 'Network files',
  CMD_INFO: 'Info commands', CMD_FOPS: 'File ops', CMD_SVC: 'Services',
  CMD_INST: 'Install', CMD_SCRIPT: 'Scripts', CMD_NET: 'Net commands',
  CMD_ADMIN: 'Admin commands', CMD_DISK: 'Disk commands',
  HA_SENS: 'Sensors', HA_PRES: 'Presence', HA_LIGHT: 'Lights',
  HA_MEDIA: 'Media players', HA_CLIM: 'Climate', HA_COVER: 'Covers',
  HA_GARAGE: 'Garage', HA_LOCK: 'Locks', HA_ALARM: 'Alarm',
  HA_CAM: 'Cameras', HA_NOTIFY: 'Notifications', HA_SCENE: 'Scenes',
  HA_AUTO: 'Automations', HA_SCRIPT: 'HA Scripts', HA_HELPER: 'Helpers',
  HA_CONF: 'HA Config',
  OFF_DOC: 'Office docs', OFF_MACRO: 'Macros', OFF_EREAD: 'Email read',
  OFF_ESEND: 'Email send', OFF_CAL: 'Calendar', OFF_CONT: 'Contacts',
};

const CATEGORY_ICONS: Record<string, string> = {
  OBSERVE: '👁️', LIST: '📋', CREATE: '✨', MODIFY: '✏️', EXECUTE: '⚡',
  TRANSFER: '📤', DELETE: '🗑️', CONFIGURE: '⚙️', INSTALL: '📦', ADMIN: '🔑',
};

// Filter categories for the dropdown
const CATEGORY_OPTIONS = [
  { value: '', label: 'All categories' },
  { value: 'OBSERVE', label: '👁️ Observe' },
  { value: 'LIST', label: '📋 List' },
  { value: 'CREATE', label: '✨ Create' },
  { value: 'MODIFY', label: '✏️ Modify' },
  { value: 'EXECUTE', label: '⚡ Execute' },
  { value: 'TRANSFER', label: '📤 Transfer' },
  { value: 'DELETE', label: '🗑️ Delete' },
  { value: 'CONFIGURE', label: '⚙️ Configure' },
  { value: 'INSTALL', label: '📦 Install' },
  { value: 'ADMIN', label: '🔑 Admin' },
];

export const SecurityLevelEditor: React.FC<SecurityLevelEditorProps> = ({
  adminApiUrl, adminSecret,
}) => {
  const [gates, setGates] = useState<GatesData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [pendingChanges, setPendingChanges] = useState<Record<string, number>>({});
  const [saving, setSaving] = useState(false);
  const [categoryFilter, setCategoryFilter] = useState('');
  const [saveResult, setSaveResult] = useState<string | null>(null);

  const fetchGates = useCallback(async () => {
    try {
      const resp = await fetch(`${adminApiUrl}/api/admin/gates`, {
        headers: { 'X-Admin-Secret': adminSecret },
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      setGates(data);
      setError(null);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [adminApiUrl, adminSecret]);

  useEffect(() => { fetchGates(); }, [fetchGates]);

  const handleLevelChange = (key: string, newLevel: number) => {
    setPendingChanges(prev => ({ ...prev, [key]: newLevel }));
    setSaveResult(null);
  };

  const handleSave = async () => {
    setSaving(true);
    setSaveResult(null);
    try {
      const tierOverrides: Record<string, any> = {};
      for (const [key, level] of Object.entries(pendingChanges)) {
        tierOverrides[key] = { level, reason: 'Admin UI adjustment' };
      }

      const resp = await fetch(`${adminApiUrl}/api/admin/config/apply`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Admin-Secret': adminSecret,
        },
        body: JSON.stringify({ tier_overrides: tierOverrides }),
      });
      const result = await resp.json();

      if (result.success) {
        setPendingChanges({});
        setSaveResult(`✅ ${result.applied?.length || 0} changes applied`);
        fetchGates();
      } else {
        const rejectedMsg = result.rejected?.map((r: any) =>
          `${r.key}: ${r.reason}`
        ).join('; ') || '';
        setSaveResult(`⚠️ ${rejectedMsg || result.errors?.[0]?.error || 'Unknown error'}`);
      }
    } catch (e: any) {
      setSaveResult(`❌ ${e.message}`);
    } finally {
      setSaving(false);
    }
  };

  const handleReset = async () => {
    if (!confirm('Reset ALL overrides to defaults? This cannot be undone.')) return;
    setSaving(true);
    try {
      const resp = await fetch(`${adminApiUrl}/api/admin/config/reset`, {
        method: 'POST',
        headers: { 'X-Admin-Secret': adminSecret },
      });
      const result = await resp.json();
      if (result.success) {
        setPendingChanges({});
        setSaveResult(`✅ Reset ${result.overrides_removed} overrides`);
        fetchGates();
      }
    } catch (e: any) {
      setSaveResult(`❌ ${e.message}`);
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <div style={{ padding: 'var(--space-lg)', color: 'var(--text-muted)' }}>Loading security levels...</div>;
  if (error) return <div style={{ padding: 'var(--space-lg)', color: 'var(--status-down)' }}>Error: {error}</div>;
  if (!gates) return null;

  const hasPending = Object.keys(pendingChanges).length > 0;

  return (
    <div style={{ maxWidth: 900 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-lg)' }}>
        <h2 style={{ fontSize: 'var(--font-size-xl)', fontWeight: 700 }}>⚙️ Security Levels</h2>
        <select
          value={categoryFilter}
          onChange={e => setCategoryFilter(e.target.value)}
          style={{
            background: 'var(--bg-elevated)', color: 'var(--text-primary)',
            border: '1px solid var(--border-default)', borderRadius: 'var(--radius-sm)',
            padding: '4px 8px', fontSize: 'var(--font-size-sm)',
          }}
        >
          {CATEGORY_OPTIONS.map(opt => (
            <option key={opt.value} value={opt.value}>{opt.label}</option>
          ))}
        </select>
      </div>

      {Object.entries(gates).map(([gateName, gate]) => (
        <GateBlock
          key={gateName}
          gateName={gateName}
          gate={gate}
          categoryFilter={categoryFilter}
          pendingChanges={pendingChanges}
          onLevelChange={handleLevelChange}
        />
      ))}

      {/* Action bar */}
      <div style={{
        position: 'sticky', bottom: 0,
        background: 'var(--bg-surface)', borderTop: '1px solid var(--border-default)',
        padding: 'var(--space-md)', display: 'flex', alignItems: 'center', gap: 'var(--space-md)',
        marginTop: 'var(--space-lg)',
      }}>
        <button
          onClick={handleSave}
          disabled={!hasPending || saving}
          style={{
            background: hasPending ? 'var(--accent-primary)' : 'var(--bg-hover)',
            color: hasPending ? 'var(--text-inverse)' : 'var(--text-muted)',
            border: 'none', borderRadius: 'var(--radius-sm)',
            padding: '6px 16px', fontWeight: 600, cursor: hasPending ? 'pointer' : 'default',
          }}
        >
          {saving ? 'Saving...' : `Save Changes${hasPending ? ` (${Object.keys(pendingChanges).length})` : ''}`}
        </button>
        <button
          onClick={handleReset}
          disabled={saving}
          style={{
            background: 'transparent', color: 'var(--text-secondary)',
            border: '1px solid var(--border-default)', borderRadius: 'var(--radius-sm)',
            padding: '6px 16px', cursor: 'pointer',
          }}
        >
          Reset to Defaults
        </button>
        {saveResult && (
          <span style={{ fontSize: 'var(--font-size-sm)', color: 'var(--text-secondary)' }}>
            {saveResult}
          </span>
        )}
      </div>
    </div>
  );
};

// ---- Sub-components ----

const GateBlock: React.FC<{
  gateName: string;
  gate: GateSection;
  categoryFilter: string;
  pendingChanges: Record<string, number>;
  onLevelChange: (key: string, level: number) => void;
}> = ({ gateName, gate, categoryFilter, pendingChanges, onLevelChange }) => {
  const color = GATE_COLORS[gateName] || 'var(--text-muted)';
  const range = GATE_RANGES[gateName];
  const isDeny = gateName === 'DENY';

  const filteredItems = gate.items.filter(item =>
    !categoryFilter || item.category === categoryFilter
  );

  if (filteredItems.length === 0) return null;

  return (
    <div style={{
      marginBottom: 'var(--space-lg)',
      background: 'var(--bg-elevated)',
      border: `1px solid var(--border-default)`,
      borderRadius: 'var(--radius-lg)',
      overflow: 'hidden',
    }}>
      {/* Gate header */}
      <div style={{
        padding: 'var(--space-md)',
        borderBottom: '1px solid var(--border-subtle)',
        display: 'flex', alignItems: 'center', gap: 'var(--space-sm)',
      }}>
        <span style={{ fontSize: '1.2em' }}>{gate.icon}</span>
        <span style={{ fontWeight: 700, color, textTransform: 'uppercase', fontSize: 'var(--font-size-sm)', letterSpacing: '0.05em' }}>
          {gate.name} Gate
        </span>
        {isDeny && (
          <span style={{
            marginLeft: 'auto', fontSize: 'var(--font-size-xs)',
            color: 'var(--text-muted)', fontFamily: 'var(--font-mono)',
          }}>
            🔒 Cannot be changed — code only
          </span>
        )}
        {!isDeny && gate.editable === 'depth_only' && (
          <span style={{
            marginLeft: 'auto', fontSize: 'var(--font-size-xs)',
            color: 'var(--text-muted)',
          }}>
            Review depth only — gate cannot be changed at runtime
          </span>
        )}
      </div>

      {/* Items */}
      <div style={{ padding: 'var(--space-sm)' }}>
        {filteredItems.map(item => {
          const key = `${item.category}:${item.domain}`;
          const pendingLevel = pendingChanges[key];
          const effectiveLevel = pendingLevel ?? item.current_level;

          return (
            <div key={key} style={{
              display: 'flex', alignItems: 'center', gap: 'var(--space-md)',
              padding: 'var(--space-sm) var(--space-md)',
              borderRadius: 'var(--radius-sm)',
              background: item.is_overridden || pendingLevel !== undefined
                ? 'var(--bg-hover)' : 'transparent',
            }}>
              {/* Label */}
              <div style={{ width: 200, flexShrink: 0 }}>
                <span style={{ fontSize: '0.85em', marginRight: 4 }}>
                  {CATEGORY_ICONS[item.category] || '•'}
                </span>
                <span style={{ fontSize: 'var(--font-size-sm)', color: 'var(--text-primary)' }}>
                  {DOMAIN_LABELS[item.domain] || item.domain}
                </span>
                <span style={{
                  fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)',
                  marginLeft: 6, fontFamily: 'var(--font-mono)',
                }}>
                  {item.category}
                </span>
              </div>

              {/* Slider or lock */}
              <div style={{ flex: 1, display: 'flex', alignItems: 'center', gap: 'var(--space-sm)' }}>
                {isDeny ? (
                  <span style={{
                    fontSize: 'var(--font-size-xs)', color: 'var(--status-down)',
                    fontFamily: 'var(--font-mono)',
                  }}>
                    {item.current_level_name}
                  </span>
                ) : (
                  <>
                    <input
                      type="range"
                      min={range ? range[0] : 0}
                      max={range ? range[1] : 14}
                      value={effectiveLevel}
                      onChange={e => onLevelChange(key, parseInt(e.target.value))}
                      style={{ flex: 1, accentColor: color }}
                    />
                    <span style={{
                      width: 120, fontSize: 'var(--font-size-xs)',
                      fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)',
                      textAlign: 'right',
                    }}>
                      {LEVEL_NAMES[effectiveLevel] || `L${effectiveLevel}`}
                    </span>
                  </>
                )}
              </div>

              {/* Override indicator */}
              {(item.is_overridden || pendingLevel !== undefined) && (
                <span style={{
                  fontSize: 'var(--font-size-xs)',
                  color: pendingLevel !== undefined ? 'var(--severity-warning)' : 'var(--accent-primary)',
                }}>
                  {pendingLevel !== undefined ? '●' : '◆'}
                </span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default SecurityLevelEditor;
