import { contextBridge, ipcRenderer } from 'electron';

/**
 * Preload script — the security boundary between Node.js and the renderer.
 * 
 * Only the methods exposed here are available to the React UI.
 * The renderer CANNOT access fs, child_process, or any Node APIs directly.
 */

export interface LogLine {
  timestamp: string;
  severity: 'DEBUG' | 'INFO' | 'WARNING' | 'ERROR' | 'CRITICAL';
  message: string;
  raw: string;
}

export interface HealthSnapshot {
  openWebUI: ServiceHealth;
  fido2: ServiceHealth;
  ollama: ServiceHealth;
  timestamp: string;
}

export interface ServiceHealth {
  status: 'healthy' | 'degraded' | 'down' | 'unknown';
  latencyMs: number | null;
  lastChecked: string;
  error?: string;
}

export interface ConfigJSON {
  [key: string]: unknown;
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
}

// ─── Exposed API ───────────────────────────────────────────
const electronAPI = {
  // Log streaming
  logs: {
    readRecent: (count: number): Promise<LogLine[]> =>
      ipcRenderer.invoke('logs:readRecent', count),

    onNewLine: (callback: (line: LogLine) => void): (() => void) => {
      const handler = (_event: Electron.IpcRendererEvent, line: LogLine) => callback(line);
      ipcRenderer.on('logs:newLine', handler);
      // Return unsubscribe function
      return () => ipcRenderer.removeListener('logs:newLine', handler);
    },
  },

  // Config management
  config: {
    read: (): Promise<ConfigJSON | null> =>
      ipcRenderer.invoke('config:read'),

    validate: (proposed: ConfigJSON): Promise<ValidationResult> =>
      ipcRenderer.invoke('config:validate', proposed),
  },

  // Health monitoring
  health: {
    checkNow: (): Promise<HealthSnapshot | null> =>
      ipcRenderer.invoke('health:checkNow'),

    onUpdate: (callback: (snapshot: HealthSnapshot) => void): (() => void) => {
      const handler = (_event: Electron.IpcRendererEvent, snapshot: HealthSnapshot) => callback(snapshot);
      ipcRenderer.on('health:update', handler);
      return () => ipcRenderer.removeListener('health:update', handler);
    },
  },

  // Integrity (Phase 2)
  integrity: {
    check: (): Promise<unknown> =>
      ipcRenderer.invoke('integrity:check'),
  },

  // App info and window controls
  app: {
    getVersion: (): Promise<string> =>
      ipcRenderer.invoke('app:getVersion'),

    getAIOHAIPath: (): Promise<string | null> =>
      ipcRenderer.invoke('app:getAIOHAIPath'),

    minimize: (): void =>
      ipcRenderer.send('app:minimize'),

    close: (): void =>
      ipcRenderer.send('app:close'),
  },
};

// Expose to renderer as window.electronAPI
contextBridge.exposeInMainWorld('electronAPI', electronAPI);

// Type declaration for the renderer to use
export type ElectronAPI = typeof electronAPI;
