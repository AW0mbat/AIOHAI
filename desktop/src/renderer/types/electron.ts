/**
 * Type declarations for the Electron preload bridge.
 * These types must match what's exposed in preload.ts via contextBridge.
 */

export interface LogLine {
  timestamp: string;
  severity: 'DEBUG' | 'INFO' | 'WARNING' | 'ERROR' | 'CRITICAL';
  message: string;
  raw: string;
}

export interface ServiceHealth {
  status: 'healthy' | 'degraded' | 'down' | 'unknown';
  latencyMs: number | null;
  lastChecked: string;
  error?: string;
}

export interface HealthSnapshot {
  openWebUI: ServiceHealth;
  fido2: ServiceHealth;
  ollama: ServiceHealth;
  timestamp: string;
}

export interface ConfigJSON {
  [key: string]: unknown;
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
}

export interface ElectronAPI {
  logs: {
    readRecent: (count: number) => Promise<LogLine[]>;
    onNewLine: (callback: (line: LogLine) => void) => () => void;
  };
  config: {
    read: () => Promise<ConfigJSON | null>;
    validate: (proposed: ConfigJSON) => Promise<ValidationResult>;
  };
  health: {
    checkNow: () => Promise<HealthSnapshot | null>;
    onUpdate: (callback: (snapshot: HealthSnapshot) => void) => () => void;
  };
  integrity: {
    check: () => Promise<unknown>;
  };
  app: {
    getVersion: () => Promise<string>;
    getAIOHAIPath: () => Promise<string | null>;
    minimize: () => void;
    close: () => void;
  };
}

declare global {
  interface Window {
    electronAPI: ElectronAPI;
  }
}
