/**
 * HealthMonitor — Periodic health checks for all AIOHAI services.
 * 
 * Runs in the main process. Polls each service at a configurable interval
 * and pushes snapshots to registered callbacks (which forward to the renderer).
 */

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

interface HealthMonitorConfig {
  openWebUIUrl: string;
  fido2Url: string;
  ollamaUrl: string;
  pollIntervalMs: number;
}

type HealthCallback = (snapshot: HealthSnapshot) => void;

export class HealthMonitor {
  private config: HealthMonitorConfig;
  private timer: ReturnType<typeof setInterval> | null = null;
  private callbacks: HealthCallback[] = [];
  private lastSnapshot: HealthSnapshot | null = null;

  constructor(config: HealthMonitorConfig) {
    this.config = config;
    this.start();
  }

  onUpdate(callback: HealthCallback): void {
    this.callbacks.push(callback);
    // Send current state immediately if available
    if (this.lastSnapshot) {
      callback(this.lastSnapshot);
    }
  }

  async checkAll(): Promise<HealthSnapshot> {
    const [openWebUI, fido2, ollama] = await Promise.all([
      this.checkService(this.config.openWebUIUrl, '/api/config'),
      this.checkService(this.config.fido2Url, '/api/health'),
      this.checkService(this.config.ollamaUrl, '/api/tags'),
    ]);

    const snapshot: HealthSnapshot = {
      openWebUI,
      fido2,
      ollama,
      timestamp: new Date().toISOString(),
    };

    this.lastSnapshot = snapshot;
    return snapshot;
  }

  private async checkService(baseUrl: string, healthPath: string): Promise<ServiceHealth> {
    const start = Date.now();
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);

      const response = await fetch(`${baseUrl}${healthPath}`, {
        signal: controller.signal,
        // Accept self-signed certs for FIDO2 server
        // Note: In Electron main process, we may need to handle this differently
      });

      clearTimeout(timeout);
      const latencyMs = Date.now() - start;

      if (response.ok) {
        return {
          status: 'healthy',
          latencyMs,
          lastChecked: new Date().toISOString(),
        };
      } else {
        return {
          status: 'degraded',
          latencyMs,
          lastChecked: new Date().toISOString(),
          error: `HTTP ${response.status}`,
        };
      }
    } catch (err) {
      return {
        status: 'down',
        latencyMs: null,
        lastChecked: new Date().toISOString(),
        error: err instanceof Error ? err.message : 'Unknown error',
      };
    }
  }

  private start(): void {
    // Initial check
    this.checkAll().then((snapshot) => {
      this.callbacks.forEach((cb) => cb(snapshot));
    });

    // Periodic checks
    this.timer = setInterval(async () => {
      const snapshot = await this.checkAll();
      this.callbacks.forEach((cb) => cb(snapshot));
    }, this.config.pollIntervalMs);
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }
}
