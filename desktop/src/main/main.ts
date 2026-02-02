import { app, BrowserWindow, Tray, Menu, nativeImage, ipcMain } from 'electron';
import * as path from 'path';
import { HealthMonitor } from './services/HealthMonitor';
import { LogWatcher } from './services/LogWatcher';
import { ConfigManager } from './services/ConfigManager';
import { TrayManager } from './services/TrayManager';

// ─── Globals ───────────────────────────────────────────────
let mainWindow: BrowserWindow | null = null;
let trayManager: TrayManager | null = null;
let healthMonitor: HealthMonitor | null = null;
let logWatcher: LogWatcher | null = null;
let configManager: ConfigManager | null = null;
let isQuitting = false;

const isDev = !app.isPackaged;

// ─── Window Creation ───────────────────────────────────────
function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 900,
    minHeight: 600,
    title: 'AIOHAI Desktop',
    icon: path.join(__dirname, '../../resources/icon.png'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,     // Security: renderer can't access Node
      nodeIntegration: false,     // Security: no require() in renderer
      webviewTag: true,           // Needed for FIDO2 approval modal
      sandbox: false,             // Needed for preload script IPC
    },
    // We'll add a custom titlebar later; for now use the default
    frame: true,
    backgroundColor: '#0a0a0f',
  });

  // Load the renderer
  if (isDev) {
    // In dev mode, Vite serves the renderer on port 5173
    mainWindow.loadURL('http://localhost:5173');
    mainWindow.webContents.openDevTools();
  } else {
    // In production, load the built HTML
    mainWindow.loadFile(path.join(__dirname, '../renderer/index.html'));
  }

  // Minimize to tray instead of closing
  mainWindow.on('close', (event) => {
    if (trayManager && !isQuitting) {
      event.preventDefault();
      mainWindow?.hide();
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// ─── IPC Handlers ──────────────────────────────────────────
function registerIPC(): void {
  // Health
  ipcMain.handle('health:checkNow', async () => {
    return healthMonitor?.checkAll() ?? null;
  });

  // Logs
  ipcMain.handle('logs:readRecent', async (_event, count: number) => {
    return logWatcher?.readRecent(count) ?? [];
  });

  // Log streaming is handled via mainWindow.webContents.send()
  // from LogWatcher — see LogWatcher.ts

  // Config
  ipcMain.handle('config:read', async () => {
    return configManager?.read() ?? null;
  });

  ipcMain.handle('config:validate', async (_event, proposed: unknown) => {
    return configManager?.validate(proposed) ?? { valid: false, errors: ['ConfigManager not initialized'] };
  });

  // Integrity (Phase 2 — stub)
  ipcMain.handle('integrity:check', async () => {
    return { status: 'not_implemented', message: 'Integrity checking available in Phase 2' };
  });

  // App info
  ipcMain.handle('app:getVersion', async () => {
    return app.getVersion();
  });

  ipcMain.handle('app:getAIOHAIPath', async () => {
    return configManager?.getAIOHAIPath() ?? null;
  });

  // Window controls
  ipcMain.on('app:minimize', () => mainWindow?.minimize());
  ipcMain.on('app:close', () => mainWindow?.close());
}

// ─── Services ──────────────────────────────────────────────
function initializeServices(): void {
  const aiohaiPath = process.env.AIOHAI_HOME || 'C:\\AIOHAI';

  configManager = new ConfigManager(aiohaiPath);

  healthMonitor = new HealthMonitor({
    openWebUIUrl: 'http://localhost:3000',   // Will be configurable via first-run setup
    fido2Url: 'https://localhost:8443',
    ollamaUrl: 'http://localhost:11434',
    pollIntervalMs: 10000,
  });

  logWatcher = new LogWatcher(
    path.join(aiohaiPath, 'logs'),
    (line) => {
      // Stream log lines to the renderer
      mainWindow?.webContents.send('logs:newLine', line);
    }
  );

  // Health updates pushed to renderer
  healthMonitor.onUpdate((snapshot) => {
    mainWindow?.webContents.send('health:update', snapshot);
  });

  trayManager = new TrayManager(mainWindow!, () => {
    mainWindow?.show();
    mainWindow?.focus();
  });
}

// ─── App Lifecycle ─────────────────────────────────────────
app.whenReady().then(() => {
  createWindow();
  registerIPC();
  initializeServices();
});

app.on('window-all-closed', () => {
  // On Windows, don't quit when windows close (tray keeps running)
  // But if tray is gone, quit
  if (!trayManager) {
    app.quit();
  }
});

app.on('before-quit', () => {
  isQuitting = true;
  healthMonitor?.stop();
  logWatcher?.stop();
  trayManager?.destroy();
});

app.on('activate', () => {
  if (mainWindow === null) {
    createWindow();
  }
});
