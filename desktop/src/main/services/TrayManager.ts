import { Tray, Menu, nativeImage, app, BrowserWindow, Notification } from 'electron';
import * as path from 'path';

/**
 * TrayManager — System tray icon with context menu.
 * 
 * Minimizes to tray. Shows notification badge when approvals are pending.
 * Clicking the tray icon restores the main window.
 */

export class TrayManager {
  private tray: Tray | null = null;
  private window: BrowserWindow;
  private onRestore: () => void;
  private pendingCount: number = 0;

  constructor(window: BrowserWindow, onRestore: () => void) {
    this.window = window;
    this.onRestore = onRestore;
    this.create();
  }

  private create(): void {
    const iconPath = path.join(__dirname, '../../../resources/icon.png');

    // Create a simple default icon if the file doesn't exist yet
    let icon: Electron.NativeImage;
    try {
      icon = nativeImage.createFromPath(iconPath);
      if (icon.isEmpty()) {
        icon = this.createDefaultIcon();
      }
    } catch {
      icon = this.createDefaultIcon();
    }

    this.tray = new Tray(icon);
    this.tray.setToolTip('AIOHAI Desktop');
    this.updateContextMenu();

    this.tray.on('click', () => {
      this.onRestore();
    });
  }

  /**
   * Create a minimal fallback icon (16x16 blue square).
   */
  private createDefaultIcon(): Electron.NativeImage {
    return nativeImage.createFromBuffer(
      Buffer.alloc(16 * 16 * 4, 0),
      { width: 16, height: 16 }
    );
  }

  /**
   * Update the pending approval count shown in the tray tooltip and context menu.
   */
  setPendingCount(count: number): void {
    const wasZero = this.pendingCount === 0;
    this.pendingCount = count;

    if (this.tray) {
      this.tray.setToolTip(
        count > 0
          ? `AIOHAI Desktop — ${count} pending approval${count > 1 ? 's' : ''}`
          : 'AIOHAI Desktop'
      );
      this.updateContextMenu();
    }

    // Notify if new approvals appeared and window is hidden
    if (wasZero && count > 0 && !this.window.isVisible()) {
      this.showNotification(count);
    }
  }

  private showNotification(count: number): void {
    if (Notification.isSupported()) {
      const notification = new Notification({
        title: 'AIOHAI — Approval Required',
        body: `${count} action${count > 1 ? 's' : ''} waiting for your approval`,
        icon: path.join(__dirname, '../../../resources/icon.png'),
      });

      notification.on('click', () => {
        this.onRestore();
      });

      notification.show();
    }
  }

  private updateContextMenu(): void {
    const contextMenu = Menu.buildFromTemplate([
      {
        label: this.pendingCount > 0
          ? `⚠ ${this.pendingCount} Pending Approval${this.pendingCount > 1 ? 's' : ''}`
          : '✓ No Pending Approvals',
        enabled: this.pendingCount > 0,
        click: () => this.onRestore(),
      },
      { type: 'separator' },
      { label: 'Open AIOHAI Desktop', click: () => this.onRestore() },
      { type: 'separator' },
      {
        label: 'Quit',
        click: () => {
          app.quit();
        },
      },
    ]);

    this.tray?.setContextMenu(contextMenu);
  }

  destroy(): void {
    if (this.tray) {
      this.tray.destroy();
      this.tray = null;
    }
  }
}
