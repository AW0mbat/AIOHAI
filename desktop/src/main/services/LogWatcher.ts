import * as fs from 'fs';
import * as path from 'path';

/**
 * LogWatcher — Tails the proxy log directory.
 * 
 * Watches the logs/ directory for changes, reads new lines from the most
 * recent log file, and streams parsed log lines to a callback (which forwards
 * to the renderer via IPC).
 */

export interface LogLine {
  timestamp: string;
  severity: 'DEBUG' | 'INFO' | 'WARNING' | 'ERROR' | 'CRITICAL';
  message: string;
  raw: string;
}

type LogCallback = (line: LogLine) => void;

export class LogWatcher {
  private logDir: string;
  private callback: LogCallback;
  private watcher: fs.FSWatcher | null = null;
  private currentFile: string | null = null;
  private filePosition: number = 0;

  constructor(logDir: string, callback: LogCallback) {
    this.logDir = logDir;
    this.callback = callback;
    this.start();
  }

  /**
   * Read the most recent N lines from the current log file.
   */
  async readRecent(count: number): Promise<LogLine[]> {
    const logFile = this.findMostRecentLog();
    if (!logFile) return [];

    try {
      const content = fs.readFileSync(logFile, 'utf-8');
      const lines = content.trim().split('\n');
      const recent = lines.slice(-count);
      return recent.map((raw) => this.parseLine(raw));
    } catch {
      return [];
    }
  }

  private start(): void {
    // Check if log directory exists
    if (!fs.existsSync(this.logDir)) {
      console.warn(`[LogWatcher] Log directory not found: ${this.logDir}`);
      return;
    }

    // Find the most recent log file
    this.currentFile = this.findMostRecentLog();
    if (this.currentFile) {
      // Start reading from the end of the file
      const stat = fs.statSync(this.currentFile);
      this.filePosition = stat.size;
    }

    // Watch for changes
    try {
      this.watcher = fs.watch(this.logDir, (_eventType, filename) => {
        if (filename && filename.endsWith('.log')) {
          this.handleFileChange();
        }
      });
    } catch (err) {
      console.error(`[LogWatcher] Failed to watch directory: ${err}`);
    }
  }

  private handleFileChange(): void {
    const logFile = this.findMostRecentLog();
    if (!logFile) return;

    // If a new log file appeared, switch to it
    if (logFile !== this.currentFile) {
      this.currentFile = logFile;
      this.filePosition = 0;
    }

    // Read new content
    try {
      const stat = fs.statSync(logFile);
      if (stat.size > this.filePosition) {
        const fd = fs.openSync(logFile, 'r');
        const buffer = Buffer.alloc(stat.size - this.filePosition);
        fs.readSync(fd, buffer, 0, buffer.length, this.filePosition);
        fs.closeSync(fd);

        const newContent = buffer.toString('utf-8');
        const lines = newContent.trim().split('\n').filter((l) => l.length > 0);

        for (const raw of lines) {
          this.callback(this.parseLine(raw));
        }

        this.filePosition = stat.size;
      }
    } catch (err) {
      console.error(`[LogWatcher] Error reading log file: ${err}`);
    }
  }

  private findMostRecentLog(): string | null {
    try {
      const files = fs.readdirSync(this.logDir)
        .filter((f) => f.endsWith('.log'))
        .map((f) => ({
          name: f,
          path: path.join(this.logDir, f),
          mtime: fs.statSync(path.join(this.logDir, f)).mtime,
        }))
        .sort((a, b) => b.mtime.getTime() - a.mtime.getTime());

      return files.length > 0 ? files[0].path : null;
    } catch {
      return null;
    }
  }

  /**
   * Parse a raw log line into structured fields.
   * Expected format: "2025-01-15 10:30:45 - INFO - Some message here"
   * Falls back gracefully if format doesn't match.
   */
  private parseLine(raw: string): LogLine {
    // Try to match: YYYY-MM-DD HH:MM:SS - SEVERITY - message
    const match = raw.match(/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s*-\s*(DEBUG|INFO|WARNING|ERROR|CRITICAL)\s*-\s*(.*)$/);

    if (match) {
      return {
        timestamp: match[1],
        severity: match[2] as LogLine['severity'],
        message: match[3],
        raw,
      };
    }

    // Fallback: unparseable line
    return {
      timestamp: '',
      severity: 'INFO',
      message: raw,
      raw,
    };
  }

  stop(): void {
    if (this.watcher) {
      this.watcher.close();
      this.watcher = null;
    }
  }
}
