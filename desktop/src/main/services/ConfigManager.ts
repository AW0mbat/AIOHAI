import * as fs from 'fs';
import * as path from 'path';

/**
 * ConfigManager — Reads and validates AIOHAI config.json.
 * 
 * Phase 1: Read-only access to config.
 * Phase 2: Will add write with validation and diff preview.
 */

export interface ValidationResult {
  valid: boolean;
  errors: string[];
}

export class ConfigManager {
  private aiohaiPath: string;
  private configPath: string;

  constructor(aiohaiPath: string) {
    this.aiohaiPath = aiohaiPath;
    this.configPath = path.join(aiohaiPath, 'config', 'config.json');
  }

  getAIOHAIPath(): string {
    return this.aiohaiPath;
  }

  /**
   * Read the current config.json. Returns null if file doesn't exist.
   */
  read(): Record<string, unknown> | null {
    try {
      if (!fs.existsSync(this.configPath)) {
        console.warn(`[ConfigManager] Config not found: ${this.configPath}`);
        return null;
      }

      const content = fs.readFileSync(this.configPath, 'utf-8');
      return JSON.parse(content);
    } catch (err) {
      console.error(`[ConfigManager] Error reading config: ${err}`);
      return null;
    }
  }

  /**
   * Validate a proposed config object.
   * Phase 1: Basic structural validation only.
   * Phase 2: Will add type checking, range validation, and semantic checks.
   */
  validate(proposed: unknown): ValidationResult {
    const errors: string[] = [];

    if (!proposed || typeof proposed !== 'object') {
      return { valid: false, errors: ['Config must be a JSON object'] };
    }

    const config = proposed as Record<string, unknown>;

    // Check that security section exists
    if (!config.security || typeof config.security !== 'object') {
      errors.push('Missing or invalid "security" section');
    }

    // Check that proxy section exists
    if (!config.proxy || typeof config.proxy !== 'object') {
      errors.push('Missing or invalid "proxy" section');
    }

    // Check version field
    if (typeof config.version !== 'string') {
      errors.push('Missing or invalid "version" field');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }
}
