/**
 * Config Command - View or modify configuration
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { load as parseYAML, dump as stringifyYAML } from 'js-yaml';
import type { CortexConfig } from '../../types/config.js';

export interface ConfigCommandOptions {
  /** Path to config.yaml file */
  configPath: string;
  /** Subcommand: get or set */
  subcommand?: 'get' | 'set';
  /** Config key (dotted path) */
  key?: string;
  /** Config value (for set) */
  value?: string;
  /** Output JSON format */
  json?: boolean;
}

export interface ConfigCommandResult {
  /** Command succeeded */
  success: boolean;
  /** Result message */
  message?: string;
  /** Error message */
  error?: string;
  /** Retrieved value (for get) */
  value?: unknown;
  /** Editor path (for no subcommand) */
  editorPath?: string;
  /** JSON output */
  json?: string;
}

/**
 * Valid config keys with their validation rules
 */
const CONFIG_SCHEMA: Record<
  string,
  {
    path: string[];
    validate: (value: unknown) => boolean;
    errorMessage: string;
    parse: (value: string) => unknown;
  }
> = {
  'pruning.threshold': {
    path: ['pruning', 'threshold'],
    validate: (v) => typeof v === 'number' && v >= 1 && v <= 100,
    errorMessage: 'threshold must be between 1-100',
    parse: (v) => Number.parseInt(v, 10),
  },
  'pruning.aggressiveness': {
    path: ['pruning', 'aggressiveness'],
    validate: (v) => typeof v === 'number' && v >= 0 && v <= 100,
    errorMessage: 'aggressiveness must be between 0-100',
    parse: (v) => Number.parseInt(v, 10),
  },
  'decay.defaultTTL': {
    path: ['decay', 'defaultTTL'],
    validate: (v) => typeof v === 'number' && v > 0,
    errorMessage: 'defaultTTL must be a positive number (hours)',
    parse: (v) => Number.parseFloat(v),
  },
  'decay.decayThreshold': {
    path: ['decay', 'decayThreshold'],
    validate: (v) => typeof v === 'number' && v >= 0.0 && v <= 1.0,
    errorMessage: 'decayThreshold must be between 0.0-1.0',
    parse: (v) => Number.parseFloat(v),
  },
  'states.activeThreshold': {
    path: ['states', 'activeThreshold'],
    validate: (v) => typeof v === 'number' && v >= 0.0 && v <= 1.0,
    errorMessage: 'activeThreshold must be between 0.0-1.0',
    parse: (v) => Number.parseFloat(v),
  },
  'states.readyThreshold': {
    path: ['states', 'readyThreshold'],
    validate: (v) => typeof v === 'number' && v >= 0.0 && v <= 1.0,
    errorMessage: 'readyThreshold must be between 0.0-1.0',
    parse: (v) => Number.parseFloat(v),
  },
  agent: {
    path: ['agent'],
    validate: (v) => v === 'claude-code' || v === 'generic',
    errorMessage: 'agent must be "claude-code" or "generic"',
    parse: (v) => v,
  },
  'ui.colors': {
    path: ['ui', 'colors'],
    validate: (v) => typeof v === 'boolean',
    errorMessage: 'colors must be true or false',
    parse: (v) => v === 'true',
  },
  'ui.sounds': {
    path: ['ui', 'sounds'],
    validate: (v) => typeof v === 'boolean',
    errorMessage: 'sounds must be true or false',
    parse: (v) => v === 'true',
  },
  'ui.verbose': {
    path: ['ui', 'verbose'],
    validate: (v) => typeof v === 'boolean',
    errorMessage: 'verbose must be true or false',
    parse: (v) => v === 'true',
  },
  autoConsolidate: {
    path: ['autoConsolidate'],
    validate: (v) => v === null || (typeof v === 'number' && v > 0),
    errorMessage: 'autoConsolidate must be a positive number (hours) or null',
    parse: (v) => (v === 'null' ? null : Number.parseFloat(v)),
  },
  'realtime.tokenBudget': {
    path: ['realtime', 'tokenBudget'],
    validate: (v) => typeof v === 'number' && v > 0,
    errorMessage: 'tokenBudget must be a positive number',
    parse: (v) => Number.parseInt(v, 10),
  },
  'realtime.autoOptimizeThreshold': {
    path: ['realtime', 'autoOptimizeThreshold'],
    validate: (v) => typeof v === 'number' && v > 0,
    errorMessage: 'autoOptimizeThreshold must be a positive number',
    parse: (v) => Number.parseInt(v, 10),
  },
  'realtime.watchPatterns': {
    path: ['realtime', 'watchPatterns'],
    validate: (v) => Array.isArray(v) && v.every((p) => typeof p === 'string'),
    errorMessage: 'watchPatterns must be an array of strings',
    parse: (v) => v.split(',').map((p) => p.trim()),
  },
  'realtime.pidFile': {
    path: ['realtime', 'pidFile'],
    validate: (v) => typeof v === 'string' && v.length > 0,
    errorMessage: 'pidFile must be a non-empty string',
    parse: (v) => v,
  },
  'realtime.logFile': {
    path: ['realtime', 'logFile'],
    validate: (v) => typeof v === 'string' && v.length > 0,
    errorMessage: 'logFile must be a non-empty string',
    parse: (v) => v,
  },
  'realtime.debounceMs': {
    path: ['realtime', 'debounceMs'],
    validate: (v) => typeof v === 'number' && v >= 0,
    errorMessage: 'debounceMs must be a non-negative number',
    parse: (v) => Number.parseInt(v, 10),
  },
  'realtime.incremental': {
    path: ['realtime', 'incremental'],
    validate: (v) => typeof v === 'boolean',
    errorMessage: 'incremental must be true or false',
    parse: (v) => v === 'true',
  },
  'realtime.windowSize': {
    path: ['realtime', 'windowSize'],
    validate: (v) => typeof v === 'number' && v > 0,
    errorMessage: 'windowSize must be a positive number',
    parse: (v) => Number.parseInt(v, 10),
  },
};

/**
 * Execute the config command
 * @param options - Command options
 * @returns Config result
 */
export async function configCommand(options: ConfigCommandOptions): Promise<ConfigCommandResult> {
  const { configPath, subcommand, key, value, json } = options;

  try {
    // Read config file
    const configYAML = readFileSync(configPath, 'utf-8');
    const config = parseYAML(configYAML) as CortexConfig;

    // No subcommand: open editor or return JSON
    if (!subcommand) {
      if (json) {
        return {
          success: true,
          json: JSON.stringify(config, null, 2),
        };
      }
      return {
        success: true,
        editorPath: configPath,
        message: `Config file: ${configPath}`,
      };
    }

    // Get subcommand
    if (subcommand === 'get') {
      if (!key) {
        return {
          success: false,
          error: 'Key required for get command',
        };
      }

      const schema = CONFIG_SCHEMA[key];
      if (!schema) {
        return {
          success: false,
          error: `Invalid key: ${key}. Run 'cortex config' to see available keys.`,
        };
      }

      const retrievedValue = getNestedValue(
        config as unknown as Record<string, unknown>,
        schema.path,
      );

      if (json) {
        return {
          success: true,
          value: retrievedValue,
          json: JSON.stringify({ key, value: retrievedValue }, null, 2),
        };
      }

      return {
        success: true,
        value: retrievedValue,
        message: String(retrievedValue),
      };
    }

    // Set subcommand
    if (subcommand === 'set') {
      if (!key) {
        return {
          success: false,
          error: 'Key required for set command',
        };
      }

      if (value === undefined) {
        return {
          success: false,
          error: 'Value required for set command',
        };
      }

      const schema = CONFIG_SCHEMA[key];
      if (!schema) {
        return {
          success: false,
          error: `Invalid key: ${key}. Run 'cortex config' to see available keys.`,
        };
      }

      // Parse and validate value
      const parsedValue = schema.parse(value);
      if (!schema.validate(parsedValue)) {
        return {
          success: false,
          error: `Invalid value for ${key}: ${schema.errorMessage}`,
        };
      }

      // Update config
      setNestedValue(config as unknown as Record<string, unknown>, schema.path, parsedValue);

      // Write back to file
      const updatedYAML = stringifyYAML(config);
      writeFileSync(configPath, updatedYAML, 'utf-8');

      return {
        success: true,
        message: `Config updated: ${key} = ${parsedValue}`,
      };
    }

    return {
      success: false,
      error: `Unknown subcommand: ${subcommand}`,
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Get nested value from object using path array
 * @param obj - Object to query
 * @param path - Path array
 * @returns Nested value
 */
function getNestedValue(obj: Record<string, unknown>, path: string[]): unknown {
  let current: unknown = obj;
  for (const key of path) {
    if (current && typeof current === 'object' && !Array.isArray(current) && key in current) {
      current = (current as Record<string, unknown>)[key];
    } else {
      return undefined;
    }
  }
  return current;
}

/**
 * Set nested value in object using path array
 * @param obj - Object to mutate
 * @param path - Path array
 * @param value - Value to set
 */
function setNestedValue(obj: Record<string, unknown>, path: string[], value: unknown): void {
  let current: Record<string, unknown> = obj;
  for (let i = 0; i < path.length - 1; i++) {
    const key = path[i];
    if (!key) continue;

    if (!current[key] || typeof current[key] !== 'object') {
      current[key] = {};
    }
    current = current[key] as Record<string, unknown>;
  }

  const lastKey = path[path.length - 1];
  if (lastKey) {
    current[lastKey] = value;
  }
}
