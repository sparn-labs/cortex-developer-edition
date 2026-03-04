/**
 * Setup command — One-command setup for Cortex.
 *
 * Automates the full onboarding flow:
 * 1. Detects Claude Code environment
 * 2. Initializes .cortex/ directory with auto-detected config
 * 3. Installs hooks globally
 * 4. Starts daemon
 * 5. Generates CLAUDE.md
 * 6. Prints summary
 */

import type { CortexConfig } from '../../types/config.js';
import { detectClaudeCode, initCommand } from './init.js';

export interface SetupOptions {
  /** Force overwrite if .cortex/ exists */
  force?: boolean;
  /** Current working directory */
  cwd?: string;
  /** Skip hook installation */
  skipHooks?: boolean;
  /** Skip daemon start */
  skipDaemon?: boolean;
  /** Skip CLAUDE.md generation */
  skipDocs?: boolean;
}

export interface SetupStep {
  name: string;
  status: 'success' | 'skipped' | 'failed';
  message: string;
}

export interface SetupResult {
  steps: SetupStep[];
  isClaudeCode: boolean;
  configPath: string;
  dbPath: string;
  durationMs: number;
}

export async function setupCommand(options: SetupOptions = {}): Promise<SetupResult> {
  const startTime = Date.now();
  const cwd = options.cwd || process.cwd();
  const steps: SetupStep[] = [];

  // Step 1: Detect Claude Code
  const isClaudeCode = detectClaudeCode();
  steps.push({
    name: 'detect',
    status: 'success',
    message: isClaudeCode
      ? 'Claude Code detected — using claude-code adapter'
      : 'Claude Code not detected — using generic adapter',
  });

  // Step 2: Initialize .cortex/
  let configPath = '';
  let dbPath = '';
  try {
    const initResult = await initCommand({ force: options.force, cwd });
    configPath = initResult.configPath;
    dbPath = initResult.dbPath;
    steps.push({
      name: 'init',
      status: 'success',
      message: `Initialized .cortex/ (${initResult.durationMs}ms)`,
    });
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    steps.push({ name: 'init', status: 'failed', message: msg });
    return {
      steps,
      isClaudeCode,
      configPath,
      dbPath,
      durationMs: Date.now() - startTime,
    };
  }

  // Step 3: Install hooks (globally by default for Claude Code)
  if (options.skipHooks) {
    steps.push({ name: 'hooks', status: 'skipped', message: 'Hook installation skipped' });
  } else {
    try {
      const { hooksCommand } = await import('./hooks.js');
      const hookResult = await hooksCommand({ subcommand: 'install', global: isClaudeCode });
      if (hookResult.success) {
        steps.push({
          name: 'hooks',
          status: 'success',
          message: isClaudeCode
            ? 'Hooks installed globally (all projects)'
            : 'Hooks installed for current project',
        });
      } else {
        steps.push({
          name: 'hooks',
          status: 'failed',
          message: hookResult.error || hookResult.message,
        });
      }
    } catch (error) {
      steps.push({
        name: 'hooks',
        status: 'failed',
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }

  // Step 4: Start daemon
  if (options.skipDaemon) {
    steps.push({ name: 'daemon', status: 'skipped', message: 'Daemon start skipped' });
  } else {
    try {
      const { readFileSync } = await import('node:fs');
      const { load: parseYAML } = await import('js-yaml');
      const configContent = readFileSync(configPath, 'utf-8');
      const config = parseYAML(configContent) as CortexConfig;

      const { createDaemonCommand } = await import('../../daemon/daemon-process.js');
      const daemon = createDaemonCommand();
      const daemonResult = await daemon.start(config);

      if (daemonResult.success) {
        steps.push({
          name: 'daemon',
          status: 'success',
          message: `Daemon started (PID ${daemonResult.pid})`,
        });
      } else {
        steps.push({
          name: 'daemon',
          status: 'failed',
          message: daemonResult.error || daemonResult.message,
        });
      }
    } catch (error) {
      steps.push({
        name: 'daemon',
        status: 'failed',
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }

  // Step 5: Generate CLAUDE.md
  if (options.skipDocs) {
    steps.push({ name: 'docs', status: 'skipped', message: 'CLAUDE.md generation skipped' });
  } else {
    try {
      const { docsCommand } = await import('./docs.js');
      const docsResult = await docsCommand({ includeGraph: true });
      steps.push({
        name: 'docs',
        status: 'success',
        message: docsResult.message || 'CLAUDE.md generated',
      });
    } catch (error) {
      // Docs generation is non-critical
      steps.push({
        name: 'docs',
        status: 'failed',
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }

  return {
    steps,
    isClaudeCode,
    configPath,
    dbPath,
    durationMs: Date.now() - startTime,
  };
}
