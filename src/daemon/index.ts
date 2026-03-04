/**
 * Daemon Entry Point - Background process main loop
 *
 * This file is executed as a forked child process by daemon-process.ts.
 * It runs the session watcher and handles cleanup on exit.
 */

import { appendFileSync, existsSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { createKVMemory } from '../core/kv-memory.js';
import type { CortexConfig } from '../types/config.js';
import { setPreciseTokenCounting } from '../utils/tokenizer.js';
import { createConsolidationScheduler } from './consolidation-scheduler.js';
import { createSessionWatcher } from './session-watcher.js';

// Parse config from environment or config file
let configJson = process.env['CORTEX_CONFIG'];
let pidFile = process.env['CORTEX_PID_FILE'];
let logFile = process.env['CORTEX_LOG_FILE'];

// On Windows, env vars may not survive process detachment - read from config file
const configFilePath = process.env['CORTEX_CONFIG_FILE'];
if ((!configJson || !pidFile || !logFile) && configFilePath && existsSync(configFilePath)) {
  const fileConfig = JSON.parse(readFileSync(configFilePath, 'utf-8'));
  configJson = configJson || JSON.stringify(fileConfig.config);
  pidFile = pidFile || fileConfig.pidFile;
  logFile = logFile || fileConfig.logFile;
}

if (!configJson || !pidFile || !logFile) {
  console.error('Daemon: Missing required environment variables');
  process.exit(1);
}

const config: CortexConfig = JSON.parse(configJson);

// Enable precise token counting if configured
if (config.realtime?.preciseTokenCounting) {
  setPreciseTokenCounting(true);
}

// Write our own PID so the parent can find us
writeFileSync(pidFile, String(process.pid), 'utf-8');

// Log helper
function log(message: string): void {
  const timestamp = new Date().toISOString();
  const logMessage = `[${timestamp}] ${message}\n`;

  // logFile is guaranteed to be defined after env check
  if (logFile) {
    try {
      appendFileSync(logFile, logMessage, 'utf-8');
    } catch {
      // Fail silently if can't write log
    }
  }
}

// Cleanup on exit
function cleanup(): void {
  log('Daemon shutting down');

  // Remove PID file (pidFile is guaranteed to be defined after env check)
  if (pidFile && existsSync(pidFile)) {
    try {
      unlinkSync(pidFile);
    } catch {
      // Fail silently
    }
  }

  // Stop scheduler
  if (scheduler) {
    scheduler.stop();
  }

  // Stop watcher
  watcher.stop();

  // Close memory connection
  if (memory) {
    void memory.close();
  }

  process.exit(0);
}

// Signal handlers
process.on('SIGTERM', cleanup);
process.on('SIGINT', cleanup);
process.on('SIGHUP', cleanup);

// Uncaught exception handler
process.on('uncaughtException', (error) => {
  log(`Uncaught exception: ${error.message}`);
  cleanup();
});

process.on('unhandledRejection', (reason) => {
  log(`Unhandled rejection: ${reason}`);
  cleanup();
});

// Create memory instance for consolidation scheduler
// Using a default path - could be made configurable in future
let memory: Awaited<ReturnType<typeof createKVMemory>> | null = null;
let scheduler: ReturnType<typeof createConsolidationScheduler> | null = null;

// Create and start session watcher
log('Daemon starting');

const watcher = createSessionWatcher({
  config,
  onOptimize: (sessionId, stats) => {
    log(
      `Optimized session ${sessionId}: ${stats.optimizedTokens} tokens (${Math.round(stats.reduction * 100)}% reduction)`,
    );
  },
  onError: (error) => {
    log(`Error: ${error.message}`);
  },
});

// Start watching
watcher
  .start()
  .then(async () => {
    log('Daemon ready - watching Claude Code sessions');

    // Initialize consolidation scheduler if enabled
    if (
      config.realtime.consolidationInterval !== null &&
      config.realtime.consolidationInterval > 0
    ) {
      try {
        // Create memory instance
        memory = await createKVMemory('.cortex/memory.db');

        // Create and start scheduler
        scheduler = createConsolidationScheduler({
          memory,
          config,
          logFile,
        });

        scheduler.start();
        log(
          `Consolidation scheduler started (interval: ${config.realtime.consolidationInterval}h)`,
        );
      } catch (error) {
        log(
          `Failed to start consolidation scheduler: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
  })
  .catch((error) => {
    log(`Failed to start: ${error.message}`);
    cleanup();
  });

// Keep process alive - setInterval keeps the event loop active
setInterval(() => {
  // Heartbeat - keep event loop active
}, 30000);

// On Windows, detached processes may need an additional active handle
try {
  process.stdin.resume();
} catch {
  // Ignore if stdin is unavailable (detached mode)
}
