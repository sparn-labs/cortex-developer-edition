/**
 * Consolidation Scheduler - Periodic memory consolidation
 *
 * Handles:
 * - Scheduled consolidation using setInterval
 * - Integration with existing consolidate command
 * - Logging to daemon log file
 * - Metrics tracking for consolidation runs
 */

import { appendFileSync } from 'node:fs';
import { consolidateCommand } from '../cli/commands/consolidate.js';
import type { KVMemory } from '../core/kv-memory.js';
import { getMetrics } from '../core/metrics.js';
import type { CortexConfig } from '../types/config.js';

export interface ConsolidationScheduler {
  /**
   * Start the scheduler
   */
  start(): void;

  /**
   * Stop the scheduler
   */
  stop(): void;

  /**
   * Get scheduler status
   */
  getStatus(): ConsolidationSchedulerStatus;
}

export interface ConsolidationSchedulerStatus {
  /** Is the scheduler running */
  running: boolean;
  /** Interval in hours */
  intervalHours: number | null;
  /** Next run timestamp (null if not running) */
  nextRun: number | null;
  /** Total consolidations run */
  totalRuns: number;
  /** Last run timestamp (null if never run) */
  lastRun: number | null;
  /** Last run result (null if never run) */
  lastResult: ConsolidationResult | null;
}

export interface ConsolidationResult {
  /** Timestamp of consolidation */
  timestamp: number;
  /** Entries before consolidation */
  entriesBefore: number;
  /** Entries after consolidation */
  entriesAfter: number;
  /** Decayed entries removed */
  decayedRemoved: number;
  /** Duplicate entries merged */
  duplicatesRemoved: number;
  /** Compression ratio (0.0-1.0) */
  compressionRatio: number;
  /** Duration in milliseconds */
  durationMs: number;
  /** Success flag */
  success: boolean;
  /** Error message if failed */
  error?: string;
}

export interface ConsolidationSchedulerOptions {
  /** Memory store instance */
  memory: KVMemory;
  /** Cortex configuration */
  config: CortexConfig;
  /** Log file path (optional, defaults to daemon log) */
  logFile?: string;
}

/**
 * Create a consolidation scheduler instance
 * @param options - Scheduler options
 * @returns ConsolidationScheduler instance
 */
export function createConsolidationScheduler(
  options: ConsolidationSchedulerOptions,
): ConsolidationScheduler {
  const { memory, config, logFile } = options;
  const intervalHours = config.realtime.consolidationInterval;

  let timerId: NodeJS.Timeout | null = null;
  let totalRuns = 0;
  let lastRun: number | null = null;
  let lastResult: ConsolidationResult | null = null;
  let nextRun: number | null = null;
  let isRunning = false;

  /**
   * Log helper
   */
  function log(message: string): void {
    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] [Consolidation] ${message}\n`;

    // Log to daemon log file if available
    const logPath = logFile || config.realtime.logFile;
    if (logPath) {
      try {
        appendFileSync(logPath, logMessage, 'utf-8');
      } catch {
        // Fail silently if can't write log
      }
    }
  }

  /**
   * Run consolidation
   */
  async function runConsolidation(): Promise<void> {
    if (isRunning) {
      log('Consolidation already in progress, skipping');
      return;
    }

    isRunning = true;
    const startTime = Date.now();
    log('Starting scheduled consolidation');

    try {
      const result = await consolidateCommand({ memory });

      // Record success
      lastRun = startTime;
      totalRuns++;
      lastResult = {
        timestamp: startTime,
        entriesBefore: result.entriesBefore,
        entriesAfter: result.entriesAfter,
        decayedRemoved: result.decayedRemoved,
        duplicatesRemoved: result.duplicatesRemoved,
        compressionRatio: result.compressionRatio,
        durationMs: result.durationMs,
        success: true,
      };

      // Log result
      log(
        `Consolidation completed: ${result.entriesBefore} -> ${result.entriesAfter} entries ` +
          `(${result.decayedRemoved} decayed, ${result.duplicatesRemoved} duplicates, ` +
          `${Math.round(result.compressionRatio * 100)}% compression) in ${result.durationMs}ms`,
      );

      // Update metrics
      const metrics = getMetrics();
      metrics.recordOptimization({
        timestamp: startTime,
        duration: result.durationMs,
        tokensBefore: result.entriesBefore * 100, // Rough estimate
        tokensAfter: result.entriesAfter * 100, // Rough estimate
        entriesProcessed: result.entriesBefore,
        entriesKept: result.entriesAfter,
        cacheHitRate: 0, // N/A for consolidation
        memoryUsage: process.memoryUsage().heapUsed,
      });
    } catch (error) {
      // Record failure
      lastRun = startTime;
      totalRuns++;
      lastResult = {
        timestamp: startTime,
        entriesBefore: 0,
        entriesAfter: 0,
        decayedRemoved: 0,
        duplicatesRemoved: 0,
        compressionRatio: 0,
        durationMs: Date.now() - startTime,
        success: false,
        error: error instanceof Error ? error.message : String(error),
      };

      log(`Consolidation failed: ${lastResult.error}`);
    }

    // Update next run time
    if (intervalHours !== null && intervalHours > 0) {
      nextRun = Date.now() + intervalHours * 60 * 60 * 1000;
    }

    isRunning = false;
  }

  function start(): void {
    // Check if interval is configured
    if (intervalHours === null || intervalHours <= 0) {
      log('Consolidation scheduler disabled (consolidationInterval not set)');
      return;
    }

    // Check if already running
    if (timerId !== null) {
      log('Consolidation scheduler already running');
      return;
    }

    // Calculate interval in milliseconds
    const intervalMs = intervalHours * 60 * 60 * 1000;

    // Set up periodic timer
    timerId = setInterval(() => {
      void runConsolidation();
    }, intervalMs);

    // Calculate next run
    nextRun = Date.now() + intervalMs;

    log(
      `Consolidation scheduler started (interval: ${intervalHours}h, next run: ${new Date(nextRun).toISOString()})`,
    );
  }

  function stop(): void {
    if (timerId !== null) {
      clearInterval(timerId);
      timerId = null;
      nextRun = null;
      log('Consolidation scheduler stopped');
    }
  }

  function getStatus(): ConsolidationSchedulerStatus {
    return {
      running: timerId !== null,
      intervalHours,
      nextRun,
      totalRuns,
      lastRun,
      lastResult,
    };
  }

  return {
    start,
    stop,
    getStatus,
  };
}
