/**
 * Session Watcher - Monitor Claude Code session files for changes
 *
 * Uses Node.js fs.watch to monitor ~/.claude/projects/**\/*.jsonl files.
 * Debounces events and triggers optimization when token threshold exceeded.
 * Maintains per-session ContextPipeline instances.
 */

import {
  existsSync,
  type FSWatcher,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  watch,
  writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { type ContextPipeline, createContextPipeline } from '../core/context-pipeline.js';
import { getMetrics } from '../core/metrics.js';
import type { CortexConfig } from '../types/config.js';
import { estimateTokens } from '../utils/tokenizer.js';
import { createFileTracker } from './file-tracker.js';

export interface SessionWatcherConfig {
  /** Cortex configuration */
  config: CortexConfig;
  /** Callback when optimization triggered */
  onOptimize?: (sessionId: string, stats: SessionStats) => void;
  /** Callback on error */
  onError?: (error: Error) => void;
}

export interface SessionStats {
  /** Session ID */
  sessionId: string;
  /** Total tokens ingested */
  totalTokens: number;
  /** Current optimized tokens */
  optimizedTokens: number;
  /** Reduction percentage */
  reduction: number;
  /** Entry count */
  entryCount: number;
  /** Budget utilization */
  budgetUtilization: number;
}

export interface SessionWatcher {
  /**
   * Start watching Claude Code session files
   * @returns Promise that resolves when watcher is ready
   */
  start(): Promise<void>;

  /**
   * Stop watching and cleanup
   */
  stop(): void;

  /**
   * Get statistics for all sessions
   * @returns Array of session stats
   */
  getStats(): SessionStats[];

  /**
   * Get statistics for a specific session
   * @param sessionId - Session ID
   * @returns Session stats or null if not found
   */
  getSessionStats(sessionId: string): SessionStats | null;

  /**
   * Manually trigger optimization for a session
   * @param sessionId - Session ID
   */
  optimizeSession(sessionId: string): void;
}

/**
 * Create a session watcher instance
 * @param config - Watcher configuration
 * @returns SessionWatcher instance
 */
export function createSessionWatcher(config: SessionWatcherConfig): SessionWatcher {
  const { config: cortexConfig, onOptimize, onError } = config;
  const { realtime, decay, states } = cortexConfig;

  // Per-session pipelines and trackers
  const pipelines = new Map<string, ContextPipeline>();
  const fileTracker = createFileTracker();

  // File system watchers
  const watchers: FSWatcher[] = [];

  // Debounce timers per file
  const debounceTimers = new Map<string, NodeJS.Timeout>();

  /**
   * Get Claude Code projects directory
   */
  function getProjectsDir(): string {
    return join(homedir(), '.claude', 'projects');
  }

  /**
   * Extract session ID from file path
   * Example: ~/.claude/projects/my-project/abc123.jsonl -> abc123
   */
  function getSessionId(filePath: string): string {
    const filename = filePath.split(/[/\\]/).pop() || '';
    return filename.replace(/\.jsonl$/, '');
  }

  /**
   * Get or create pipeline for session
   */
  function getPipeline(sessionId: string): ContextPipeline {
    let pipeline = pipelines.get(sessionId);

    if (!pipeline) {
      pipeline = createContextPipeline({
        tokenBudget: realtime.tokenBudget,
        decay,
        states,
        windowSize: realtime.windowSize,
        fullOptimizationInterval: 50, // Full re-optimization every 50 incremental updates
      });
      // Restore persisted optimizer state if available
      loadState(sessionId, pipeline);
      pipelines.set(sessionId, pipeline);
    }

    return pipeline;
  }

  /**
   * Handle file change event (debounced)
   */
  function handleFileChange(filePath: string): void {
    // Clear existing timer
    const existingTimer = debounceTimers.get(filePath);
    if (existingTimer) {
      clearTimeout(existingTimer);
    }

    // Set new debounced timer
    const timer = setTimeout(() => {
      try {
        // Read new lines from file
        const newLines = fileTracker.readNewLines(filePath);

        if (newLines.length === 0) return;

        // Parse JSONL content
        const content = newLines.join('\n');
        const sessionId = getSessionId(filePath);
        const pipeline = getPipeline(sessionId);

        // Ingest into pipeline
        pipeline.ingest(content, { sessionId, filePath });

        // Check if we should trigger optimization
        const stats = pipeline.getStats();
        if (stats.currentTokens >= realtime.autoOptimizeThreshold) {
          // Update daemon metrics
          getMetrics().updateDaemon({
            sessionsWatched: pipelines.size,
            memoryUsage: process.memoryUsage().heapUsed,
          });

          // Trigger optimization callback
          if (onOptimize) {
            const sessionStats = computeSessionStats(sessionId, pipeline);
            onOptimize(sessionId, sessionStats);
          }
        }
      } catch (error) {
        if (onError) {
          onError(error instanceof Error ? error : new Error(String(error)));
        }
      } finally {
        debounceTimers.delete(filePath);
      }
    }, realtime.debounceMs);

    debounceTimers.set(filePath, timer);
  }

  /**
   * Recursively find all JSONL files in directory
   */
  function findJsonlFiles(dir: string): string[] {
    const files: string[] = [];

    try {
      const entries = readdirSync(dir);

      for (const entry of entries) {
        const fullPath = join(dir, entry);
        const stat = statSync(fullPath);

        if (stat.isDirectory()) {
          // Recurse into subdirectories
          files.push(...findJsonlFiles(fullPath));
        } else if (entry.endsWith('.jsonl')) {
          // Match pattern
          const matches = realtime.watchPatterns.some((pattern) => {
            // Simple glob matching (supports **/*.jsonl)
            const regex = new RegExp(
              pattern
                .replace(/\./g, '\\.')
                .replace(/\*\*/g, '.*')
                .replace(/(?<!\.)(\*)/g, '[^/\\\\]*'),
            );
            return regex.test(fullPath);
          });

          if (matches) {
            files.push(fullPath);
          }
        }
      }
    } catch (_error) {
      // Ignore errors (directory might not exist yet)
    }

    return files;
  }

  /**
   * Compute session statistics
   */
  function computeSessionStats(sessionId: string, pipeline: ContextPipeline): SessionStats {
    const stats = pipeline.getStats();
    const entries = pipeline.getEntries();
    const totalTokens = entries.reduce((sum, e) => sum + estimateTokens(e.content), 0);

    return {
      sessionId,
      totalTokens: stats.totalIngested,
      optimizedTokens: stats.currentTokens,
      reduction: totalTokens > 0 ? (totalTokens - stats.currentTokens) / totalTokens : 0,
      entryCount: stats.currentEntries,
      budgetUtilization: stats.budgetUtilization,
    };
  }

  async function start(): Promise<void> {
    const projectsDir = getProjectsDir();

    // Find all existing JSONL files (for initial metrics count)
    const jsonlFiles = findJsonlFiles(projectsDir);

    // Use a single recursive watcher on the projects dir to avoid duplicate events
    // from both per-dir watchers and the recursive watcher firing for the same file
    try {
      const projectsWatcher = watch(projectsDir, { recursive: true }, (_eventType, filename) => {
        if (filename?.endsWith('.jsonl')) {
          const fullPath = join(projectsDir, filename);
          handleFileChange(fullPath);
        }
      });

      watchers.push(projectsWatcher);
    } catch {
      // Recursive watch not supported (some Linux kernels) - fall back to per-dir
      const watchedDirs = new Set<string>();

      for (const file of jsonlFiles) {
        const dir = dirname(file);

        if (!watchedDirs.has(dir)) {
          const watcher = watch(dir, { recursive: false }, (_eventType, filename) => {
            if (filename?.endsWith('.jsonl')) {
              const fullPath = join(dir, filename);
              handleFileChange(fullPath);
            }
          });

          watchers.push(watcher);
          watchedDirs.add(dir);
        }
      }
    }

    // Update daemon metrics
    getMetrics().updateDaemon({
      startTime: Date.now(),
      sessionsWatched: jsonlFiles.length,
      memoryUsage: process.memoryUsage().heapUsed,
    });
  }

  /**
   * State persistence path
   */
  function getStatePath(): string {
    return join(homedir(), '.cortex', 'optimizer-state.json');
  }

  /**
   * Save optimizer state for all sessions
   */
  function saveState(): void {
    try {
      const stateMap: Record<string, string> = {};
      for (const [sessionId, pipeline] of pipelines.entries()) {
        stateMap[sessionId] = pipeline.serializeOptimizerState();
      }
      const statePath = getStatePath();
      const dir = dirname(statePath);
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
      }
      writeFileSync(statePath, JSON.stringify(stateMap), 'utf-8');
    } catch {
      // Best-effort — fail silently
    }
  }

  /**
   * Load optimizer state for a session
   */
  function loadState(sessionId: string, pipeline: ReturnType<typeof createContextPipeline>): void {
    try {
      const statePath = getStatePath();
      if (!existsSync(statePath)) return;
      const raw = readFileSync(statePath, 'utf-8');
      const stateMap = JSON.parse(raw) as Record<string, string>;
      const sessionState = stateMap[sessionId];
      if (sessionState) {
        pipeline.deserializeOptimizerState(sessionState);
      }
    } catch {
      // Best-effort — fail silently
    }
  }

  function stop(): void {
    // Save optimizer state before stopping
    saveState();

    // Close all watchers
    for (const watcher of watchers) {
      watcher.close();
    }
    watchers.length = 0;

    // Clear all timers
    for (const timer of debounceTimers.values()) {
      clearTimeout(timer);
    }
    debounceTimers.clear();

    // Clear pipelines
    pipelines.clear();

    // Clear file tracker
    fileTracker.clearAll();
  }

  function getStats(): SessionStats[] {
    const stats: SessionStats[] = [];

    for (const [sessionId, pipeline] of pipelines.entries()) {
      stats.push(computeSessionStats(sessionId, pipeline));
    }

    return stats;
  }

  function getSessionStats(sessionId: string): SessionStats | null {
    const pipeline = pipelines.get(sessionId);
    if (!pipeline) return null;

    return computeSessionStats(sessionId, pipeline);
  }

  function optimizeSession(sessionId: string): void {
    const pipeline = pipelines.get(sessionId);
    if (!pipeline) return;

    // Get entries and force full optimization
    const entries = pipeline.getEntries();
    pipeline.clear();
    pipeline.ingest(entries.map((e) => e.content).join('\n\n'));

    // Trigger callback
    if (onOptimize) {
      const stats = computeSessionStats(sessionId, pipeline);
      onOptimize(sessionId, stats);
    }
  }

  return {
    start,
    stop,
    getStats,
    getSessionStats,
    optimizeSession,
  };
}
