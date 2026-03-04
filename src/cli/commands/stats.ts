/**
 * Stats Command - View optimization statistics
 */

import type { KVMemory } from '../../core/kv-memory.js';

export interface StatsCommandOptions {
  /** Memory store instance */
  memory: KVMemory;
  /** Display ASCII bar chart */
  graph?: boolean;
  /** Reset statistics */
  reset?: boolean;
  /** Auto-confirm reset (for testing) */
  confirmReset?: boolean;
  /** Output JSON format */
  json?: boolean;
}

export interface StatsCommandResult {
  /** Total number of optimization commands run */
  totalCommands: number;
  /** Total tokens saved across all optimizations */
  totalTokensSaved: number;
  /** Average reduction percentage (0.0-1.0) */
  averageReduction: number;
  /** ASCII bar chart (if graph=true) */
  graph?: string;
  /** JSON output (if json=true) */
  json?: string;
  /** Reset was confirmed (if reset=true) */
  resetConfirmed?: boolean;
}

/**
 * Execute the stats command
 * @param options - Command options
 * @returns Statistics result
 */
export async function statsCommand(options: StatsCommandOptions): Promise<StatsCommandResult> {
  const { memory, graph, reset, confirmReset, json } = options;

  // Handle reset
  if (reset) {
    if (confirmReset) {
      await memory.clearOptimizationStats();
      return {
        totalCommands: 0,
        totalTokensSaved: 0,
        averageReduction: 0,
        resetConfirmed: true,
      };
    }
  }

  // Get optimization stats from database
  const stats = await memory.getOptimizationStats();

  // Calculate aggregations
  const totalCommands = stats.length;

  const totalTokensSaved = stats.reduce((sum, s) => sum + (s.tokens_before - s.tokens_after), 0);

  const averageReduction =
    totalCommands > 0
      ? stats.reduce((sum, s) => {
          const reduction =
            s.tokens_before > 0 ? (s.tokens_before - s.tokens_after) / s.tokens_before : 0;
          return sum + reduction;
        }, 0) / totalCommands
      : 0;

  const result: StatsCommandResult = {
    totalCommands,
    totalTokensSaved,
    averageReduction,
  };

  // Generate ASCII bar chart if requested
  if (graph && totalCommands > 0) {
    result.graph = generateBarChart(stats);
  }

  // Generate JSON output if requested
  if (json) {
    result.json = JSON.stringify(
      {
        totalCommands,
        totalTokensSaved,
        averageReduction: Math.round(averageReduction * 1000) / 10, // Convert to percentage
        optimizations: stats.map((s) => ({
          timestamp: s.timestamp,
          tokensBefore: s.tokens_before,
          tokensAfter: s.tokens_after,
          entriesPruned: s.entries_pruned,
          durationMs: s.duration_ms,
          reduction: Math.round(((s.tokens_before - s.tokens_after) / s.tokens_before) * 1000) / 10,
        })),
      },
      null,
      2,
    );
  }

  return result;
}

/**
 * Generate ASCII bar chart for optimization history
 * @param stats - Optimization statistics
 * @returns ASCII bar chart string
 */
function generateBarChart(
  stats: Array<{ tokens_before: number; tokens_after: number; timestamp: number }>,
): string {
  const maxBars = 20; // Maximum number of bars to display
  const recentStats = stats.slice(0, maxBars);

  const lines: string[] = [];
  lines.push('\nOptimization History (most recent first):\n');

  // Find max reduction for scaling
  const maxReduction = Math.max(...recentStats.map((s) => s.tokens_before - s.tokens_after));

  for (let i = 0; i < recentStats.length; i++) {
    const s = recentStats[i];
    if (!s) continue; // Skip undefined entries

    const reduction = s.tokens_before - s.tokens_after;
    const reductionPct = s.tokens_before > 0 ? (reduction / s.tokens_before) * 100 : 0;

    // Scale bar length (max 40 chars)
    const barLength = Math.round((reduction / maxReduction) * 40);
    const bar = '█'.repeat(barLength);

    // Format timestamp
    const date = new Date(s.timestamp);
    const timeStr = date.toLocaleTimeString();

    lines.push(`${timeStr} │ ${bar} ${reductionPct.toFixed(1)}%`);
  }

  return lines.join('\n');
}
