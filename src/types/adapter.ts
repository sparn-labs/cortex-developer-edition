/**
 * Agent adapter interface types.
 * Enables agent-agnostic design per Article IV.
 */

import type { StateDistribution } from './memory.js';

/**
 * Options for optimization operations.
 */
export interface OptimizeOptions {
  /** Dry-run mode (don't modify memory store) */
  dryRun?: boolean;

  /** Verbose output */
  verbose?: boolean;

  /** Custom pruning threshold (overrides config) */
  threshold?: number;
}

/**
 * Result of an optimization operation.
 */
export interface OptimizationResult {
  /** Optimized context text */
  optimizedContext: string;

  /** Token count before optimization */
  tokensBefore: number;

  /** Token count after optimization */
  tokensAfter: number;

  /** Reduction percentage (0.0-1.0) */
  reduction: number;

  /** Total entries processed */
  entriesProcessed: number;

  /** Entries kept after optimization */
  entriesKept: number;

  /** Optimization duration in milliseconds */
  durationMs: number;

  /** State distribution after optimization */
  stateDistribution: StateDistribution;

  /** Optional: Detailed per-entry information (when verbose=true) */
  details?: Array<{
    id: string;
    score: number;
    state: string;
    isBTSP: boolean;
    tokens: number;
  }>;
}

/**
 * Agent adapter interface.
 * All agent-specific logic must implement this contract.
 */
export interface AgentAdapter {
  /**
   * Optimize context using this agent's strategy.
   *
   * @param context - Input context (plain text)
   * @param options - Optimization options
   * @returns Optimization result
   */
  optimize(context: string, options?: OptimizeOptions): Promise<OptimizationResult>;
}
