/**
 * Sparse pruner types.
 * Relevance filtering: keep only the most important entries.
 */

import type { MemoryEntry } from './memory.js';

/**
 * Result of a pruning operation.
 */
export interface PruneResult {
  /** Entries kept after pruning */
  kept: MemoryEntry[];

  /** Entries removed during pruning */
  removed: MemoryEntry[];

  /** Original token count before pruning */
  originalTokens: number;

  /** Token count after pruning */
  prunedTokens: number;
}
