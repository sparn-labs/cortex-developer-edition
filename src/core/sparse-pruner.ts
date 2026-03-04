/**
 * Sparse Pruner - Relevance filtering
 *
 * Keeps only the top 2-5% most relevant context entries by TF-IDF score.
 * Low-scoring entries are pruned to reduce token usage.
 */

import type { MemoryEntry } from '../types/memory.js';
import type { PruneResult } from '../types/pruner.js';
import { createTFIDFIndex, scoreTFIDF } from '../utils/tfidf.js';
import { estimateTokens } from '../utils/tokenizer.js';

export interface SparsePrunerConfig {
  /** Percentage threshold for pruning (e.g., 5 = keep top 5%) */
  threshold: number;
}

export interface SparsePruner {
  /**
   * Prune entries to keep only top N% by relevance score
   * @param entries - Memory entries to prune
   * @returns Result with kept/removed entries and token counts
   */
  prune(entries: MemoryEntry[]): PruneResult;

  /**
   * Calculate TF-IDF relevance score for a single entry
   * @param entry - Entry to score
   * @param allEntries - All entries for IDF calculation
   * @returns Relevance score (0.0-1.0)
   */
  scoreEntry(entry: MemoryEntry, allEntries: MemoryEntry[]): number;
}

/**
 * Create a sparse pruner instance
 * @param config - Pruner configuration
 * @returns SparsePruner instance
 */
export function createSparsePruner(config: SparsePrunerConfig): SparsePruner {
  const { threshold } = config;

  function scoreEntry(entry: MemoryEntry, allEntries: MemoryEntry[]): number {
    return scoreTFIDF(entry, createTFIDFIndex(allEntries));
  }

  function prune(entries: MemoryEntry[]): PruneResult {
    if (entries.length === 0) {
      return {
        kept: [],
        removed: [],
        originalTokens: 0,
        prunedTokens: 0,
      };
    }

    // Calculate original token count
    const originalTokens = entries.reduce((sum, e) => sum + estimateTokens(e.content), 0);

    // Build TF-IDF index once for all entries
    const tfidfIndex = createTFIDFIndex(entries);

    // Score all entries using pre-computed index
    const scored = entries.map((entry) => ({
      entry,
      score: scoreTFIDF(entry, tfidfIndex),
    }));

    // Sort by score descending
    scored.sort((a, b) => b.score - a.score);

    // Keep top N% (minimum 1 entry)
    const keepCount = Math.max(1, Math.ceil(entries.length * (threshold / 100)));
    const kept = scored.slice(0, keepCount).map((s) => s.entry);
    const removed = scored.slice(keepCount).map((s) => s.entry);

    // Calculate pruned token count
    const prunedTokens = kept.reduce((sum, e) => sum + estimateTokens(e.content), 0);

    return {
      kept,
      removed,
      originalTokens,
      prunedTokens,
    };
  }

  return {
    prune,
    scoreEntry,
  };
}
