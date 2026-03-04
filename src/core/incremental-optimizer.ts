/**
 * Incremental Optimizer - Cache-based delta processing
 *
 * Optimizes performance for real-time scenarios by:
 * - Caching entry scores by content hash
 * - Only recomputing scores for new/changed entries
 * - Pre-computing and caching document frequency tables
 * - Periodically forcing full re-optimization to prevent drift
 *
 * Target: <50ms for incremental updates on 100K token contexts
 */

import type { MemoryEntry } from '../types/memory.js';
import type { PruneResult } from '../types/pruner.js';
import { tokenize } from '../utils/tfidf.js';
import { estimateTokens } from '../utils/tokenizer.js';
import { type BudgetPrunerConfig, createBudgetPruner } from './budget-pruner.js';
import { getMetrics } from './metrics.js';

export interface IncrementalOptimizerConfig extends BudgetPrunerConfig {
  /** Force full re-optimization every N incremental updates */
  fullOptimizationInterval: number;
}

export interface IncrementalOptimizerState {
  /** Entry cache keyed by content hash */
  entryCache: Map<string, { entry: MemoryEntry; score: number; timestamp: number }>;
  /** Document frequency table for IDF calculation */
  documentFrequency: Map<string, number>;
  /** Total document count for IDF */
  totalDocuments: number;
  /** Incremental update counter */
  updateCount: number;
  /** Last full optimization timestamp */
  lastFullOptimization: number;
}

export interface IncrementalOptimizer {
  /**
   * Optimize incrementally (only process new/changed entries)
   * @param newEntries - New entries to add
   * @param budget - Optional budget override
   * @returns Prune result with budget utilization
   */
  optimizeIncremental(
    newEntries: MemoryEntry[],
    budget?: number,
  ): PruneResult & { budgetUtilization: number };

  /**
   * Optimize fully (recompute all scores)
   * @param allEntries - All entries to optimize
   * @param budget - Optional budget override
   * @returns Prune result with budget utilization
   */
  optimizeFull(
    allEntries: MemoryEntry[],
    budget?: number,
  ): PruneResult & { budgetUtilization: number };

  /**
   * Get current optimizer state (for serialization)
   * @returns Serializable state object
   */
  getState(): IncrementalOptimizerState;

  /**
   * Restore optimizer state (from serialization)
   * @param state - State to restore
   */
  restoreState(state: IncrementalOptimizerState): void;

  /**
   * Reset optimizer state (clear all caches)
   */
  reset(): void;

  /**
   * Get cache statistics
   * @returns Cache stats
   */
  getStats(): {
    cachedEntries: number;
    uniqueTerms: number;
    totalDocuments: number;
    updateCount: number;
    lastFullOptimization: number;
  };

  /**
   * Serialize optimizer state to JSON string for persistence
   * @returns JSON string of the state
   */
  serializeState(): string;

  /**
   * Deserialize optimizer state from JSON string
   * @param json - JSON string to restore from
   * @returns true if successful, false on error
   */
  deserializeState(json: string): boolean;
}

/**
 * Create an incremental optimizer instance
 * @param config - Optimizer configuration
 * @returns IncrementalOptimizer instance
 */
export function createIncrementalOptimizer(
  config: IncrementalOptimizerConfig,
): IncrementalOptimizer {
  const pruner = createBudgetPruner(config);
  const { fullOptimizationInterval } = config;

  // Internal state
  let state: IncrementalOptimizerState = {
    entryCache: new Map(),
    documentFrequency: new Map(),
    totalDocuments: 0,
    updateCount: 0,
    lastFullOptimization: Date.now(),
  };

  /**
   * Update document frequency table incrementally
   */
  function updateDocumentFrequency(entries: MemoryEntry[], remove = false): void {
    for (const entry of entries) {
      const tokens = tokenize(entry.content);
      const uniqueTerms = [...new Set(tokens)];

      for (const term of uniqueTerms) {
        const current = state.documentFrequency.get(term) || 0;
        const updated = remove ? Math.max(0, current - 1) : current + 1;

        if (updated === 0) {
          state.documentFrequency.delete(term);
        } else {
          state.documentFrequency.set(term, updated);
        }
      }
    }

    state.totalDocuments += remove ? -entries.length : entries.length;
    state.totalDocuments = Math.max(0, state.totalDocuments);
  }

  /**
   * Check if entry is cached and still valid
   */
  function getCachedEntry(hash: string): MemoryEntry | null {
    const cached = state.entryCache.get(hash);
    if (!cached) return null;

    // Entry is valid if found in cache
    return cached.entry;
  }

  /** Max cache entries to prevent unbounded growth */
  const MAX_CACHE_SIZE = 10000;

  /**
   * Cache entry with score
   */
  function cacheEntry(entry: MemoryEntry, score: number): void {
    // Evict oldest entries if cache is full
    if (state.entryCache.size >= MAX_CACHE_SIZE) {
      const entries = Array.from(state.entryCache.entries());
      entries.sort((a, b) => a[1].timestamp - b[1].timestamp);
      // Remove oldest 20%
      const toRemove = Math.floor(MAX_CACHE_SIZE * 0.2);
      for (let i = 0; i < toRemove && i < entries.length; i++) {
        const entry = entries[i];
        if (entry) {
          state.entryCache.delete(entry[0]);
        }
      }
    }

    state.entryCache.set(entry.hash, {
      entry,
      score,
      timestamp: Date.now(),
    });
  }

  function optimizeIncremental(
    newEntries: MemoryEntry[],
    budget?: number,
  ): PruneResult & { budgetUtilization: number } {
    const startTime = Date.now();
    state.updateCount++;

    // Force full optimization if interval reached
    if (state.updateCount >= fullOptimizationInterval) {
      // Get all cached entries
      const allEntries = Array.from(state.entryCache.values()).map((c) => c.entry);
      return optimizeFull([...allEntries, ...newEntries], budget);
    }

    // Filter out already-cached entries
    const uncachedEntries: MemoryEntry[] = [];
    const cachedEntries: MemoryEntry[] = [];

    for (const entry of newEntries) {
      const cached = getCachedEntry(entry.hash);
      if (cached) {
        cachedEntries.push(cached);
      } else {
        uncachedEntries.push(entry);
      }
    }

    // Update document frequency for new entries only
    if (uncachedEntries.length > 0) {
      updateDocumentFrequency(uncachedEntries, false);
    }

    // Combine with cached entries for scoring context
    const allEntries = [...cachedEntries, ...uncachedEntries];

    // Score only uncached entries (reuse cached scores)
    for (const entry of uncachedEntries) {
      const score = pruner.priorityScore(entry, allEntries);
      cacheEntry(entry, score);
    }

    // Get all current entries (from cache + new)
    const currentEntries = Array.from(state.entryCache.values()).map((c) => c.entry);

    // Calculate tokens before
    const tokensBefore = currentEntries.reduce((sum, e) => sum + estimateTokens(e.content), 0);

    // Prune to fit budget
    const result = pruner.pruneToFit(currentEntries, budget);

    // Calculate tokens after
    const tokensAfter = result.kept.reduce((sum, e) => sum + estimateTokens(e.content), 0);

    // Update cache: remove pruned entries
    for (const removed of result.removed) {
      state.entryCache.delete(removed.hash);
    }

    // Update document frequency to reflect removal
    if (result.removed.length > 0) {
      updateDocumentFrequency(result.removed, true);
    }

    // Record metrics
    const duration = Date.now() - startTime;
    const cacheHitRate = newEntries.length > 0 ? cachedEntries.length / newEntries.length : 0;

    getMetrics().recordOptimization({
      timestamp: Date.now(),
      duration,
      tokensBefore,
      tokensAfter,
      entriesProcessed: newEntries.length,
      entriesKept: result.kept.length,
      cacheHitRate,
      memoryUsage: process.memoryUsage().heapUsed,
    });

    return result;
  }

  function optimizeFull(
    allEntries: MemoryEntry[],
    budget?: number,
  ): PruneResult & { budgetUtilization: number } {
    const startTime = Date.now();

    // Calculate tokens before
    const tokensBefore = allEntries.reduce((sum, e) => sum + estimateTokens(e.content), 0);

    // Reset state
    state.entryCache.clear();
    state.documentFrequency.clear();
    state.totalDocuments = 0;
    state.updateCount = 0;
    state.lastFullOptimization = Date.now();

    // Rebuild document frequency table
    updateDocumentFrequency(allEntries, false);

    // Score and cache all entries
    for (const entry of allEntries) {
      const score = pruner.priorityScore(entry, allEntries);
      cacheEntry(entry, score);
    }

    // Prune to fit budget
    const result = pruner.pruneToFit(allEntries, budget);

    // Calculate tokens after
    const tokensAfter = result.kept.reduce((sum, e) => sum + estimateTokens(e.content), 0);

    // Update cache: remove pruned entries
    for (const removed of result.removed) {
      state.entryCache.delete(removed.hash);
    }

    // Update document frequency to reflect removal
    if (result.removed.length > 0) {
      updateDocumentFrequency(result.removed, true);
    }

    // Record metrics
    const duration = Date.now() - startTime;

    getMetrics().recordOptimization({
      timestamp: Date.now(),
      duration,
      tokensBefore,
      tokensAfter,
      entriesProcessed: allEntries.length,
      entriesKept: result.kept.length,
      cacheHitRate: 0, // Full optimization has no cache hits
      memoryUsage: process.memoryUsage().heapUsed,
    });

    return result;
  }

  function getState(): IncrementalOptimizerState {
    return {
      entryCache: new Map(state.entryCache),
      documentFrequency: new Map(state.documentFrequency),
      totalDocuments: state.totalDocuments,
      updateCount: state.updateCount,
      lastFullOptimization: state.lastFullOptimization,
    };
  }

  function restoreState(restoredState: IncrementalOptimizerState): void {
    state = {
      entryCache: new Map(restoredState.entryCache),
      documentFrequency: new Map(restoredState.documentFrequency),
      totalDocuments: restoredState.totalDocuments,
      updateCount: restoredState.updateCount,
      lastFullOptimization: restoredState.lastFullOptimization,
    };
  }

  function reset(): void {
    state = {
      entryCache: new Map(),
      documentFrequency: new Map(),
      totalDocuments: 0,
      updateCount: 0,
      lastFullOptimization: Date.now(),
    };
  }

  function getStats() {
    return {
      cachedEntries: state.entryCache.size,
      uniqueTerms: state.documentFrequency.size,
      totalDocuments: state.totalDocuments,
      updateCount: state.updateCount,
      lastFullOptimization: state.lastFullOptimization,
    };
  }

  function serializeState(): string {
    const s = getState();
    return JSON.stringify({
      entryCache: Array.from(s.entryCache.entries()),
      documentFrequency: Array.from(s.documentFrequency.entries()),
      totalDocuments: s.totalDocuments,
      updateCount: s.updateCount,
      lastFullOptimization: s.lastFullOptimization,
    });
  }

  function deserializeState(json: string): boolean {
    try {
      const parsed = JSON.parse(json);
      restoreState({
        entryCache: new Map(parsed.entryCache),
        documentFrequency: new Map(parsed.documentFrequency),
        totalDocuments: parsed.totalDocuments,
        updateCount: parsed.updateCount,
        lastFullOptimization: parsed.lastFullOptimization,
      });
      return true;
    } catch {
      return false;
    }
  }

  return {
    optimizeIncremental,
    optimizeFull,
    getState,
    restoreState,
    reset,
    getStats,
    serializeState,
    deserializeState,
  };
}
