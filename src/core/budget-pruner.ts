/**
 * Budget-Aware Pruner - Token budget optimization
 *
 * Unlike SparsePruner which keeps top N% entries, BudgetPruner fits entries
 * within a target token budget using priority scoring that combines:
 * - TF-IDF relevance
 * - Time-based decay
 * - Confidence state multipliers
 * - BTSP bypass (always included)
 *
 * Target use case: Real-time optimization for Opus model (~50K token budget)
 */

import type { RealtimeConfig } from '../types/config.js';
import type { MemoryEntry } from '../types/memory.js';
import type { PruneResult } from '../types/pruner.js';
import { createTFIDFIndex, scoreTFIDF, type TFIDFIndex } from '../utils/tfidf.js';
import { estimateTokens } from '../utils/tokenizer.js';
import { createEngramScorer } from './engram-scorer.js';

export interface BudgetPrunerConfig {
  /** Target token budget */
  tokenBudget: number;
  /** Decay configuration */
  decay: {
    defaultTTL: number;
    decayThreshold: number;
  };
  /** State multipliers */
  states: {
    activeThreshold: number;
    readyThreshold: number;
  };
}

export interface BudgetPruner {
  /**
   * Prune entries to fit within token budget
   * @param entries - Memory entries to prune
   * @param budget - Optional override budget (uses config default if not provided)
   * @returns Result with kept/removed entries and budget utilization
   */
  pruneToFit(entries: MemoryEntry[], budget?: number): PruneResult & { budgetUtilization: number };

  /**
   * Calculate priority score for an entry
   * @param entry - Entry to score
   * @param allEntries - All entries for TF-IDF calculation
   * @param index - Optional pre-computed TF-IDF index
   * @returns Priority score (higher = more important)
   */
  priorityScore(entry: MemoryEntry, allEntries: MemoryEntry[], index?: TFIDFIndex): number;
}

/**
 * Create a budget-aware pruner instance
 * @param config - Pruner configuration
 * @returns BudgetPruner instance
 */
export function createBudgetPruner(config: BudgetPrunerConfig): BudgetPruner {
  const { tokenBudget, decay } = config;
  const engramScorer = createEngramScorer(decay);

  function getStateMultiplier(entry: MemoryEntry): number {
    // BTSP entries get max priority (handled separately, but keep high multiplier)
    if (entry.isBTSP) return 2.0;

    // State-based multipliers
    switch (entry.state) {
      case 'active':
        return 2.0;
      case 'ready':
        return 1.0;
      case 'silent':
        return 0.5;
      default:
        return 1.0;
    }
  }

  function priorityScore(
    entry: MemoryEntry,
    allEntries: MemoryEntry[],
    index?: TFIDFIndex,
  ): number {
    const tfidf = index
      ? scoreTFIDF(entry, index)
      : scoreTFIDF(entry, createTFIDFIndex(allEntries));
    const currentScore = engramScorer.calculateScore(entry);
    const engramDecay = 1 - currentScore; // Lower decay = higher priority
    const stateMultiplier = getStateMultiplier(entry);

    // Priority = TF-IDF * (1 - decay) * state_multiplier
    // This balances relevance, recency, and confidence state
    return tfidf * (1 - engramDecay) * stateMultiplier;
  }

  function pruneToFit(
    entries: MemoryEntry[],
    budget: number = tokenBudget,
  ): PruneResult & { budgetUtilization: number } {
    if (entries.length === 0) {
      return {
        kept: [],
        removed: [],
        originalTokens: 0,
        prunedTokens: 0,
        budgetUtilization: 0,
      };
    }

    // Calculate original token count
    const originalTokens = entries.reduce((sum, e) => sum + estimateTokens(e.content), 0);

    // Step 1: Separate BTSP entries (high priority but still within budget)
    const btspEntries = entries.filter((e) => e.isBTSP);
    const regularEntries = entries.filter((e) => !e.isBTSP);

    // Guard: if BTSP entries alone exceed budget, only include most recent ones
    let includedBtsp: MemoryEntry[] = [];
    let btspTokens = 0;
    const sortedBtsp = [...btspEntries].sort((a, b) => b.timestamp - a.timestamp);
    for (const entry of sortedBtsp) {
      const tokens = estimateTokens(entry.content);
      if (btspTokens + tokens <= budget * 0.8) {
        // Reserve 20% for regular entries
        includedBtsp.push(entry);
        btspTokens += tokens;
      }
    }
    // If no BTSP fits, include at least the most recent one
    if (includedBtsp.length === 0 && sortedBtsp.length > 0) {
      const firstBtsp = sortedBtsp[0];
      if (firstBtsp) {
        includedBtsp = [firstBtsp];
        btspTokens = estimateTokens(firstBtsp.content);
      }
    }

    // Track BTSP entries excluded by the guard
    const excludedBtsp = btspEntries.filter((e) => !includedBtsp.includes(e));

    // Step 2: Build TF-IDF index once and score regular entries
    const tfidfIndex = createTFIDFIndex(entries);
    const scored = regularEntries.map((entry) => ({
      entry,
      score: priorityScore(entry, entries, tfidfIndex),
      tokens: estimateTokens(entry.content),
    }));

    // Step 3: Sort by priority score descending
    scored.sort((a, b) => b.score - a.score);

    // Step 4: Greedy fill until budget exceeded
    const kept: MemoryEntry[] = [...includedBtsp];
    const removed: MemoryEntry[] = [...excludedBtsp];
    let currentTokens = btspTokens;

    for (const item of scored) {
      if (currentTokens + item.tokens <= budget) {
        kept.push(item.entry);
        currentTokens += item.tokens;
      } else {
        removed.push(item.entry);
      }
    }

    const budgetUtilization = budget > 0 ? currentTokens / budget : 0;

    return {
      kept,
      removed,
      originalTokens,
      prunedTokens: currentTokens,
      budgetUtilization,
    };
  }

  return {
    pruneToFit,
    priorityScore,
  };
}

/**
 * Helper to create budget pruner from RealtimeConfig
 * @param realtimeConfig - Realtime configuration
 * @param decayConfig - Decay configuration
 * @param statesConfig - States configuration
 * @returns BudgetPruner instance
 */
export function createBudgetPrunerFromConfig(
  realtimeConfig: RealtimeConfig,
  decayConfig: { defaultTTL: number; decayThreshold: number },
  statesConfig: { activeThreshold: number; readyThreshold: number },
): BudgetPruner {
  return createBudgetPruner({
    tokenBudget: realtimeConfig.tokenBudget,
    decay: decayConfig,
    states: statesConfig,
  });
}
