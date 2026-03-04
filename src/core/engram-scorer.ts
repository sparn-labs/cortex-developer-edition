/**
 * Engram Scorer - Implements time-based memory decay
 *
 * Older entries fade over time unless reinforced by access.
 * Applies exponential decay formula to memory scores based on age and access count.
 *
 * Formula: decay = 1 - e^(-age/TTL)
 * Score adjustment: score_new = score_old * (1 - decay) + (accessCount bonus)
 */

import type { MemoryEntry } from '../types/memory.js';

export interface EngramScorerConfig {
  /** Default TTL in hours for new entries */
  defaultTTL: number;
  /** Decay threshold (0.0-1.0) above which entries are marked for pruning */
  decayThreshold: number;
}

export interface EngramScorer {
  /**
   * Calculate current score for an entry based on decay and access count
   * @param entry - Memory entry to score
   * @param currentTime - Current timestamp in milliseconds (for testing)
   * @returns Updated score (0.0-1.0)
   */
  calculateScore(entry: MemoryEntry, currentTime?: number): number;

  /**
   * Refresh TTL to default value
   * @param entry - Entry to refresh
   * @returns Entry with refreshed TTL and timestamp
   */
  refreshTTL(entry: MemoryEntry): MemoryEntry;

  /**
   * Calculate decay factor (0.0-1.0) based on age and TTL
   * @param ageInSeconds - Age of entry in seconds
   * @param ttlInSeconds - TTL in seconds
   * @returns Decay factor (0.0 = fresh, 1.0 = fully decayed)
   */
  calculateDecay(ageInSeconds: number, ttlInSeconds: number): number;
}

/**
 * Create an engram scorer instance
 * @param config - Scorer configuration
 * @returns EngramScorer instance
 */
export function createEngramScorer(
  config: EngramScorerConfig & { recencyBoostMinutes?: number; recencyBoostMultiplier?: number },
): EngramScorer {
  const { defaultTTL } = config;
  const recencyWindowMs = (config.recencyBoostMinutes ?? 30) * 60 * 1000;
  const recencyMultiplier = config.recencyBoostMultiplier ?? 1.3;

  function calculateDecay(ageInSeconds: number, ttlInSeconds: number): number {
    if (ttlInSeconds === 0) return 1.0; // Instant decay
    if (ageInSeconds <= 0) return 0.0; // Fresh entry

    // Exponential decay: 1 - e^(-age/TTL)
    const ratio = ageInSeconds / ttlInSeconds;
    const decay = 1 - Math.exp(-ratio);

    // Clamp to [0.0, 1.0]
    return Math.max(0, Math.min(1, decay));
  }

  function calculateScore(entry: MemoryEntry, currentTime: number = Date.now()): number {
    // Calculate age in seconds
    const ageInMilliseconds = currentTime - entry.timestamp;
    const ageInSeconds = Math.max(0, ageInMilliseconds / 1000);

    // Calculate decay factor
    const decay = calculateDecay(ageInSeconds, entry.ttl);

    // Base score reduced by decay
    let score = entry.score * (1 - decay);

    // Access count bonus (diminishing returns via log)
    if (entry.accessCount > 0) {
      const accessBonus = Math.log(entry.accessCount + 1) * 0.1;
      score = Math.min(1.0, score + accessBonus);
    }

    // BTSP entries maintain high score
    if (entry.isBTSP) {
      score = Math.max(score, 0.9);
    }

    // Recency boost for non-BTSP entries within the recency window
    if (!entry.isBTSP && recencyWindowMs > 0) {
      const ageMs = currentTime - entry.timestamp;
      if (ageMs >= 0 && ageMs < recencyWindowMs) {
        const boostFactor = 1 + (recencyMultiplier - 1) * (1 - ageMs / recencyWindowMs);
        score = score * boostFactor;
      }
    }

    return Math.max(0, Math.min(1, score));
  }

  function refreshTTL(entry: MemoryEntry): MemoryEntry {
    return {
      ...entry,
      ttl: defaultTTL * 3600, // Convert hours to seconds
      timestamp: Date.now(),
    };
  }

  return {
    calculateScore,
    refreshTTL,
    calculateDecay,
  };
}
