/**
 * Confidence States - Entry classification by score
 *
 * Entries exist in three states: silent, ready, active.
 * Classifies memory entries by score into silent/ready/active states.
 */

import type { ConfidenceState, MemoryEntry, StateDistribution } from '../types/memory.js';

export interface ConfidenceStatesConfig {
  /** Score threshold for active state (e.g., 0.7) */
  activeThreshold: number;
  /** Score threshold for ready state (e.g., 0.3) */
  readyThreshold: number;
}

export interface ConfidenceStates {
  /**
   * Calculate state based on entry score and BTSP flag
   * @param entry - Memory entry
   * @returns Confidence state
   */
  calculateState(entry: MemoryEntry): ConfidenceState;

  /**
   * Transition entry to correct state based on its score
   * @param entry - Entry to transition
   * @returns Entry with updated state
   */
  transition(entry: MemoryEntry): MemoryEntry;

  /**
   * Get distribution of states across all entries
   * @param entries - All memory entries
   * @returns State distribution with counts
   */
  getDistribution(entries: MemoryEntry[]): StateDistribution;
}

/**
 * Create a confidence states manager
 * @param config - States configuration
 * @returns ConfidenceStates instance
 */
export function createConfidenceStates(config: ConfidenceStatesConfig): ConfidenceStates {
  const { activeThreshold, readyThreshold } = config;

  function calculateState(entry: MemoryEntry): ConfidenceState {
    // BTSP entries are always active
    if (entry.isBTSP) {
      return 'active';
    }

    // State based on score thresholds
    // Active: score >= 0.7
    if (entry.score >= activeThreshold) {
      return 'active';
    }

    // Ready: 0.3 <= score < 0.7
    if (entry.score >= readyThreshold) {
      return 'ready';
    }

    // Silent: score < 0.3
    return 'silent';
  }

  function transition(entry: MemoryEntry): MemoryEntry {
    const newState = calculateState(entry);

    return {
      ...entry,
      state: newState,
    };
  }

  function getDistribution(entries: MemoryEntry[]): StateDistribution {
    const distribution: StateDistribution = {
      silent: 0,
      ready: 0,
      active: 0,
      total: entries.length,
    };

    for (const entry of entries) {
      const state = calculateState(entry);
      distribution[state]++;
    }

    return distribution;
  }

  return {
    calculateState,
    transition,
    getDistribution,
  };
}
