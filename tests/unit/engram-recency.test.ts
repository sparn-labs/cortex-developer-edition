/**
 * Engram Recency Boost Tests
 */

import { describe, expect, it } from 'vitest';
import { createEngramScorer } from '../../src/core/engram-scorer.js';
import type { MemoryEntry } from '../../src/types/memory.js';

function makeEntry(overrides: Partial<MemoryEntry> = {}): MemoryEntry {
  return {
    id: 'test-1',
    content: 'test content',
    hash: 'hash-1',
    timestamp: Date.now(),
    score: 0.8,
    ttl: 86400,
    state: 'active',
    accessCount: 0,
    tags: [],
    metadata: {},
    isBTSP: false,
    ...overrides,
  };
}

describe('Engram Recency Boost', () => {
  const scorer = createEngramScorer({
    defaultTTL: 24,
    decayThreshold: 0.95,
    recencyBoostMinutes: 30,
    recencyBoostMultiplier: 1.3,
  });

  it('should give full boost at age 0', () => {
    const now = Date.now();
    const entry = makeEntry({ timestamp: now });

    const score = scorer.calculateScore(entry, now);
    // At age 0: boost factor = 1 + (1.3-1) * (1 - 0/window) = 1.3
    // Base score 0.8 * 1.3 = 1.04 -> clamped to 1.0
    expect(score).toBeCloseTo(1.0, 1);
  });

  it('should give no boost at age = window edge', () => {
    const now = Date.now();
    const windowMs = 30 * 60 * 1000;
    const entry = makeEntry({ timestamp: now - windowMs });

    const score = scorer.calculateScore(entry, now);
    const scorerNoBoost = createEngramScorer({
      defaultTTL: 24,
      decayThreshold: 0.95,
      recencyBoostMinutes: 0,
    });
    const scoreNoBoost = scorerNoBoost.calculateScore(entry, now);

    // At exactly the window edge, boost factor = 1 + (1.3-1) * (1 - 1) = 1.0
    expect(score).toBeCloseTo(scoreNoBoost, 2);
  });

  it('should give no boost beyond the window', () => {
    const now = Date.now();
    const windowMs = 30 * 60 * 1000;
    const entry = makeEntry({ timestamp: now - windowMs - 1000 });

    const score = scorer.calculateScore(entry, now);
    const scorerNoBoost = createEngramScorer({
      defaultTTL: 24,
      decayThreshold: 0.95,
      recencyBoostMinutes: 0,
    });
    const scoreNoBoost = scorerNoBoost.calculateScore(entry, now);

    expect(score).toBeCloseTo(scoreNoBoost, 2);
  });

  it('should skip recency boost for BTSP entries', () => {
    const now = Date.now();
    const btspEntry = makeEntry({ timestamp: now, isBTSP: true, score: 1.0 });

    const score = scorer.calculateScore(btspEntry, now);
    // BTSP entries are already >= 0.9, recency boost should not be applied
    expect(score).toBeGreaterThanOrEqual(0.9);
  });

  it('should respect custom config values', () => {
    const customScorer = createEngramScorer({
      defaultTTL: 24,
      decayThreshold: 0.95,
      recencyBoostMinutes: 60,
      recencyBoostMultiplier: 2.0,
    });

    const now = Date.now();
    const entry = makeEntry({ timestamp: now, score: 0.5 });

    const score = customScorer.calculateScore(entry, now);
    // At age 0: boost factor = 1 + (2.0-1) * 1 = 2.0
    // Score 0.5 * 2.0 = 1.0
    expect(score).toBeCloseTo(1.0, 1);
  });

  it('should default to 30 min window and 1.3x multiplier', () => {
    const defaultScorer = createEngramScorer({
      defaultTTL: 24,
      decayThreshold: 0.95,
    });

    const now = Date.now();
    const entry = makeEntry({ timestamp: now, score: 0.5 });

    const score = defaultScorer.calculateScore(entry, now);
    // Default boost at age 0: 0.5 * 1.3 = 0.65
    expect(score).toBeCloseTo(0.65, 1);
  });

  it('should provide partial boost at mid-window', () => {
    const now = Date.now();
    const halfWindow = 15 * 60 * 1000; // 15 minutes
    const entry = makeEntry({ timestamp: now - halfWindow, score: 0.6 });

    const score = scorer.calculateScore(entry, now);
    // Should be between unboosted and fully boosted
    const scorerNoBoost = createEngramScorer({
      defaultTTL: 24,
      decayThreshold: 0.95,
      recencyBoostMinutes: 0,
    });
    const scoreNoBoost = scorerNoBoost.calculateScore(entry, now);

    expect(score).toBeGreaterThan(scoreNoBoost);
  });
});
