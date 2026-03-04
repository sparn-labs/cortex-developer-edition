import { beforeEach, describe, expect, it } from 'vitest';
import { createEngramScorer } from '../../src/core/engram-scorer.js';
import type { MemoryEntry } from '../../src/types/memory.js';

describe('EngramScorer', () => {
  let scorer: ReturnType<typeof createEngramScorer>;

  beforeEach(() => {
    scorer = createEngramScorer({ defaultTTL: 24, decayThreshold: 0.95 });
  });

  it('uses exponential decay formula', () => {
    const now = Date.now();
    const entry: MemoryEntry = {
      id: 'test',
      content: 'test content',
      hash: 'hash',
      timestamp: now - 12 * 3600 * 1000, // 12 hours ago (milliseconds)
      score: 1.0,
      ttl: 24 * 3600, // 24 hours in seconds
      state: 'active',
      accessCount: 0,
      tags: [],
      metadata: {},
      isBTSP: false,
    };

    const score = scorer.calculateScore(entry, now);

    // Exponential decay: 1 - e^(-age/TTL)
    // age = 12 hours, TTL = 24 hours
    // decay = 1 - e^(-12/24) = 1 - e^(-0.5) ≈ 0.393
    // score = 1.0 * (1 - 0.393) ≈ 0.607
    expect(score).toBeGreaterThan(0.5);
    expect(score).toBeLessThan(0.7);
  });

  it('factors in accessCount', () => {
    const now = Date.now();
    const baseEntry: MemoryEntry = {
      id: 'test',
      content: 'test',
      hash: 'hash',
      timestamp: now - 12 * 3600 * 1000, // milliseconds
      score: 1.0,
      ttl: 24 * 3600,
      state: 'active',
      accessCount: 0,
      tags: [],
      metadata: {},
      isBTSP: false,
    };

    const accessedEntry: MemoryEntry = {
      ...baseEntry,
      accessCount: 5,
    };

    const scoreBase = scorer.calculateScore(baseEntry, now);
    const scoreAccessed = scorer.calculateScore(accessedEntry, now);

    // Higher accessCount should result in higher score
    expect(scoreAccessed).toBeGreaterThan(scoreBase);
  });

  it('refreshTTL resets TTL to default', () => {
    const entry: MemoryEntry = {
      id: 'test',
      content: 'test',
      hash: 'hash',
      timestamp: Date.now() - 20 * 3600 * 1000, // milliseconds
      score: 0.1,
      ttl: 1000, // Low TTL
      state: 'silent',
      accessCount: 0,
      tags: [],
      metadata: {},
      isBTSP: false,
    };

    const refreshed = scorer.refreshTTL(entry);

    expect(refreshed.ttl).toBe(24 * 3600); // Reset to 24 hours (in seconds)
    expect(refreshed.timestamp).toBeGreaterThan(entry.timestamp);
  });

  it('calculateDecay returns 0.0-1.0 range', () => {
    const cases = [
      { age: 0, ttl: 24 * 3600, expected: 0.0 }, // Fresh entry
      { age: 24 * 3600, ttl: 24 * 3600, expected: 0.632 }, // One TTL period
      { age: 100 * 3600, ttl: 24 * 3600, expected: 0.98 }, // Very old
    ];

    for (const { age, ttl, expected } of cases) {
      const decay = scorer.calculateDecay(age, ttl);
      expect(decay).toBeGreaterThanOrEqual(0.0);
      expect(decay).toBeLessThanOrEqual(1.0);
      expect(decay).toBeCloseTo(expected, 1); // Within 0.1
    }
  });

  it('marks entries with decay ≥0.95 for pruning', () => {
    const now = Date.now();
    const oldEntry: MemoryEntry = {
      id: 'old',
      content: 'old content',
      hash: 'hash',
      timestamp: now - 100 * 3600 * 1000, // 100 hours ago (milliseconds)
      score: 1.0,
      ttl: 24 * 3600, // 24 hours in seconds
      state: 'active',
      accessCount: 0,
      tags: [],
      metadata: {},
      isBTSP: false,
    };

    const score = scorer.calculateScore(oldEntry, now);
    const decay = scorer.calculateDecay((now - oldEntry.timestamp) / 1000, oldEntry.ttl);

    expect(decay).toBeGreaterThanOrEqual(0.95);
    expect(score).toBeLessThan(0.1); // Should be very low, candidate for pruning
  });
});
