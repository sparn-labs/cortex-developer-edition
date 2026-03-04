/**
 * Incremental Optimizer Tests
 */

import { beforeEach, describe, expect, it } from 'vitest';
import { createIncrementalOptimizer } from '../../src/core/incremental-optimizer.js';
import type { MemoryEntry } from '../../src/types/memory.js';
import { hashContent } from '../../src/utils/hash.js';

describe('Incremental Optimizer', () => {
  const createTestEntry = (content: string): MemoryEntry => ({
    id: Math.random().toString(),
    content,
    hash: hashContent(content),
    timestamp: Date.now(),
    score: 0.5,
    ttl: 24 * 3600,
    state: 'ready',
    accessCount: 0,
    tags: [],
    metadata: {},
    isBTSP: false,
  });

  const config = {
    tokenBudget: 200,
    decay: { defaultTTL: 24, decayThreshold: 0.95 },
    states: { activeThreshold: 0.7, readyThreshold: 0.3 },
    fullOptimizationInterval: 50,
  };

  let optimizer: ReturnType<typeof createIncrementalOptimizer>;

  beforeEach(() => {
    optimizer = createIncrementalOptimizer(config);
  });

  describe('optimizeIncremental', () => {
    it('should cache entry scores for reuse', () => {
      const entry = createTestEntry('Test content for caching');

      // First optimization
      optimizer.optimizeIncremental([entry]);

      const stats1 = optimizer.getStats();
      expect(stats1.cachedEntries).toBe(1);

      // Second optimization with same content should use cache
      optimizer.optimizeIncremental([entry]);

      const stats2 = optimizer.getStats();
      expect(stats2.cachedEntries).toBe(1); // Same entry, still cached
    });

    it('should only process new entries incrementally', () => {
      const entry1 = createTestEntry('First entry');
      const entry2 = createTestEntry('Second entry');

      // Add first entry
      optimizer.optimizeIncremental([entry1]);

      // Add second entry - should only process entry2
      const result = optimizer.optimizeIncremental([entry2]);

      expect(result.kept.length).toBeGreaterThan(0);
    });

    it('should track update count', () => {
      const entry = createTestEntry('Test');

      optimizer.optimizeIncremental([entry]);
      const stats1 = optimizer.getStats();

      optimizer.optimizeIncremental([createTestEntry('Another')]);
      const stats2 = optimizer.getStats();

      expect(stats2.updateCount).toBe(stats1.updateCount + 1);
    });

    it('should force full optimization after interval', () => {
      const shortIntervalConfig = {
        ...config,
        fullOptimizationInterval: 2,
      };

      const shortOptimizer = createIncrementalOptimizer(shortIntervalConfig);

      // First update (count = 1)
      shortOptimizer.optimizeIncremental([createTestEntry('Entry 1')]);

      // Second update (count = 2, triggers full optimization at threshold)
      shortOptimizer.optimizeIncremental([createTestEntry('Entry 2')]);

      // After full optimization, count is reset
      const stats = shortOptimizer.getStats();

      // Update count should be 0 after full optimization
      expect(stats.updateCount).toBe(0);
    });

    it('should respect token budget', () => {
      const entries = Array.from({ length: 10 }, (_, i) =>
        createTestEntry(`Entry ${i} with some content to fill tokens`),
      );

      const result = optimizer.optimizeIncremental(entries, 100);

      expect(result.prunedTokens).toBeLessThanOrEqual(100);
    });

    it('should maintain document frequency table', () => {
      optimizer.optimizeIncremental([createTestEntry('unique word alpha')]);
      const stats1 = optimizer.getStats();

      optimizer.optimizeIncremental([createTestEntry('unique word beta')]);
      const stats2 = optimizer.getStats();

      // Should track unique terms
      expect(stats2.uniqueTerms).toBeGreaterThanOrEqual(stats1.uniqueTerms);
    });
  });

  describe('optimizeFull', () => {
    it('should reset state and recompute all scores', () => {
      // Add some entries incrementally first
      optimizer.optimizeIncremental([createTestEntry('Entry 1')]);
      optimizer.optimizeIncremental([createTestEntry('Entry 2')]);

      const _statsBefore = optimizer.getStats();

      // Run full optimization
      const entries = [
        createTestEntry('Entry A'),
        createTestEntry('Entry B'),
        createTestEntry('Entry C'),
      ];

      optimizer.optimizeFull(entries);

      const statsAfter = optimizer.getStats();

      // Update count should be reset
      expect(statsAfter.updateCount).toBe(0);

      // Should have new entries cached
      expect(statsAfter.cachedEntries).toBe(entries.length);
    });

    it('should update last full optimization timestamp', () => {
      const statsBefore = optimizer.getStats();
      const timestampBefore = statsBefore.lastFullOptimization;

      // Wait a bit
      const start = Date.now();
      while (Date.now() - start < 10) {
        // Busy wait
      }

      optimizer.optimizeFull([createTestEntry('Test')]);

      const statsAfter = optimizer.getStats();
      expect(statsAfter.lastFullOptimization).toBeGreaterThan(timestampBefore);
    });
  });

  describe('state management', () => {
    it('should get current state', () => {
      optimizer.optimizeIncremental([createTestEntry('Test entry')]);

      const state = optimizer.getState();

      expect(state.entryCache.size).toBeGreaterThan(0);
      expect(state.documentFrequency.size).toBeGreaterThan(0);
      expect(state.totalDocuments).toBeGreaterThan(0);
    });

    it('should restore state correctly', () => {
      optimizer.optimizeIncremental([createTestEntry('Entry 1')]);
      optimizer.optimizeIncremental([createTestEntry('Entry 2')]);

      const state = optimizer.getState();

      // Create new optimizer and restore state
      const newOptimizer = createIncrementalOptimizer(config);
      newOptimizer.restoreState(state);

      const restoredStats = newOptimizer.getStats();

      expect(restoredStats.cachedEntries).toBe(2);
      expect(restoredStats.totalDocuments).toBe(state.totalDocuments);
    });

    it('should reset state completely', () => {
      optimizer.optimizeIncremental([createTestEntry('Entry 1')]);
      optimizer.optimizeIncremental([createTestEntry('Entry 2')]);

      optimizer.reset();

      const stats = optimizer.getStats();

      expect(stats.cachedEntries).toBe(0);
      expect(stats.uniqueTerms).toBe(0);
      expect(stats.totalDocuments).toBe(0);
      expect(stats.updateCount).toBe(0);
    });
  });

  describe('getStats', () => {
    it('should return accurate statistics', () => {
      const entry1 = createTestEntry('Alpha beta gamma');
      const entry2 = createTestEntry('Delta epsilon zeta');

      optimizer.optimizeIncremental([entry1]);
      optimizer.optimizeIncremental([entry2]);

      const stats = optimizer.getStats();

      expect(stats.cachedEntries).toBe(2);
      expect(stats.uniqueTerms).toBeGreaterThan(0);
      expect(stats.totalDocuments).toBe(2);
      expect(stats.updateCount).toBe(2);
      expect(stats.lastFullOptimization).toBeGreaterThan(0);
    });
  });
});
