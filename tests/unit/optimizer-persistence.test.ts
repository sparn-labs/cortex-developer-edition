/**
 * Optimizer State Persistence Tests
 */

import { describe, expect, it } from 'vitest';
import { createIncrementalOptimizer } from '../../src/core/incremental-optimizer.js';
import type { MemoryEntry } from '../../src/types/memory.js';

function makeEntry(id: string, content: string): MemoryEntry {
  return {
    id,
    content,
    hash: `hash-${id}`,
    timestamp: Date.now(),
    score: 0.5,
    ttl: 86400,
    state: 'active',
    accessCount: 0,
    tags: [],
    metadata: {},
    isBTSP: false,
  };
}

const defaultConfig = {
  tokenBudget: 50000,
  decay: { defaultTTL: 24, decayThreshold: 0.95 },
  states: { activeThreshold: 0.7, readyThreshold: 0.3 },
  fullOptimizationInterval: 50,
};

describe('Optimizer State Persistence', () => {
  it('should round-trip serialize/deserialize', () => {
    const optimizer = createIncrementalOptimizer(defaultConfig);

    // Add some entries to build state
    const entries = [makeEntry('e1', 'hello world'), makeEntry('e2', 'test content here')];
    optimizer.optimizeFull(entries);

    const serialized = optimizer.serializeState();
    expect(serialized).toBeTruthy();

    // Verify it's valid JSON
    const parsed = JSON.parse(serialized);
    expect(parsed.totalDocuments).toBe(2);
    expect(parsed.documentFrequency).toBeDefined();
    expect(parsed.entryCache).toBeDefined();
  });

  it('should produce valid JSON', () => {
    const optimizer = createIncrementalOptimizer(defaultConfig);
    optimizer.optimizeFull([makeEntry('e1', 'test')]);

    const json = optimizer.serializeState();
    expect(() => JSON.parse(json)).not.toThrow();
  });

  it('should restore state correctly', () => {
    const optimizer1 = createIncrementalOptimizer(defaultConfig);
    const entries = [
      makeEntry('e1', 'alpha beta'),
      makeEntry('e2', 'gamma delta'),
      makeEntry('e3', 'alpha gamma'),
    ];
    optimizer1.optimizeFull(entries);

    const stats1 = optimizer1.getStats();
    const serialized = optimizer1.serializeState();

    // Create new optimizer and restore
    const optimizer2 = createIncrementalOptimizer(defaultConfig);
    const success = optimizer2.deserializeState(serialized);
    expect(success).toBe(true);

    const stats2 = optimizer2.getStats();
    expect(stats2.totalDocuments).toBe(stats1.totalDocuments);
    expect(stats2.uniqueTerms).toBe(stats1.uniqueTerms);
    expect(stats2.cachedEntries).toBe(stats1.cachedEntries);
  });

  it('should handle missing file (return false)', () => {
    const optimizer = createIncrementalOptimizer(defaultConfig);
    const result = optimizer.deserializeState('invalid json {{{');
    expect(result).toBe(false);
  });

  it('should handle empty state', () => {
    const optimizer = createIncrementalOptimizer(defaultConfig);
    const serialized = optimizer.serializeState();
    const parsed = JSON.parse(serialized);

    expect(parsed.totalDocuments).toBe(0);
    expect(parsed.entryCache.length).toBe(0);
    expect(parsed.documentFrequency.length).toBe(0);
  });

  it('should handle large state efficiently', () => {
    const optimizer = createIncrementalOptimizer(defaultConfig);
    const entries = Array.from({ length: 100 }, (_, i) =>
      makeEntry(`e${i}`, `entry ${i} with content about topic ${i % 10}`),
    );
    optimizer.optimizeFull(entries);

    const start = performance.now();
    const serialized = optimizer.serializeState();
    const elapsed = performance.now() - start;

    expect(serialized.length).toBeGreaterThan(0);
    expect(elapsed).toBeLessThan(100);
  });

  it('should preserve stats after restore', () => {
    const optimizer = createIncrementalOptimizer(defaultConfig);
    const entries = [makeEntry('e1', 'test data')];
    optimizer.optimizeFull(entries);

    const serialized = optimizer.serializeState();

    const optimizer2 = createIncrementalOptimizer(defaultConfig);
    optimizer2.deserializeState(serialized);

    const stats = optimizer2.getStats();
    expect(stats.cachedEntries).toBeGreaterThan(0);
  });
});
