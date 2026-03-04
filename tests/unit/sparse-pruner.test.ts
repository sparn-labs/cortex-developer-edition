import { beforeEach, describe, expect, it } from 'vitest';
import { createSparsePruner } from '../../src/core/sparse-pruner.js';
import type { MemoryEntry } from '../../src/types/memory.js';

describe('SparsePruner', () => {
  let pruner: ReturnType<typeof createSparsePruner>;

  beforeEach(() => {
    pruner = createSparsePruner({ threshold: 5 });
  });

  it('keeps top 5% by TF-IDF relevance', () => {
    const entries: MemoryEntry[] = Array.from({ length: 100 }, (_, i) => ({
      id: `entry-${i}`,
      content: i < 5 ? 'critical important unique keyword' : 'common filler text',
      hash: `hash-${i}`,
      timestamp: Date.now(),
      score: 0.5,
      ttl: 3600,
      state: 'ready' as const,
      accessCount: 0,
      tags: [],
      metadata: {},
      isBTSP: false,
    }));

    const result = pruner.prune(entries);

    expect(result.kept.length).toBe(5); // Top 5%
    expect(result.removed.length).toBe(95);
    expect(result.kept.every((e) => e.content.includes('critical'))).toBe(true);
  });

  it('returns PruneResult with kept/removed entries', () => {
    const entries: MemoryEntry[] = [
      {
        id: 'keep-1',
        content: 'unique specialized terminology',
        hash: 'hash1',
        timestamp: Date.now(),
        score: 0.8,
        ttl: 3600,
        state: 'active',
        accessCount: 5,
        tags: [],
        metadata: {},
        isBTSP: false,
      },
      {
        id: 'remove-1',
        content: 'generic text',
        hash: 'hash2',
        timestamp: Date.now(),
        score: 0.2,
        ttl: 3600,
        state: 'silent',
        accessCount: 0,
        tags: [],
        metadata: {},
        isBTSP: false,
      },
    ];

    const result = pruner.prune(entries);

    expect(result).toHaveProperty('kept');
    expect(result).toHaveProperty('removed');
    expect(result).toHaveProperty('originalTokens');
    expect(result).toHaveProperty('prunedTokens');
    expect(Array.isArray(result.kept)).toBe(true);
    expect(Array.isArray(result.removed)).toBe(true);
  });

  it('calculates TF-IDF correctly', () => {
    const entry: MemoryEntry = {
      id: 'test',
      content: 'test word test word common',
      hash: 'hash',
      timestamp: Date.now(),
      score: 0.5,
      ttl: 3600,
      state: 'ready',
      accessCount: 0,
      tags: [],
      metadata: {},
      isBTSP: false,
    };

    const allEntries: MemoryEntry[] = [
      entry,
      {
        ...entry,
        id: 'other',
        content: 'different words here',
        hash: 'hash2',
      },
    ];

    const score = pruner.scoreEntry(entry, allEntries);

    expect(typeof score).toBe('number');
    expect(score).toBeGreaterThan(0);
    expect(score).toBeLessThanOrEqual(1);
  });

  it('handles empty context gracefully', () => {
    const result = pruner.prune([]);

    expect(result.kept).toEqual([]);
    expect(result.removed).toEqual([]);
    expect(result.originalTokens).toBe(0);
    expect(result.prunedTokens).toBe(0);
  });

  it('handles single-line context', () => {
    const entries: MemoryEntry[] = [
      {
        id: 'single',
        content: 'only one entry',
        hash: 'hash',
        timestamp: Date.now(),
        score: 0.5,
        ttl: 3600,
        state: 'ready',
        accessCount: 0,
        tags: [],
        metadata: {},
        isBTSP: false,
      },
    ];

    const result = pruner.prune(entries);

    // With threshold 5%, single entry should be kept (minimum 1)
    expect(result.kept.length).toBeGreaterThanOrEqual(1);
    expect(result.originalTokens).toBeGreaterThan(0);
  });
});
