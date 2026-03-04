/**
 * TF-IDF Pre-computed Index Tests
 */

import { describe, expect, it } from 'vitest';
import type { MemoryEntry } from '../../src/types/memory.js';
import { calculateTFIDF, createTFIDFIndex, scoreTFIDF } from '../../src/utils/tfidf.js';

function makeEntry(content: string, overrides: Partial<MemoryEntry> = {}): MemoryEntry {
  return {
    id: `test-${Math.random().toString(36).slice(2)}`,
    content,
    hash: `hash-${content.slice(0, 10)}`,
    timestamp: Date.now(),
    score: 0.5,
    ttl: 86400,
    state: 'active',
    accessCount: 0,
    tags: [],
    metadata: {},
    isBTSP: false,
    ...overrides,
  };
}

describe('createTFIDFIndex', () => {
  it('should build correct document frequencies', () => {
    const entries = [makeEntry('hello world'), makeEntry('hello there'), makeEntry('world peace')];
    const index = createTFIDFIndex(entries);

    expect(index.totalDocuments).toBe(3);
    expect(index.documentFrequency.get('hello')).toBe(2);
    expect(index.documentFrequency.get('world')).toBe(2);
    expect(index.documentFrequency.get('there')).toBe(1);
    expect(index.documentFrequency.get('peace')).toBe(1);
  });

  it('should handle empty entries array', () => {
    const index = createTFIDFIndex([]);
    expect(index.totalDocuments).toBe(0);
    expect(index.documentFrequency.size).toBe(0);
  });

  it('should handle single document', () => {
    const entries = [makeEntry('hello world hello')];
    const index = createTFIDFIndex(entries);

    expect(index.totalDocuments).toBe(1);
    // 'hello' appears in 1 doc (even though repeated)
    expect(index.documentFrequency.get('hello')).toBe(1);
    expect(index.documentFrequency.get('world')).toBe(1);
  });

  it('should count terms case-insensitively', () => {
    const entries = [makeEntry('Hello World'), makeEntry('HELLO world')];
    const index = createTFIDFIndex(entries);

    expect(index.documentFrequency.get('hello')).toBe(2);
    expect(index.documentFrequency.get('world')).toBe(2);
  });
});

describe('scoreTFIDF', () => {
  it('should match calculateTFIDF output within float tolerance', () => {
    const entries = [
      makeEntry('error error critical failure'),
      makeEntry('all tests pass successfully'),
      makeEntry('deployment in production error'),
    ];

    const index = createTFIDFIndex(entries);

    for (const entry of entries) {
      const oldScore = calculateTFIDF(entry, entries);
      const newScore = scoreTFIDF(entry, index);
      expect(newScore).toBeCloseTo(oldScore, 10);
    }
  });

  it('should return 0 for empty content', () => {
    const entries = [makeEntry(''), makeEntry('hello world')];
    const index = createTFIDFIndex(entries);
    expect(scoreTFIDF(entries[0] as MemoryEntry, index)).toBe(0);
  });

  it('should return 0 for single document corpus (all IDF = 0)', () => {
    const entries = [makeEntry('hello world')];
    const index = createTFIDFIndex(entries);
    expect(scoreTFIDF(entries[0] as MemoryEntry, index)).toBe(0);
  });

  it('should score higher for entries with distinctive terms', () => {
    const entries = [
      makeEntry('unique_term_xyz special_word_abc'),
      makeEntry('common common common common'),
      makeEntry('common common'),
    ];
    const index = createTFIDFIndex(entries);

    const scoreWithUnique = scoreTFIDF(entries[0] as MemoryEntry, index);
    const scoreCommon = scoreTFIDF(entries[1] as MemoryEntry, index);

    // Entry with terms unique to it scores higher than entry with only common terms
    expect(scoreWithUnique).toBeGreaterThan(scoreCommon);
  });

  it('should perform well with 500 entries', () => {
    const entries = Array.from({ length: 500 }, (_, i) =>
      makeEntry(`entry ${i} with some content about topic ${i % 10} and category ${i % 5}`),
    );

    const start = performance.now();
    const index = createTFIDFIndex(entries);
    for (const entry of entries) {
      scoreTFIDF(entry, index);
    }
    const elapsed = performance.now() - start;

    expect(elapsed).toBeLessThan(500); // Should complete well under 500ms
  });
});
