import { beforeEach, describe, expect, it } from 'vitest';
import { createSleepCompressor } from '../../src/core/sleep-compressor.js';
import type { MemoryEntry } from '../../src/types/memory.js';

describe('SleepCompressor', () => {
  let compressor: ReturnType<typeof createSleepCompressor>;

  beforeEach(() => {
    compressor = createSleepCompressor();
  });

  it('removes fully decayed entries (decay ≥0.95)', () => {
    const now = Date.now();
    const entries: MemoryEntry[] = [
      {
        id: 'fresh',
        content: 'Fresh entry',
        hash: 'hash1',
        timestamp: now,
        score: 1.0,
        ttl: 24 * 3600,
        state: 'active',
        accessCount: 5,
        tags: [],
        metadata: {},
        isBTSP: false,
      },
      {
        id: 'old',
        content: 'Very old entry',
        hash: 'hash2',
        timestamp: now - 200 * 3600 * 1000, // 200 hours ago
        score: 0.05,
        ttl: 24 * 3600,
        state: 'silent',
        accessCount: 0,
        tags: [],
        metadata: {},
        isBTSP: false,
      },
    ];

    const result = compressor.consolidate(entries);

    // Old entry should be removed (high decay)
    expect(result.kept.length).toBe(1);
    expect(result.removed.length).toBe(1);
    expect(result.kept[0].id).toBe('fresh');
    expect(result.removed[0].id).toBe('old');
  });

  it('detects exact hash matches', () => {
    const entries: MemoryEntry[] = [
      {
        id: 'entry1',
        content: 'Same content',
        hash: 'identical-hash',
        timestamp: Date.now(),
        score: 0.8,
        ttl: 3600,
        state: 'active',
        accessCount: 3,
        tags: [],
        metadata: {},
        isBTSP: false,
      },
      {
        id: 'entry2',
        content: 'Same content',
        hash: 'identical-hash',
        timestamp: Date.now(),
        score: 0.6,
        ttl: 3600,
        state: 'ready',
        accessCount: 1,
        tags: [],
        metadata: {},
        isBTSP: false,
      },
    ];

    const duplicates = compressor.findDuplicates(entries);

    expect(duplicates.length).toBe(1);
    expect(duplicates[0].entries.length).toBe(2);
    expect(duplicates[0].entries[0].hash).toBe('identical-hash');
    expect(duplicates[0].entries[1].hash).toBe('identical-hash');
  });

  it('detects near-duplicates (cosine similarity ≥0.85)', () => {
    const entries: MemoryEntry[] = [
      {
        id: 'entry1',
        content: 'The quick brown fox jumps over the lazy dog',
        hash: 'hash1',
        timestamp: Date.now(),
        score: 0.8,
        ttl: 3600,
        state: 'active',
        accessCount: 2,
        tags: [],
        metadata: {},
        isBTSP: false,
      },
      {
        id: 'entry2',
        content: 'The quick brown fox jumps over lazy dog', // Very similar
        hash: 'hash2',
        timestamp: Date.now(),
        score: 0.7,
        ttl: 3600,
        state: 'ready',
        accessCount: 1,
        tags: [],
        metadata: {},
        isBTSP: false,
      },
      {
        id: 'entry3',
        content: 'Completely different text about something else',
        hash: 'hash3',
        timestamp: Date.now(),
        score: 0.6,
        ttl: 3600,
        state: 'ready',
        accessCount: 1,
        tags: [],
        metadata: {},
        isBTSP: false,
      },
    ];

    const duplicates = compressor.findDuplicates(entries);

    // Should find entry1 and entry2 as near-duplicates
    expect(duplicates.length).toBeGreaterThanOrEqual(1);
    const nearDupGroup = duplicates.find((g) => g.entries.some((e) => e.id === 'entry1'));
    expect(nearDupGroup).toBeDefined();
    expect(nearDupGroup?.entries.length).toBe(2);
  });

  it('keeps highest score entry when merging duplicates', () => {
    const entries: MemoryEntry[] = [
      {
        id: 'low-score',
        content: 'Same',
        hash: 'same-hash',
        timestamp: Date.now(),
        score: 0.3,
        ttl: 3600,
        state: 'silent',
        accessCount: 1,
        tags: [],
        metadata: {},
        isBTSP: false,
      },
      {
        id: 'high-score',
        content: 'Same',
        hash: 'same-hash',
        timestamp: Date.now(),
        score: 0.9,
        ttl: 3600,
        state: 'active',
        accessCount: 2,
        tags: [],
        metadata: {},
        isBTSP: false,
      },
    ];

    const duplicateGroups = compressor.findDuplicates(entries);
    const merged = compressor.mergeDuplicates(duplicateGroups);

    expect(merged.length).toBe(1);
    expect(merged[0].id).toBe('high-score');
    expect(merged[0].score).toBe(0.9);
  });

  it('sums accessCount when merging duplicates', () => {
    const entries: MemoryEntry[] = [
      {
        id: 'entry1',
        content: 'Same',
        hash: 'same-hash',
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
        id: 'entry2',
        content: 'Same',
        hash: 'same-hash',
        timestamp: Date.now(),
        score: 0.6,
        ttl: 3600,
        state: 'ready',
        accessCount: 3,
        tags: [],
        metadata: {},
        isBTSP: false,
      },
    ];

    const duplicateGroups = compressor.findDuplicates(entries);
    const merged = compressor.mergeDuplicates(duplicateGroups);

    expect(merged.length).toBe(1);
    expect(merged[0].accessCount).toBe(8); // 5 + 3
  });
});
