import { mkdir, rm } from 'node:fs/promises';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { consolidateCommand } from '../../src/cli/commands/consolidate.js';
import type { KVMemory } from '../../src/core/kv-memory.js';
import { createKVMemory } from '../../src/core/kv-memory.js';
import type { MemoryEntry } from '../../src/types/memory.js';

describe('consolidate command integration', () => {
  const testDir = './.test-consolidate';
  const dbPath = `${testDir}/memory.db`;
  let memory: KVMemory;

  beforeEach(async () => {
    await mkdir(testDir, { recursive: true });
    memory = await createKVMemory(dbPath);
  });

  afterEach(async () => {
    await memory.close();
    await rm(testDir, { recursive: true, force: true });
  });

  it('shows entries before/after and compression ratio', async () => {
    // Add some test entries
    const now = Date.now();
    const entries: MemoryEntry[] = [
      {
        id: 'entry1',
        content: 'Content 1 unique first',
        hash: 'hash1-unique',
        timestamp: now,
        score: 0.9,
        ttl: 3600,
        state: 'active',
        accessCount: 5,
        tags: [],
        metadata: {},
        isBTSP: false,
      },
      {
        id: 'entry2',
        content: 'Content 1 unique second', // Similar but not identical
        hash: 'hash2-unique',
        timestamp: now,
        score: 0.7,
        ttl: 3600,
        state: 'ready',
        accessCount: 2,
        tags: [],
        metadata: {},
        isBTSP: false,
      },
      {
        id: 'entry3',
        content: 'Old content that will decay',
        hash: 'hash3-unique',
        timestamp: now - 200 * 3600 * 1000, // Very old
        score: 0.05,
        ttl: 3600,
        state: 'silent',
        accessCount: 0,
        tags: [],
        metadata: {},
        isBTSP: false,
      },
    ];

    for (const entry of entries) {
      await memory.put(entry);
    }

    // Verify entries were stored
    const storedCount = (await memory.list()).length;
    expect(storedCount).toBe(3);

    // Run consolidation
    const result = await consolidateCommand({ memory });

    expect(result.entriesBefore).toBeGreaterThanOrEqual(2); // Should have at least 2
    expect(result.entriesAfter).toBeLessThan(result.entriesBefore); // Should consolidate
    expect(result.decayedRemoved + result.duplicatesRemoved).toBeGreaterThan(0); // Should remove something
    expect(result.compressionRatio).toBeGreaterThan(0);
    expect(result.compressionRatio).toBeLessThanOrEqual(1);
    expect(result.durationMs).toBeGreaterThanOrEqual(0); // Can be 0 if very fast
  });

  it('runs database VACUUM', async () => {
    // Add and remove entries to create fragmentation
    for (let i = 0; i < 10; i++) {
      await memory.put({
        id: `temp-${i}`,
        content: `Temporary ${i}`,
        hash: `hash-${i}`,
        timestamp: Date.now(),
        score: 0.5,
        ttl: 3600,
        state: 'ready',
        accessCount: 0,
        tags: [],
        metadata: {},
        isBTSP: false,
      });
    }

    // Delete half of them
    for (let i = 0; i < 5; i++) {
      await memory.delete(`temp-${i}`);
    }

    // Run consolidation
    const result = await consolidateCommand({ memory });

    // VACUUM should have run (indicated by completion)
    expect(result.vacuumCompleted).toBe(true);
  });
});
