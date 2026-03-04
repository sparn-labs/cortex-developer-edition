/**
 * Compact Decay-Based Removal Tests
 */

import { existsSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createKVMemory, type KVMemory } from '../../src/core/kv-memory.js';
import type { MemoryEntry } from '../../src/types/memory.js';

function makeEntry(id: string, content: string, overrides: Partial<MemoryEntry> = {}): MemoryEntry {
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
    ...overrides,
  };
}

describe('Compact with Decay-Based Removal', () => {
  let memory: KVMemory;
  let tempDir: string;

  beforeEach(async () => {
    tempDir = join(tmpdir(), `cortex-compact-test-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });
    memory = await createKVMemory(join(tempDir, 'test.db'));
  });

  afterEach(async () => {
    await memory.close();
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('should remove decayed entries', async () => {
    // TTL = 100 seconds, entry is very old -> decay >> 0.95
    const oldEntry = makeEntry('old', 'old content', {
      timestamp: Date.now() - 10 * 86400 * 1000, // 10 days ago
      ttl: 100, // 100 seconds TTL
    });
    await memory.put(oldEntry);

    const removed = await memory.compact();
    expect(removed).toBe(1);
  });

  it('should keep fresh entries', async () => {
    const freshEntry = makeEntry('fresh', 'fresh content', {
      timestamp: Date.now(),
      ttl: 86400,
    });
    await memory.put(freshEntry);

    const removed = await memory.compact();
    expect(removed).toBe(0);

    const entry = await memory.get('fresh');
    expect(entry).not.toBeNull();
  });

  it('should preserve BTSP entries regardless of decay', async () => {
    const btspEntry = makeEntry('btsp', 'critical error info', {
      timestamp: Date.now() - 10 * 86400 * 1000,
      ttl: 100,
      isBTSP: true,
    });
    await memory.put(btspEntry);

    const removed = await memory.compact();
    expect(removed).toBe(0);

    const entry = await memory.get('btsp');
    expect(entry).not.toBeNull();
  });

  it('should still remove TTL-expired entries', async () => {
    // Entry with timestamp + ttl*1000 < now
    const expiredEntry = makeEntry('expired', 'expired content', {
      timestamp: Date.now() - 200 * 1000,
      ttl: 100,
    });
    await memory.put(expiredEntry);

    const removed = await memory.compact();
    expect(removed).toBe(1);
  });

  it('should handle empty database', async () => {
    const removed = await memory.compact();
    expect(removed).toBe(0);
  });

  it('should handle mixed entries correctly', async () => {
    // Fresh entry (should keep)
    await memory.put(
      makeEntry('fresh', 'keep me', {
        timestamp: Date.now(),
        ttl: 86400,
      }),
    );

    // Old non-BTSP entry (should remove - high decay)
    await memory.put(
      makeEntry('old', 'remove me', {
        timestamp: Date.now() - 10 * 86400 * 1000,
        ttl: 100,
      }),
    );

    // Old BTSP entry (should keep despite high decay)
    await memory.put(
      makeEntry('btsp', 'critical keep', {
        timestamp: Date.now() - 10 * 86400 * 1000,
        ttl: 100,
        isBTSP: true,
      }),
    );

    const removed = await memory.compact();
    expect(removed).toBe(1); // Only old non-BTSP removed

    expect(await memory.get('fresh')).not.toBeNull();
    expect(await memory.get('old')).toBeNull();
    expect(await memory.get('btsp')).not.toBeNull();
  });

  it('should clean orphaned value entries', async () => {
    await memory.put(makeEntry('e1', 'content'));
    const removed = await memory.compact();
    // No orphans since we just inserted
    expect(removed).toBe(0);
  });
});
