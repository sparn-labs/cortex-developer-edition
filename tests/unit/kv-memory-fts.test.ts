/**
 * KV Memory FTS5 Tests
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

describe('KVMemory FTS5', () => {
  let memory: KVMemory;
  let dbPath: string;
  let tempDir: string;

  beforeEach(async () => {
    tempDir = join(tmpdir(), `cortex-fts-test-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });
    dbPath = join(tempDir, 'test.db');
    memory = await createKVMemory(dbPath);
  });

  afterEach(async () => {
    await memory.close();
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('should find inserted entries via FTS search', async () => {
    await memory.put(makeEntry('e1', 'The quick brown fox jumps over the lazy dog'));
    await memory.put(makeEntry('e2', 'TypeScript is a typed superset of JavaScript'));

    const results = await memory.searchFTS('fox');
    expect(results.length).toBe(1);
    expect(results[0]?.entry.id).toBe('e1');
  });

  it('should rank results by relevance', async () => {
    await memory.put(makeEntry('e1', 'error error error critical failure'));
    await memory.put(makeEntry('e2', 'single error occurred'));
    await memory.put(makeEntry('e3', 'everything is fine'));

    const results = await memory.searchFTS('error');
    expect(results.length).toBe(2);
    // FTS5 rank: lower (more negative) = better match, so first result is most relevant
    expect(results[0]?.rank).toBeLessThanOrEqual(results[1]?.rank);
  });

  it('should respect limit parameter', async () => {
    await memory.put(makeEntry('e1', 'hello world one'));
    await memory.put(makeEntry('e2', 'hello world two'));
    await memory.put(makeEntry('e3', 'hello world three'));

    const results = await memory.searchFTS('hello', 2);
    expect(results.length).toBe(2);
  });

  it('should return empty for empty query', async () => {
    await memory.put(makeEntry('e1', 'hello world'));
    const results = await memory.searchFTS('');
    expect(results.length).toBe(0);
  });

  it('should handle special characters safely', async () => {
    await memory.put(makeEntry('e1', 'function foo() { return bar; }'));
    // These special chars should be stripped, not crash
    const results = await memory.searchFTS('foo() { }');
    expect(results.length).toBeGreaterThanOrEqual(0); // Just shouldn't throw
  });

  it('should sync on delete', async () => {
    await memory.put(makeEntry('e1', 'special unique content'));
    let results = await memory.searchFTS('special');
    expect(results.length).toBe(1);

    await memory.delete('e1');
    results = await memory.searchFTS('special');
    expect(results.length).toBe(0);
  });

  it('should sync on update', async () => {
    await memory.put(makeEntry('e1', 'original content here'));
    let results = await memory.searchFTS('original');
    expect(results.length).toBe(1);

    // Update by putting same ID with different content
    await memory.put(makeEntry('e1', 'replacement text now'));
    results = await memory.searchFTS('original');
    expect(results.length).toBe(0);
    results = await memory.searchFTS('replacement');
    expect(results.length).toBe(1);
  });

  it('should backfill on reopen', async () => {
    await memory.put(makeEntry('e1', 'persistent data across sessions'));
    await memory.close();

    // Reopen — backfill should make data searchable
    memory = await createKVMemory(dbPath);
    const results = await memory.searchFTS('persistent');
    expect(results.length).toBe(1);
  });

  it('should return full entry data in results', async () => {
    await memory.put(
      makeEntry('e1', 'searchable entry', {
        score: 0.9,
        state: 'active',
        tags: ['test'],
        isBTSP: true,
      }),
    );

    const results = await memory.searchFTS('searchable');
    expect(results.length).toBe(1);
    expect(results[0]?.entry.score).toBe(0.9);
    expect(results[0]?.entry.state).toBe('active');
    expect(results[0]?.entry.tags).toContain('test');
    expect(results[0]?.entry.isBTSP).toBe(true);
  });
});
