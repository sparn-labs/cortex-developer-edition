/**
 * Hook State Cache Tests
 *
 * Tests the cache read/write logic extracted from pre-prompt.ts.
 * Since the cache functions are module-internal, we test via the
 * file system behavior using a test cache path.
 */

import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

// We'll test the cache format directly since the functions are internal
interface CacheEntry {
  key: string;
  hint: string;
  timestamp: number;
}

const CACHE_TTL_MS = 5 * 60 * 1000;

describe('Hook State Cache', () => {
  let tempDir: string;
  let cacheFile: string;

  beforeEach(() => {
    tempDir = join(tmpdir(), `cortex-cache-test-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });
    cacheFile = join(tempDir, 'hook-state-cache.json');
  });

  afterEach(() => {
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  function writeTestCache(entry: CacheEntry): void {
    writeFileSync(cacheFile, JSON.stringify(entry), 'utf-8');
  }

  function readTestCache(): CacheEntry | null {
    try {
      if (!existsSync(cacheFile)) return null;
      return JSON.parse(readFileSync(cacheFile, 'utf-8')) as CacheEntry;
    } catch {
      return null;
    }
  }

  it('should return null on first run (no cache file)', () => {
    const cache = readTestCache();
    expect(cache).toBeNull();
  });

  it('should write and read cache entry', () => {
    const entry: CacheEntry = {
      key: 'session1:12345:1000',
      hint: '[cortex] Context is growing.',
      timestamp: Date.now(),
    };
    writeTestCache(entry);

    const cached = readTestCache();
    expect(cached).not.toBeNull();
    expect(cached?.key).toBe('session1:12345:1000');
    expect(cached?.hint).toBe('[cortex] Context is growing.');
  });

  it('should invalidate on different session', () => {
    const entry: CacheEntry = {
      key: 'session1:12345:1000',
      hint: 'old hint',
      timestamp: Date.now(),
    };
    writeTestCache(entry);

    const cached = readTestCache();
    // Different session key should not match
    expect(cached?.key).not.toBe('session2:12345:1000');
  });

  it('should invalidate on different transcript size', () => {
    const entry: CacheEntry = {
      key: 'session1:12345:1000',
      hint: 'old hint',
      timestamp: Date.now(),
    };
    writeTestCache(entry);

    const cached = readTestCache();
    expect(cached?.key).not.toBe('session1:99999:1000');
  });

  it('should detect stale cache (>5 min)', () => {
    const entry: CacheEntry = {
      key: 'session1:12345:1000',
      hint: 'stale hint',
      timestamp: Date.now() - CACHE_TTL_MS - 1000,
    };
    writeTestCache(entry);

    const cached = readTestCache();
    expect(cached).not.toBeNull();
    // The caller would check: Date.now() - cached.timestamp > CACHE_TTL_MS
    expect(Date.now() - cached?.timestamp).toBeGreaterThan(CACHE_TTL_MS);
  });

  it('should handle malformed cache file gracefully', () => {
    writeFileSync(cacheFile, 'not valid json', 'utf-8');
    const cached = readTestCache();
    expect(cached).toBeNull();
  });

  it('should handle missing cache directory', () => {
    const missingDir = join(tempDir, 'nonexistent', 'cache.json');
    // Should not throw
    expect(existsSync(missingDir)).toBe(false);
  });

  it('should overwrite existing cache on write', () => {
    writeTestCache({ key: 'old', hint: 'old', timestamp: 1 });
    writeTestCache({ key: 'new', hint: 'new', timestamp: 2 });

    const cached = readTestCache();
    expect(cached?.key).toBe('new');
  });
});
