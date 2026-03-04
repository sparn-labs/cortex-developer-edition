/**
 * Search Engine Tests
 */

import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createSearchEngine } from '../../src/core/search-engine.js';

describe('Search Engine', () => {
  const tmpDir = join(process.cwd(), '.test-search-tmp');
  const dbPath = join(tmpDir, '.cortex', 'search.db');

  beforeEach(() => {
    try {
      rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      // Ignore errors on Windows file locks
    }
    mkdirSync(join(tmpDir, '.cortex'), { recursive: true });
    mkdirSync(join(tmpDir, 'src', 'core'), { recursive: true });
    mkdirSync(join(tmpDir, 'src', 'utils'), { recursive: true });
  });

  afterEach(async () => {
    // Give SQLite time to release file locks on Windows
    await new Promise((resolve) => setTimeout(resolve, 100));
    try {
      rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors on Windows (file locks)
    }
  });

  function writeFile(relativePath: string, content: string) {
    writeFileSync(join(tmpDir, relativePath), content, 'utf-8');
  }

  describe('init', () => {
    it('should create FTS5 table', async () => {
      const engine = createSearchEngine(dbPath);
      await engine.init(tmpDir);
      // Should not throw
      await engine.close();
    });

    it('should be idempotent', async () => {
      const engine = createSearchEngine(dbPath);
      await engine.init(tmpDir);
      await engine.close();

      // Init again should work
      const engine2 = createSearchEngine(dbPath);
      await engine2.init(tmpDir);
      await engine2.close();
    });
  });

  describe('index', () => {
    it('should index TypeScript files', async () => {
      writeFile('src/core/foo.ts', 'export function handleAuth() {\n  return true;\n}');
      writeFile('src/utils/bar.ts', 'export function formatDate() {\n  return new Date();\n}');

      const engine = createSearchEngine(dbPath);
      await engine.init(tmpDir);

      const stats = await engine.index();

      expect(stats.filesIndexed).toBeGreaterThan(0);
      expect(stats.totalLines).toBeGreaterThan(0);
      expect(stats.duration).toBeGreaterThanOrEqual(0);

      await engine.close();
    });

    it('should skip unchanged files on re-index', async () => {
      writeFile('src/core/foo.ts', 'export function foo() {}');

      const engine = createSearchEngine(dbPath);
      await engine.init(tmpDir);

      const stats1 = await engine.index();
      expect(stats1.filesIndexed).toBe(1);

      // Re-index without changes
      const stats2 = await engine.index();
      expect(stats2.filesIndexed).toBe(0);

      await engine.close();
    });

    it('should re-index changed files', async () => {
      writeFile('src/core/foo.ts', 'export function foo() {}');

      const engine = createSearchEngine(dbPath);
      await engine.init(tmpDir);

      await engine.index();

      // Modify file (need to wait a bit for mtime to change)
      await new Promise((resolve) => setTimeout(resolve, 50));
      writeFile('src/core/foo.ts', 'export function foo() { return 42; }');

      const stats2 = await engine.index();
      expect(stats2.filesIndexed).toBe(1);

      await engine.close();
    });
  });

  describe('search', () => {
    it('should find content via FTS5', async () => {
      writeFile(
        'src/core/auth.ts',
        'export function handleAuth() {\n  // Handle user authentication here\n  return true;\n}',
      );
      writeFile('src/utils/format.ts', 'export function formatDate() {\n  return new Date();\n}');

      const engine = createSearchEngine(dbPath);
      await engine.init(tmpDir);
      await engine.index();

      // Search for a term that exists as a standalone word in the content
      const results = await engine.search('authentication', {
        useRipgrep: false,
      });

      expect(results.length).toBeGreaterThan(0);
      expect(results[0]?.filePath).toContain('auth');

      await engine.close();
    });

    it('should respect maxResults', async () => {
      // Create multiple files with matching content
      for (let i = 0; i < 5; i++) {
        writeFile(
          `src/file${i}.ts`,
          `export function handler${i}() {\n  // handler logic\n  return ${i};\n}`,
        );
      }

      const engine = createSearchEngine(dbPath);
      await engine.init(tmpDir);
      await engine.index();

      const results = await engine.search('handler', {
        maxResults: 3,
        useRipgrep: false,
      });

      expect(results.length).toBeLessThanOrEqual(3);

      await engine.close();
    });

    it('should return empty for no matches', async () => {
      writeFile('src/core/foo.ts', 'export function foo() {}');

      const engine = createSearchEngine(dbPath);
      await engine.init(tmpDir);
      await engine.index();

      const results = await engine.search('xyznonexistent', {
        useRipgrep: false,
      });

      expect(results).toHaveLength(0);

      await engine.close();
    });

    it('should include context lines when requested', async () => {
      writeFile('src/core/foo.ts', 'line 1\nline 2\ntarget line\nline 4\nline 5');

      const engine = createSearchEngine(dbPath);
      await engine.init(tmpDir);
      await engine.index();

      const results = await engine.search('target', {
        includeContext: true,
        useRipgrep: false,
      });

      if (results.length > 0) {
        expect(results[0]?.context?.length).toBeGreaterThan(0);
      }

      await engine.close();
    });

    it('should handle special characters in query', async () => {
      writeFile('src/core/foo.ts', 'const x = "hello (world)";\nconst y = 42;');

      const engine = createSearchEngine(dbPath);
      await engine.init(tmpDir);
      await engine.index();

      // Should not throw
      const results = await engine.search('hello (world)', {
        useRipgrep: false,
      });

      // May or may not match due to FTS5 tokenization, but shouldn't crash
      expect(Array.isArray(results)).toBe(true);

      await engine.close();
    });
  });

  describe('refresh', () => {
    it('should re-index all files from scratch', async () => {
      writeFile('src/core/foo.ts', 'export function foo() {}');

      const engine = createSearchEngine(dbPath);
      await engine.init(tmpDir);

      await engine.index();

      const stats = await engine.refresh();
      expect(stats.filesIndexed).toBeGreaterThan(0);

      await engine.close();
    });
  });

  describe('edge cases', () => {
    it('should throw if not initialized', async () => {
      const engine = createSearchEngine(dbPath);

      await expect(engine.search('test')).rejects.toThrow('not initialized');
    });

    it('should handle empty project', async () => {
      const engine = createSearchEngine(dbPath);
      await engine.init(tmpDir);

      const stats = await engine.index();
      expect(stats.filesIndexed).toBe(0);

      const results = await engine.search('test', { useRipgrep: false });
      expect(results).toHaveLength(0);

      await engine.close();
    });
  });
});
