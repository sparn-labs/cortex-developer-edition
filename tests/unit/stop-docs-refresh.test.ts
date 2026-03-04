/**
 * Stop Docs Refresh Hook Tests
 *
 * Tests the logic for detecting source file changes and triggering
 * CLAUDE.md regeneration on the Stop event.
 */

import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

// We test the core logic by importing internals indirectly.
// Since the hook is a standalone script, we replicate its key functions here
// and test them in isolation.

const SOURCE_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx']);

function getMaxSourceMtime(srcDir: string): number {
  const { readdirSync, statSync } = require('node:fs');
  let maxMtime = 0;

  try {
    const entries = readdirSync(srcDir, { recursive: true }) as string[];
    for (const entry of entries) {
      const dotIdx = entry.lastIndexOf('.');
      if (dotIdx === -1) continue;
      const ext = entry.slice(dotIdx);
      if (!SOURCE_EXTENSIONS.has(ext)) continue;

      try {
        const stats = statSync(join(srcDir, entry));
        if (stats.mtimeMs > maxMtime) {
          maxMtime = stats.mtimeMs;
        }
      } catch {
        // Skip
      }
    }
  } catch {
    // Not readable
  }

  return maxMtime;
}

function readTimestamp(cortexDir: string): number {
  const { existsSync, readFileSync } = require('node:fs');
  try {
    const tsFile = join(cortexDir, 'docs-gen-timestamp');
    if (!existsSync(tsFile)) return 0;
    const content = readFileSync(tsFile, 'utf-8').trim();
    const ts = Number(content);
    return Number.isFinite(ts) ? ts : 0;
  } catch {
    return 0;
  }
}

function writeTimestamp(cortexDir: string): void {
  const { existsSync, mkdirSync: mkdir, writeFileSync: writeFile } = require('node:fs');
  try {
    if (!existsSync(cortexDir)) {
      mkdir(cortexDir, { recursive: true });
    }
    writeFile(join(cortexDir, 'docs-gen-timestamp'), String(Date.now()), 'utf-8');
  } catch {
    // Best-effort
  }
}

describe('Stop Docs Refresh Hook Logic', () => {
  const tmpDir = join(process.cwd(), '.test-stop-docs-tmp');
  const srcDir = join(tmpDir, 'src');
  const cortexDir = join(tmpDir, '.cortex');

  beforeEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    mkdirSync(srcDir, { recursive: true });
    mkdirSync(cortexDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should return 0 when no source files exist', () => {
    // Empty src/ directory
    const mtime = getMaxSourceMtime(srcDir);
    expect(mtime).toBe(0);
  });

  it('should detect max mtime of source files', async () => {
    writeFileSync(join(srcDir, 'a.ts'), 'export const a = 1;');
    // Small delay to ensure different mtime
    await new Promise((r) => setTimeout(r, 50));
    writeFileSync(join(srcDir, 'b.ts'), 'export const b = 2;');

    const mtime = getMaxSourceMtime(srcDir);
    expect(mtime).toBeGreaterThan(0);
  });

  it('should ignore non-source files', () => {
    writeFileSync(join(srcDir, 'readme.md'), '# Readme');
    writeFileSync(join(srcDir, 'data.json'), '{}');
    writeFileSync(join(srcDir, 'image.png'), 'binary');

    const mtime = getMaxSourceMtime(srcDir);
    expect(mtime).toBe(0);
  });

  it('should detect .tsx, .js, .jsx extensions', () => {
    writeFileSync(join(srcDir, 'comp.tsx'), 'export default () => null;');
    writeFileSync(join(srcDir, 'util.js'), 'module.exports = {};');
    writeFileSync(join(srcDir, 'app.jsx'), 'export default () => null;');

    const mtime = getMaxSourceMtime(srcDir);
    expect(mtime).toBeGreaterThan(0);
  });

  it('should detect files in nested directories', () => {
    const nested = join(srcDir, 'core', 'utils');
    mkdirSync(nested, { recursive: true });
    writeFileSync(join(nested, 'deep.ts'), 'export const deep = true;');

    const mtime = getMaxSourceMtime(srcDir);
    expect(mtime).toBeGreaterThan(0);
  });

  it('should return 0 when timestamp file does not exist', () => {
    const ts = readTimestamp(cortexDir);
    expect(ts).toBe(0);
  });

  it('should read a valid timestamp', () => {
    const now = Date.now();
    writeFileSync(join(cortexDir, 'docs-gen-timestamp'), String(now), 'utf-8');

    const ts = readTimestamp(cortexDir);
    expect(ts).toBe(now);
  });

  it('should return 0 for malformed timestamp', () => {
    writeFileSync(join(cortexDir, 'docs-gen-timestamp'), 'not-a-number', 'utf-8');

    const ts = readTimestamp(cortexDir);
    expect(ts).toBe(0);
  });

  it('should write and read back a timestamp', () => {
    writeTimestamp(cortexDir);

    const ts = readTimestamp(cortexDir);
    expect(ts).toBeGreaterThan(0);
    // Should be within the last second
    expect(Date.now() - ts).toBeLessThan(1000);
  });

  it('should trigger refresh when src file is newer than timestamp', async () => {
    // Write an old timestamp
    writeFileSync(join(cortexDir, 'docs-gen-timestamp'), String(Date.now() - 60000), 'utf-8');

    // Wait a bit, then create a source file
    await new Promise((r) => setTimeout(r, 10));
    writeFileSync(join(srcDir, 'new-file.ts'), 'export const x = 1;');

    const lastGen = readTimestamp(cortexDir);
    const maxMtime = getMaxSourceMtime(srcDir);

    expect(maxMtime).toBeGreaterThan(lastGen);
  });

  it('should not trigger refresh when src files are older than timestamp', () => {
    writeFileSync(join(srcDir, 'old.ts'), 'export const old = true;');

    // Write a future timestamp
    writeFileSync(join(cortexDir, 'docs-gen-timestamp'), String(Date.now() + 60000), 'utf-8');

    const lastGen = readTimestamp(cortexDir);
    const maxMtime = getMaxSourceMtime(srcDir);

    expect(maxMtime).toBeLessThanOrEqual(lastGen);
  });

  it('should trigger when timestamp file is missing (first run)', () => {
    writeFileSync(join(srcDir, 'index.ts'), 'export const main = true;');

    const lastGen = readTimestamp(cortexDir); // Returns 0
    const maxMtime = getMaxSourceMtime(srcDir);

    expect(lastGen).toBe(0);
    expect(maxMtime).toBeGreaterThan(lastGen);
  });

  it('should handle missing src/ directory gracefully', () => {
    const nonExistent = join(tmpDir, 'no-src');
    const mtime = getMaxSourceMtime(nonExistent);
    expect(mtime).toBe(0);
  });

  it('should create .cortex dir if missing when writing timestamp', () => {
    const newCortexDir = join(tmpDir, 'new-project', '.cortex');
    rmSync(join(tmpDir, 'new-project'), { recursive: true, force: true });

    writeTimestamp(newCortexDir);

    const ts = readTimestamp(newCortexDir);
    expect(ts).toBeGreaterThan(0);

    // Cleanup
    rmSync(join(tmpDir, 'new-project'), { recursive: true, force: true });
  });
});
