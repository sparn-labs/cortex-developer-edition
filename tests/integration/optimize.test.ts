import { mkdir, rm, writeFile } from 'node:fs/promises';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { optimizeCommand } from '../../src/cli/commands/optimize.js';
import type { KVMemory } from '../../src/core/kv-memory.js';
import { createKVMemory } from '../../src/core/kv-memory.js';

describe('optimize command integration', () => {
  const testDir = './.test-optimize';
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

  it('reads from stdin', async () => {
    const input = 'Test context to optimize\nMultiple lines\nSome important content';

    const result = await optimizeCommand({
      input,
      memory,
      dryRun: true,
    });

    expect(result.tokensBefore).toBeGreaterThan(0);
    expect(result.tokensAfter).toBeGreaterThanOrEqual(0);
    expect(result.entriesProcessed).toBeGreaterThan(0);
  });

  it('reads from file', async () => {
    const inputPath = `${testDir}/input.txt`;
    const content = 'File content to optimize\nWith multiple lines\nAnd some data';
    await writeFile(inputPath, content, 'utf-8');

    const result = await optimizeCommand({
      inputFile: inputPath,
      memory,
      dryRun: true,
    });

    expect(result.tokensBefore).toBeGreaterThan(0);
    expect(result.entriesProcessed).toBeGreaterThan(0);
  });

  it('writes to file', async () => {
    const outputPath = `${testDir}/output.txt`;
    const input = 'Content to optimize and write to file';

    const result = await optimizeCommand({
      input,
      outputFile: outputPath,
      memory,
      dryRun: true,
    });

    expect(result.output).toBeDefined();
    expect(result.outputFile).toBe(outputPath);
  });

  it("doesn't modify memory store with --dry-run", async () => {
    const input = 'Test content for dry run';

    const entriesBefore = await memory.list();

    await optimizeCommand({
      input,
      memory,
      dryRun: true,
    });

    const entriesAfter = await memory.list();

    expect(entriesAfter).toEqual(entriesBefore);
  });

  it('shows per-entry scores with --verbose', async () => {
    const input = 'Verbose mode test content\nWith multiple entries';

    const result = await optimizeCommand({
      input,
      memory,
      verbose: true,
      dryRun: true,
    });

    expect(result.details).toBeDefined();
    expect(Array.isArray(result.details)).toBe(true);
    if (result.details && result.details.length > 0) {
      expect(result.details[0]).toHaveProperty('id');
      expect(result.details[0]).toHaveProperty('score');
      expect(result.details[0]).toHaveProperty('state');
    }
  });

  it('completes 100K tokens in <500ms', async () => {
    // Generate ~100K tokens (approximately 400K characters)
    const largeInput = 'x'.repeat(400000);

    const startTime = Date.now();

    await optimizeCommand({
      input: largeInput,
      memory,
      dryRun: true,
    });

    const duration = Date.now() - startTime;

    expect(duration).toBeLessThan(500); // Performance requirement
  });
});
