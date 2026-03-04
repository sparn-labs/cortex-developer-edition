import { mkdir, rm } from 'node:fs/promises';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { optimizeCommand } from '../../src/cli/commands/optimize.js';
import { statsCommand } from '../../src/cli/commands/stats.js';
import type { KVMemory } from '../../src/core/kv-memory.js';
import { createKVMemory } from '../../src/core/kv-memory.js';

describe('stats command integration', () => {
  const testDir = './.test-stats';
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

  it('shows total commands, tokens saved, average reduction', async () => {
    // Run 3 optimizations to create stats
    await optimizeCommand({
      input: 'Test context 1\nWith some data',
      memory,
      dryRun: false,
    });

    await optimizeCommand({
      input: 'Test context 2\nWith more data',
      memory,
      dryRun: false,
    });

    await optimizeCommand({
      input: 'Test context 3\nWith even more data',
      memory,
      dryRun: false,
    });

    // Get stats
    const result = await statsCommand({ memory });

    expect(result.totalCommands).toBe(3);
    expect(result.totalTokensSaved).toBeGreaterThan(0);
    expect(result.averageReduction).toBeGreaterThan(0);
    expect(result.averageReduction).toBeLessThanOrEqual(1);
  });

  it('displays ASCII bar chart with --graph', async () => {
    // Run optimizations
    await optimizeCommand({
      input: 'Context 1',
      memory,
      dryRun: false,
    });

    await optimizeCommand({
      input: 'Context 2',
      memory,
      dryRun: false,
    });

    const result = await statsCommand({ memory, graph: true });

    expect(result.graph).toBeDefined();
    expect(typeof result.graph).toBe('string');
    expect(result.graph?.length).toBeGreaterThan(0);
  });

  it('prompts for confirmation with --reset', async () => {
    // Run an optimization
    await optimizeCommand({
      input: 'Test context',
      memory,
      dryRun: false,
    });

    // Reset without confirmation (for testing)
    const result = await statsCommand({
      memory,
      reset: true,
      confirmReset: true, // Auto-confirm for testing
    });

    expect(result.resetConfirmed).toBe(true);

    // Verify stats are cleared
    const afterReset = await statsCommand({ memory });
    expect(afterReset.totalCommands).toBe(0);
  });

  it('clears optimization_stats table with --reset', async () => {
    // Create stats
    await optimizeCommand({
      input: 'Test 1',
      memory,
      dryRun: false,
    });

    await optimizeCommand({
      input: 'Test 2',
      memory,
      dryRun: false,
    });

    // Verify stats exist
    const before = await statsCommand({ memory });
    expect(before.totalCommands).toBe(2);

    // Reset
    await statsCommand({
      memory,
      reset: true,
      confirmReset: true,
    });

    // Verify cleared
    const after = await statsCommand({ memory });
    expect(after.totalCommands).toBe(0);
    expect(after.totalTokensSaved).toBe(0);
  });

  it('outputs JSON format with --json', async () => {
    // Create stats
    await optimizeCommand({
      input: 'JSON test context',
      memory,
      dryRun: false,
    });

    const result = await statsCommand({ memory, json: true });

    expect(result.json).toBeDefined();
    expect(typeof result.json).toBe('string');

    // Verify valid JSON
    const parsed = JSON.parse(result.json ?? '{}');
    expect(parsed).toHaveProperty('totalCommands');
    expect(parsed).toHaveProperty('totalTokensSaved');
    expect(parsed).toHaveProperty('averageReduction');
  });
});
