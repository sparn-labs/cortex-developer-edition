/**
 * Claude Code Adapter → BudgetPruner Tests
 */

import { existsSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createClaudeCodeAdapter } from '../../src/adapters/claude-code.js';
import { createKVMemory, type KVMemory } from '../../src/core/kv-memory.js';
import { DEFAULT_CONFIG } from '../../src/types/config.js';

describe('Claude Code Adapter with BudgetPruner', () => {
  let memory: KVMemory;
  let tempDir: string;

  beforeEach(async () => {
    tempDir = join(tmpdir(), `cortex-cc-adapter-test-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });
    memory = await createKVMemory(join(tempDir, 'test.db'));
  });

  afterEach(async () => {
    await memory.close();
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('should produce output within token budget', async () => {
    const config = {
      ...DEFAULT_CONFIG,
      realtime: { ...DEFAULT_CONFIG.realtime, tokenBudget: 100 },
    };
    const adapter = createClaudeCodeAdapter(memory, config);

    const context = Array.from(
      { length: 20 },
      (_, i) => `User: Message ${i} with some extra content to use tokens`,
    ).join('\n');

    const result = await adapter.optimize(context, { dryRun: true });
    expect(result.tokensAfter).toBeLessThanOrEqual(config.realtime.tokenBudget * 1.2); // Allow small margin
  });

  it('should preserve BTSP entries', async () => {
    const adapter = createClaudeCodeAdapter(memory, DEFAULT_CONFIG);

    const context = [
      'User: Normal message',
      'Error: fatal error occurred',
      '  at module.js:10:5',
      'User: Another normal message',
    ].join('\n');

    const result = await adapter.optimize(context, { dryRun: true });
    expect(result.optimizedContext).toContain('error');
  });

  it('should apply conversation boost', async () => {
    const adapter = createClaudeCodeAdapter(memory, DEFAULT_CONFIG);

    const context = 'User: Hello world\nAssistant: Hi there!';
    const result = await adapter.optimize(context, { dryRun: true });

    expect(result.entriesKept).toBeGreaterThan(0);
    expect(result.optimizedContext.length).toBeGreaterThan(0);
  });

  it('should report reasonable budget utilization', async () => {
    const adapter = createClaudeCodeAdapter(memory, DEFAULT_CONFIG);

    const context = 'User: Simple message';
    const result = await adapter.optimize(context, { dryRun: true });

    expect(result.reduction).toBeGreaterThanOrEqual(0);
    expect(result.reduction).toBeLessThanOrEqual(1);
  });

  it('should support dry run mode', async () => {
    const adapter = createClaudeCodeAdapter(memory, DEFAULT_CONFIG);

    const context = 'User: Test message';
    await adapter.optimize(context, { dryRun: true });

    // In dry run, nothing should be stored
    const ids = await memory.list();
    expect(ids.length).toBe(0);
  });

  it('should support verbose mode', async () => {
    const adapter = createClaudeCodeAdapter(memory, DEFAULT_CONFIG);

    const context = 'User: Test message\nAssistant: Reply';
    const result = await adapter.optimize(context, { dryRun: true, verbose: true });

    expect(result.details).toBeDefined();
    expect(result.details?.length).toBeGreaterThan(0);
    expect(result.details?.[0]).toHaveProperty('score');
    expect(result.details?.[0]).toHaveProperty('tokens');
  });

  it('should handle empty context', async () => {
    const adapter = createClaudeCodeAdapter(memory, DEFAULT_CONFIG);
    const result = await adapter.optimize('', { dryRun: true });

    expect(result.entriesProcessed).toBe(0);
    expect(result.entriesKept).toBe(0);
  });

  it('should store entries when not in dry run', async () => {
    const adapter = createClaudeCodeAdapter(memory, DEFAULT_CONFIG);

    const context = 'User: Real optimization\nAssistant: Stored';
    await adapter.optimize(context, { dryRun: false });

    const ids = await memory.list();
    expect(ids.length).toBeGreaterThan(0);
  });
});
