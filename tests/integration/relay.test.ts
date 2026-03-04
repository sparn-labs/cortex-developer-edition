import { mkdir, rm } from 'node:fs/promises';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { relayCommand } from '../../src/cli/commands/relay.js';
import type { KVMemory } from '../../src/core/kv-memory.js';
import { createKVMemory } from '../../src/core/kv-memory.js';

describe('relay command integration', () => {
  const testDir = './.test-relay';
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

  it('executes command and optimizes output', async () => {
    const result = await relayCommand({
      command: 'echo',
      args: ['test message'],
      memory,
    });

    expect(result.exitCode).toBe(0);
    expect(result.originalOutput).toContain('test message');
    expect(result.optimizedOutput).toBeDefined();
    expect(result.tokensBefore).toBeGreaterThan(0);
    expect(result.tokensAfter).toBeGreaterThanOrEqual(0);
  });

  it('preserves exit code of proxied command', async () => {
    // Test successful command (exit 0)
    const successResult = await relayCommand({
      command: 'node',
      args: ['-e', 'process.exit(0)'],
      memory,
    });
    expect(successResult.exitCode).toBe(0);

    // Test failing command (exit 1)
    const failResult = await relayCommand({
      command: 'node',
      args: ['-e', 'process.exit(1)'],
      memory,
    });
    expect(failResult.exitCode).toBe(1);

    // Test custom exit code
    const customResult = await relayCommand({
      command: 'node',
      args: ['-e', 'process.exit(42)'],
      memory,
    });
    expect(customResult.exitCode).toBe(42);
  });

  it('shows token savings summary by default', async () => {
    const result = await relayCommand({
      command: 'echo',
      args: ['This is a longer message with multiple words to optimize'],
      memory,
    });

    expect(result.summary).toBeDefined();
    expect(result.summary).toContain('→');
    expect(result.summary).toContain('%');
  });

  it('suppresses savings summary with --silent', async () => {
    const result = await relayCommand({
      command: 'echo',
      args: ['test'],
      memory,
      silent: true,
    });

    expect(result.summary).toBeUndefined();
  });

  it('works with common CLI commands', async () => {
    // Test with echo (simple command)
    const echoResult = await relayCommand({
      command: 'echo',
      args: ['hello world'],
      memory,
    });
    expect(echoResult.exitCode).toBe(0);
    expect(echoResult.originalOutput).toContain('hello world');

    // Test with node (interpreter command)
    const nodeResult = await relayCommand({
      command: 'node',
      args: ['-e', 'console.log("test output")'],
      memory,
    });
    expect(nodeResult.exitCode).toBe(0);
    expect(nodeResult.originalOutput).toContain('test output');

    // Test with ls/dir (file listing command) - platform specific
    const listCommand = process.platform === 'win32' ? 'cmd' : 'ls';
    const listArgs = process.platform === 'win32' ? ['/c', 'dir'] : ['-la'];

    const listResult = await relayCommand({
      command: listCommand,
      args: listArgs,
      memory,
    });
    expect(listResult.exitCode).toBe(0);
    expect(listResult.originalOutput.length).toBeGreaterThan(0);
  });
});
