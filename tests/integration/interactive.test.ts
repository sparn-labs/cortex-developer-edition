/**
 * Interactive Command Integration Tests
 */

import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { dump as stringifyYAML } from 'js-yaml';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { interactiveCommand } from '../../src/cli/commands/interactive.js';
import { createKVMemory } from '../../src/core/kv-memory.js';
import { DEFAULT_CONFIG } from '../../src/types/config.js';

// Mock @inquirer/prompts
vi.mock('@inquirer/prompts', () => ({
  input: vi.fn(),
  select: vi.fn(),
  confirm: vi.fn(),
  number: vi.fn(),
}));

describe('Interactive Command', () => {
  let testDir: string;
  let dbPath: string;
  let configPath: string;

  beforeEach(() => {
    // Create temp directory
    testDir = join(tmpdir(), `cortex-test-${Date.now()}`);
    mkdirSync(testDir, { recursive: true });

    dbPath = join(testDir, 'memory.db');
    configPath = join(testDir, 'config.yaml');

    // Create default config
    const configYAML = stringifyYAML(DEFAULT_CONFIG);
    writeFileSync(configPath, configYAML, 'utf-8');
  });

  afterEach(async () => {
    // Give Windows time to release file handles
    await new Promise((resolve) => setTimeout(resolve, 100));

    // Clean up
    if (existsSync(testDir)) {
      try {
        rmSync(testDir, { recursive: true, force: true });
      } catch (error) {
        // Ignore cleanup errors on Windows
        console.warn(`Cleanup warning: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
    vi.clearAllMocks();
  });

  describe('Main Menu Navigation', () => {
    it('should exit gracefully when user selects exit', async () => {
      const { select } = await import('@inquirer/prompts');

      // Mock select to return 'exit' immediately
      vi.mocked(select).mockResolvedValueOnce('exit');

      const memory = await createKVMemory(dbPath);

      const result = await interactiveCommand({
        memory,
        configPath,
      });

      expect(result.success).toBe(true);
      expect(result.message).toBe('Interactive session completed');

      await memory.close();
    });

    it('should handle user force close (Ctrl+C)', async () => {
      const { select } = await import('@inquirer/prompts');

      // Mock select to simulate Ctrl+C
      vi.mocked(select).mockRejectedValueOnce(new Error('User force closed the prompt'));

      const memory = await createKVMemory(dbPath);

      const result = await interactiveCommand({
        memory,
        configPath,
      });

      expect(result.success).toBe(true);

      await memory.close();
    });
  });

  describe('Configuration Wizard', () => {
    it('should update pruning configuration', async () => {
      const { select, number } = await import('@inquirer/prompts');

      // Mock user selecting configure -> pruning -> back -> exit
      vi.mocked(select)
        .mockResolvedValueOnce('configure') // Main menu: configure
        .mockResolvedValueOnce('pruning') // Config menu: pruning
        .mockResolvedValueOnce('back') // Config menu: back
        .mockResolvedValueOnce('exit'); // Main menu: exit

      vi.mocked(number)
        .mockResolvedValueOnce(10) // threshold
        .mockResolvedValueOnce(75); // aggressiveness

      const memory = await createKVMemory(dbPath);

      await interactiveCommand({
        memory,
        configPath,
      });

      // Verify config was updated
      const updatedConfig = readFileSync(configPath, 'utf-8');
      expect(updatedConfig).toContain('threshold: 10');
      expect(updatedConfig).toContain('aggressiveness: 75');

      await memory.close();
    });

    it('should update decay configuration', async () => {
      const { select, number } = await import('@inquirer/prompts');

      vi.mocked(select)
        .mockResolvedValueOnce('configure')
        .mockResolvedValueOnce('decay')
        .mockResolvedValueOnce('back')
        .mockResolvedValueOnce('exit');

      vi.mocked(number)
        .mockResolvedValueOnce(48) // defaultTTL
        .mockResolvedValueOnce(0.85); // decayThreshold

      const memory = await createKVMemory(dbPath);

      await interactiveCommand({
        memory,
        configPath,
      });

      const updatedConfig = readFileSync(configPath, 'utf-8');
      expect(updatedConfig).toContain('defaultTTL: 48');
      expect(updatedConfig).toContain('decayThreshold: 0.85');

      await memory.close();
    });

    it('should update state thresholds', async () => {
      const { select, number } = await import('@inquirer/prompts');

      vi.mocked(select)
        .mockResolvedValueOnce('configure')
        .mockResolvedValueOnce('states')
        .mockResolvedValueOnce('back')
        .mockResolvedValueOnce('exit');

      vi.mocked(number)
        .mockResolvedValueOnce(0.8) // activeThreshold
        .mockResolvedValueOnce(0.4); // readyThreshold

      const memory = await createKVMemory(dbPath);

      await interactiveCommand({
        memory,
        configPath,
      });

      const updatedConfig = readFileSync(configPath, 'utf-8');
      expect(updatedConfig).toContain('activeThreshold: 0.8');
      expect(updatedConfig).toContain('readyThreshold: 0.4');

      await memory.close();
    });

    it('should update realtime configuration', async () => {
      const { select, number, confirm } = await import('@inquirer/prompts');

      vi.mocked(select)
        .mockResolvedValueOnce('configure')
        .mockResolvedValueOnce('realtime')
        .mockResolvedValueOnce('back')
        .mockResolvedValueOnce('exit');

      vi.mocked(number)
        .mockResolvedValueOnce(100000) // tokenBudget
        .mockResolvedValueOnce(150000) // autoOptimizeThreshold
        .mockResolvedValueOnce(1000); // windowSize

      vi.mocked(confirm).mockResolvedValueOnce(false); // incremental

      const memory = await createKVMemory(dbPath);

      await interactiveCommand({
        memory,
        configPath,
      });

      const updatedConfig = readFileSync(configPath, 'utf-8');
      expect(updatedConfig).toContain('tokenBudget: 100000');
      expect(updatedConfig).toContain('autoOptimizeThreshold: 150000');
      expect(updatedConfig).toContain('windowSize: 1000');
      expect(updatedConfig).toContain('incremental: false');

      await memory.close();
    });

    it('should update UI preferences', async () => {
      const { select, confirm } = await import('@inquirer/prompts');

      vi.mocked(select)
        .mockResolvedValueOnce('configure')
        .mockResolvedValueOnce('ui')
        .mockResolvedValueOnce('back')
        .mockResolvedValueOnce('exit');

      vi.mocked(confirm)
        .mockResolvedValueOnce(false) // colors
        .mockResolvedValueOnce(true); // verbose

      const memory = await createKVMemory(dbPath);

      await interactiveCommand({
        memory,
        configPath,
      });

      const updatedConfig = readFileSync(configPath, 'utf-8');
      expect(updatedConfig).toContain('colors: false');
      expect(updatedConfig).toContain('verbose: true');

      await memory.close();
    });
  });

  describe('Optimization Preview', () => {
    it('should skip when no file specified', async () => {
      const { select, input } = await import('@inquirer/prompts');

      vi.mocked(select).mockResolvedValueOnce('preview').mockResolvedValueOnce('exit');

      vi.mocked(input).mockResolvedValueOnce(''); // No file

      const memory = await createKVMemory(dbPath);

      const result = await interactiveCommand({
        memory,
        configPath,
      });

      expect(result.success).toBe(true);

      await memory.close();
    });

    it('should cancel optimization when user declines', async () => {
      const { select, input, confirm } = await import('@inquirer/prompts');

      const testFile = join(testDir, 'test.txt');
      writeFileSync(testFile, 'Test content for optimization', 'utf-8');

      vi.mocked(select).mockResolvedValueOnce('preview').mockResolvedValueOnce('exit');

      vi.mocked(input).mockResolvedValueOnce(testFile);
      vi.mocked(confirm).mockResolvedValueOnce(false); // Don't optimize

      const memory = await createKVMemory(dbPath);

      const result = await interactiveCommand({
        memory,
        configPath,
      });

      expect(result.success).toBe(true);

      await memory.close();
    });

    it('should handle file read errors gracefully', async () => {
      const { select, input } = await import('@inquirer/prompts');

      vi.mocked(select).mockResolvedValueOnce('preview').mockResolvedValueOnce('exit');

      vi.mocked(input).mockResolvedValueOnce('/nonexistent/file.txt');

      const memory = await createKVMemory(dbPath);

      const result = await interactiveCommand({
        memory,
        configPath,
      });

      expect(result.success).toBe(true);

      await memory.close();
    });
  });

  describe('Stats Dashboard', () => {
    it('should display optimization history', async () => {
      const { select } = await import('@inquirer/prompts');

      vi.mocked(select)
        .mockResolvedValueOnce('stats')
        .mockResolvedValueOnce('history')
        .mockResolvedValueOnce('back')
        .mockResolvedValueOnce('exit');

      const memory = await createKVMemory(dbPath);

      // Add some test optimization stats
      await memory.recordOptimization({
        timestamp: Date.now(),
        tokens_before: 10000,
        tokens_after: 3000,
        entries_pruned: 100,
        duration_ms: 250,
      });

      const result = await interactiveCommand({
        memory,
        configPath,
      });

      expect(result.success).toBe(true);

      await memory.close();
    });

    it('should display realtime metrics', async () => {
      const { select } = await import('@inquirer/prompts');

      vi.mocked(select)
        .mockResolvedValueOnce('stats')
        .mockResolvedValueOnce('realtime')
        .mockResolvedValueOnce('back')
        .mockResolvedValueOnce('exit');

      const memory = await createKVMemory(dbPath);

      const result = await interactiveCommand({
        memory,
        configPath,
      });

      expect(result.success).toBe(true);

      await memory.close();
    });

    it('should display memory statistics', async () => {
      const { select } = await import('@inquirer/prompts');

      vi.mocked(select)
        .mockResolvedValueOnce('stats')
        .mockResolvedValueOnce('memory')
        .mockResolvedValueOnce('back')
        .mockResolvedValueOnce('exit');

      const memory = await createKVMemory(dbPath);

      // Add some test entries
      const now = Date.now();
      await memory.put({
        id: 'test-1',
        content: 'Test content 1',
        hash: 'hash-1',
        score: 1.0,
        timestamp: now,
        ttl: 3600,
        state: 'active',
        accessCount: 0,
        tags: [],
        metadata: {},
        isBTSP: false,
      });
      await memory.put({
        id: 'test-2',
        content: 'Test content 2',
        hash: 'hash-2',
        score: 0.8,
        timestamp: now,
        ttl: 3600,
        state: 'active',
        accessCount: 0,
        tags: [],
        metadata: {},
        isBTSP: false,
      });

      const result = await interactiveCommand({
        memory,
        configPath,
      });

      expect(result.success).toBe(true);

      await memory.close();
    });

    it('should navigate back to main menu', async () => {
      const { select } = await import('@inquirer/prompts');

      vi.mocked(select)
        .mockResolvedValueOnce('stats')
        .mockResolvedValueOnce('back')
        .mockResolvedValueOnce('exit');

      const memory = await createKVMemory(dbPath);

      const result = await interactiveCommand({
        memory,
        configPath,
      });

      expect(result.success).toBe(true);

      await memory.close();
    });
  });

  describe('Memory Consolidation', () => {
    it('should cancel consolidation when user declines', async () => {
      const { select, confirm } = await import('@inquirer/prompts');

      vi.mocked(select).mockResolvedValueOnce('consolidate').mockResolvedValueOnce('exit');

      vi.mocked(confirm).mockResolvedValueOnce(false); // Don't consolidate

      const memory = await createKVMemory(dbPath);

      const result = await interactiveCommand({
        memory,
        configPath,
      });

      expect(result.success).toBe(true);

      await memory.close();
    });

    it('should perform consolidation when confirmed', async () => {
      const { select, confirm } = await import('@inquirer/prompts');

      vi.mocked(select).mockResolvedValueOnce('consolidate').mockResolvedValueOnce('exit');

      vi.mocked(confirm).mockResolvedValueOnce(true); // Confirm consolidation

      const memory = await createKVMemory(dbPath);

      // Add some test entries
      const now = Date.now();
      await memory.put({
        id: 'test-1',
        content: 'Test content 1',
        hash: 'hash-1',
        score: 1.0,
        timestamp: now,
        ttl: 3600,
        state: 'active',
        accessCount: 0,
        tags: [],
        metadata: {},
        isBTSP: false,
      });
      await memory.put({
        id: 'test-2',
        content: 'Test content 2',
        hash: 'hash-2',
        score: 0.8,
        timestamp: now,
        ttl: 3600,
        state: 'active',
        accessCount: 0,
        tags: [],
        metadata: {},
        isBTSP: false,
      });

      const result = await interactiveCommand({
        memory,
        configPath,
      });

      expect(result.success).toBe(true);

      await memory.close();
    });
  });

  describe('Quick Actions', () => {
    it.skip('should reset statistics when confirmed', async () => {
      const { select, confirm } = await import('@inquirer/prompts');

      vi.mocked(select)
        .mockResolvedValueOnce('quick')
        .mockResolvedValueOnce('reset-stats')
        .mockResolvedValueOnce('back')
        .mockResolvedValueOnce('exit');

      vi.mocked(confirm).mockResolvedValueOnce(true); // Confirm reset

      const memory = await createKVMemory(dbPath);

      // Add a test stat
      await memory.recordOptimization({
        timestamp: Date.now(),
        tokens_before: 5000,
        tokens_after: 2000,
        entries_pruned: 50,
        duration_ms: 150,
      });

      await interactiveCommand({
        memory,
        configPath,
      });

      // Verify stats were cleared
      const stats = await memory.getOptimizationStats();
      expect(stats.length).toBe(0);

      await memory.close();
    });

    it('should cancel reset when declined', async () => {
      const { select, confirm } = await import('@inquirer/prompts');

      vi.mocked(select)
        .mockResolvedValueOnce('quick')
        .mockResolvedValueOnce('reset-stats')
        .mockResolvedValueOnce('back')
        .mockResolvedValueOnce('exit');

      vi.mocked(confirm).mockResolvedValueOnce(false); // Don't reset

      const memory = await createKVMemory(dbPath);

      // Add a test stat
      await memory.recordOptimization({
        timestamp: Date.now(),
        tokens_before: 5000,
        tokens_after: 2000,
        entries_pruned: 50,
        duration_ms: 150,
      });

      await interactiveCommand({
        memory,
        configPath,
      });

      // Verify stats still exist
      const stats = await memory.getOptimizationStats();
      expect(stats.length).toBe(1);

      await memory.close();
    });

    it.skip('should export config as JSON', async () => {
      const { select, confirm } = await import('@inquirer/prompts');

      vi.mocked(select)
        .mockResolvedValueOnce('quick')
        .mockResolvedValueOnce('export-config')
        .mockResolvedValueOnce('back')
        .mockResolvedValueOnce('exit');

      vi.mocked(confirm).mockResolvedValueOnce(true); // Save to file

      const memory = await createKVMemory(dbPath);

      await interactiveCommand({
        memory,
        configPath,
      });

      // Verify JSON file was created
      const jsonPath = configPath.replace(/\.yaml$/, '.json');
      expect(existsSync(jsonPath)).toBe(true);

      const jsonContent = readFileSync(jsonPath, 'utf-8');
      const parsed = JSON.parse(jsonContent);
      expect(parsed).toHaveProperty('pruning');
      expect(parsed).toHaveProperty('decay');
      expect(parsed).toHaveProperty('states');

      await memory.close();
    });

    it('should run test optimization', async () => {
      const { select } = await import('@inquirer/prompts');

      vi.mocked(select)
        .mockResolvedValueOnce('quick')
        .mockResolvedValueOnce('test-optimize')
        .mockResolvedValueOnce('back')
        .mockResolvedValueOnce('exit');

      const memory = await createKVMemory(dbPath);

      const result = await interactiveCommand({
        memory,
        configPath,
      });

      expect(result.success).toBe(true);

      await memory.close();
    });

    it('should navigate back to main menu', async () => {
      const { select } = await import('@inquirer/prompts');

      vi.mocked(select)
        .mockResolvedValueOnce('quick')
        .mockResolvedValueOnce('back')
        .mockResolvedValueOnce('exit');

      const memory = await createKVMemory(dbPath);

      const result = await interactiveCommand({
        memory,
        configPath,
      });

      expect(result.success).toBe(true);

      await memory.close();
    });
  });

  describe('Error Handling', () => {
    it('should handle unexpected errors gracefully', async () => {
      const { select } = await import('@inquirer/prompts');

      vi.mocked(select)
        .mockRejectedValueOnce(new Error('Unexpected error'))
        .mockResolvedValueOnce('exit');

      const memory = await createKVMemory(dbPath);

      const result = await interactiveCommand({
        memory,
        configPath,
      });

      expect(result.success).toBe(true);

      await memory.close();
    });
  });
});
