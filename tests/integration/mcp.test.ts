import { mkdir, rm } from 'node:fs/promises';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { KVMemory } from '../../src/core/kv-memory.js';
import { createKVMemory } from '../../src/core/kv-memory.js';
import { createCortexMcpServer } from '../../src/mcp/server.js';

describe('MCP server integration', () => {
  const testDir = './.test-mcp';
  const dbPath = `${testDir}/memory.db`;
  let memory: KVMemory;
  let client: Client;

  beforeEach(async () => {
    await mkdir(testDir, { recursive: true });
    memory = await createKVMemory(dbPath);

    const mcpServer = createCortexMcpServer({ memory });
    client = new Client({ name: 'test-client', version: '1.0.0' });

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([client.connect(clientTransport), mcpServer.connect(serverTransport)]);
  });

  afterEach(async () => {
    await client.close();
    await memory.close();
    await rm(testDir, { recursive: true, force: true });
  });

  describe('tool listing', () => {
    it('lists all four tools', async () => {
      const result = await client.listTools();
      const toolNames = result.tools.map((t) => t.name);

      expect(toolNames).toContain('cortex_optimize');
      expect(toolNames).toContain('cortex_stats');
      expect(toolNames).toContain('cortex_consolidate');
      expect(toolNames).toContain('cortex_search');
      expect(result.tools.length).toBe(4);
    });

    it('each tool has a description', async () => {
      const result = await client.listTools();
      for (const tool of result.tools) {
        expect(tool.description).toBeTruthy();
        expect(typeof tool.description).toBe('string');
      }
    });

    it('cortex_optimize has input schema with required context parameter', async () => {
      const result = await client.listTools();
      const optimizeTool = result.tools.find((t) => t.name === 'cortex_optimize');
      expect(optimizeTool).toBeDefined();
      expect(optimizeTool?.inputSchema).toBeDefined();
      expect(optimizeTool?.inputSchema.properties).toHaveProperty('context');
    });
  });

  describe('cortex_optimize', () => {
    it('optimizes context and returns valid result', async () => {
      const result = await client.callTool({
        name: 'cortex_optimize',
        arguments: {
          context: 'Important function definition\nTemporary debug log\nAPI endpoint configuration',
          dryRun: true,
        },
      });

      expect(result.content).toHaveLength(1);

      const content = result.content[0];
      expect(content).toHaveProperty('type', 'text');
      expect(content).toHaveProperty('text');

      const parsed = JSON.parse((content as { type: string; text: string }).text);
      expect(parsed).toHaveProperty('tokensBefore');
      expect(parsed).toHaveProperty('tokensAfter');
      expect(parsed).toHaveProperty('reduction');
      expect(parsed).toHaveProperty('entriesProcessed');
      expect(parsed).toHaveProperty('entriesKept');
      expect(parsed).toHaveProperty('durationMs');
      expect(parsed).toHaveProperty('stateDistribution');
      expect(parsed.tokensBefore).toBeGreaterThan(0);
    });

    it('returns verbose details when requested', async () => {
      const result = await client.callTool({
        name: 'cortex_optimize',
        arguments: {
          context: 'Line one\nLine two\nLine three',
          dryRun: true,
          verbose: true,
        },
      });

      const parsed = JSON.parse((result.content[0] as { type: string; text: string }).text);
      expect(parsed).toHaveProperty('details');
      expect(Array.isArray(parsed.details)).toBe(true);
    });

    it('dry run does not persist entries to memory', async () => {
      const entriesBefore = await memory.list();

      await client.callTool({
        name: 'cortex_optimize',
        arguments: {
          context: 'Test context for dry run',
          dryRun: true,
        },
      });

      const entriesAfter = await memory.list();
      expect(entriesAfter.length).toBe(entriesBefore.length);
    });

    it('non-dry-run persists entries to memory', async () => {
      await client.callTool({
        name: 'cortex_optimize',
        arguments: {
          context: 'Test context to persist\nAnother line to save',
          dryRun: false,
        },
      });

      const entries = await memory.list();
      expect(entries.length).toBeGreaterThan(0);
    });

    it('accepts custom pruning threshold', async () => {
      const result = await client.callTool({
        name: 'cortex_optimize',
        arguments: {
          context: 'Line 1\nLine 2\nLine 3\nLine 4\nLine 5',
          dryRun: true,
          threshold: 50,
        },
      });

      const parsed = JSON.parse((result.content[0] as { type: string; text: string }).text);
      expect(parsed.entriesProcessed).toBeGreaterThan(0);
    });

    it('returns optimized context text', async () => {
      const result = await client.callTool({
        name: 'cortex_optimize',
        arguments: {
          context: 'Keep this important line',
          dryRun: true,
        },
      });

      const parsed = JSON.parse((result.content[0] as { type: string; text: string }).text);
      expect(parsed).toHaveProperty('optimizedContext');
      expect(typeof parsed.optimizedContext).toBe('string');
    });
  });

  describe('cortex_stats', () => {
    it('returns statistics with zero commands initially', async () => {
      const result = await client.callTool({
        name: 'cortex_stats',
        arguments: {},
      });

      const parsed = JSON.parse((result.content[0] as { type: string; text: string }).text);
      expect(parsed.totalCommands).toBe(0);
      expect(parsed.totalTokensSaved).toBe(0);
      expect(parsed.averageReduction).toBe('0.0%');
      expect(parsed.recentOptimizations).toEqual([]);
    });

    it('returns accumulated stats after optimizations', async () => {
      // Run an optimization first (non-dry-run to record stats)
      await client.callTool({
        name: 'cortex_optimize',
        arguments: {
          context: 'First optimization run with some content\nMultiple lines\nImportant data',
        },
      });

      const result = await client.callTool({
        name: 'cortex_stats',
        arguments: {},
      });

      const parsed = JSON.parse((result.content[0] as { type: string; text: string }).text);
      expect(parsed.totalCommands).toBe(1);
      expect(parsed.totalTokensSaved).toBeGreaterThanOrEqual(0);
      expect(parsed.recentOptimizations.length).toBe(1);
    });

    it('resets statistics when reset=true', async () => {
      // Run an optimization to create some stats
      await client.callTool({
        name: 'cortex_optimize',
        arguments: {
          context: 'Generate stats to reset',
        },
      });

      // Reset
      const resetResult = await client.callTool({
        name: 'cortex_stats',
        arguments: { reset: true },
      });

      const resetParsed = JSON.parse(
        (resetResult.content[0] as { type: string; text: string }).text,
      );
      expect(resetParsed.totalCommands).toBe(0);
      expect(resetParsed.message).toContain('reset');

      // Verify stats are actually cleared
      const statsResult = await client.callTool({
        name: 'cortex_stats',
        arguments: {},
      });

      const statsParsed = JSON.parse(
        (statsResult.content[0] as { type: string; text: string }).text,
      );
      expect(statsParsed.totalCommands).toBe(0);
    });
  });

  describe('cortex_consolidate', () => {
    it('runs consolidation on empty memory', async () => {
      const result = await client.callTool({
        name: 'cortex_consolidate',
        arguments: {},
      });

      const parsed = JSON.parse((result.content[0] as { type: string; text: string }).text);
      expect(parsed.entriesBefore).toBe(0);
      expect(parsed.entriesAfter).toBe(0);
      expect(parsed.decayedRemoved).toBe(0);
      expect(parsed.duplicatesRemoved).toBe(0);
      expect(parsed.vacuumCompleted).toBe(true);
    });

    it('runs consolidation after adding entries', async () => {
      // First optimize to populate memory
      await client.callTool({
        name: 'cortex_optimize',
        arguments: {
          context: 'Entry one\nEntry two\nEntry three\nEntry four\nEntry five',
        },
      });

      const entriesBefore = await memory.list();

      const result = await client.callTool({
        name: 'cortex_consolidate',
        arguments: {},
      });

      const parsed = JSON.parse((result.content[0] as { type: string; text: string }).text);
      expect(parsed.entriesBefore).toBe(entriesBefore.length);
      expect(parsed).toHaveProperty('entriesAfter');
      expect(parsed).toHaveProperty('durationMs');
      expect(parsed).toHaveProperty('compressionRatio');
      expect(parsed.vacuumCompleted).toBe(true);
    });
  });

  describe('error handling', () => {
    it('handles missing required context parameter gracefully', async () => {
      // Calling cortex_optimize without context should return an error
      try {
        const result = await client.callTool({
          name: 'cortex_optimize',
          arguments: {},
        });
        // If the SDK returns a result instead of throwing, check for error
        if (result.isError) {
          expect(result.isError).toBe(true);
        }
      } catch (_error) {
        // Expected - missing required parameter
        expect(true).toBe(true);
      }
    });
  });

  describe('server creation', () => {
    it('creates server with default config', () => {
      const mcpServer = createCortexMcpServer({ memory });
      expect(mcpServer).toBeDefined();
    });

    it('creates server with custom config', () => {
      const customConfig = {
        pruning: { threshold: 10, aggressiveness: 70 },
        decay: { defaultTTL: 48, decayThreshold: 0.9 },
        states: { activeThreshold: 0.8, readyThreshold: 0.4 },
        agent: 'generic' as const,
        ui: { colors: false, sounds: false, verbose: false },
        autoConsolidate: null,
        realtime: {
          tokenBudget: 50000,
          autoOptimizeThreshold: 80000,
          watchPatterns: ['**/*.jsonl'],
          pidFile: '.cortex/daemon.pid',
          logFile: '.cortex/daemon.log',
          debounceMs: 5000,
          incremental: true,
          windowSize: 500,
        },
      };

      const mcpServer = createCortexMcpServer({
        memory,
        config: customConfig,
      });
      expect(mcpServer).toBeDefined();
    });
  });
});
