/**
 * Cortex MCP Server - Model Context Protocol server implementation
 *
 * Exposes Cortex context optimization as MCP tools, enabling integration
 * with Claude Desktop, VS Code, and other MCP clients.
 *
 * Tools:
 * - cortex_optimize: Optimize context with configurable options
 * - cortex_stats: Get optimization statistics
 * - cortex_consolidate: Run memory consolidation
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { createClaudeCodeAdapter } from '../adapters/claude-code.js';
import { createGenericAdapter } from '../adapters/generic.js';
import type { KVMemory } from '../core/kv-memory.js';
import { createSleepCompressor } from '../core/sleep-compressor.js';
import type { CortexConfig } from '../types/config.js';
import { DEFAULT_CONFIG } from '../types/config.js';

/**
 * Options for creating the Cortex MCP server.
 */
export interface CortexMcpServerOptions {
  /** KV memory store instance */
  memory: KVMemory;
  /** Cortex configuration (defaults to DEFAULT_CONFIG) */
  config?: CortexConfig;
}

/**
 * Create and configure the Cortex MCP server with all tools registered.
 *
 * @param options - Server options including memory store and config
 * @returns Configured McpServer instance ready to connect to a transport
 */
export function createCortexMcpServer(options: CortexMcpServerOptions): McpServer {
  const { memory, config = DEFAULT_CONFIG } = options;

  const server = new McpServer({
    name: 'cortex',
    version: '1.0.0',
  });

  registerOptimizeTool(server, memory, config);
  registerStatsTool(server, memory);
  registerConsolidateTool(server, memory);
  registerSearchTool(server, memory);

  return server;
}

/**
 * Register the cortex_optimize tool.
 *
 * Optimizes input context using the multi-stage pipeline:
 * critical event detection, relevance scoring, entry classification, and sparse pruning.
 */
function registerOptimizeTool(server: McpServer, memory: KVMemory, config: CortexConfig): void {
  server.registerTool(
    'cortex_optimize',
    {
      title: 'Cortex Optimize',
      description:
        'Optimize context using multi-stage pruning. ' +
        'Applies critical event detection, relevance scoring, entry classification, ' +
        'and sparse pruning to reduce token usage while preserving important information.',
      inputSchema: {
        context: z.string().describe('The context text to optimize'),
        dryRun: z
          .boolean()
          .optional()
          .default(false)
          .describe('If true, do not persist changes to the memory store'),
        verbose: z
          .boolean()
          .optional()
          .default(false)
          .describe('If true, include per-entry details in the response'),
        threshold: z
          .number()
          .min(0)
          .max(100)
          .optional()
          .describe('Custom pruning threshold (1-100, overrides config)'),
      },
    },
    async ({ context, dryRun, verbose, threshold }) => {
      try {
        const effectiveConfig = threshold
          ? { ...config, pruning: { ...config.pruning, threshold } }
          : config;

        const adapter =
          effectiveConfig.agent === 'claude-code'
            ? createClaudeCodeAdapter(memory, effectiveConfig)
            : createGenericAdapter(memory, effectiveConfig);
        const result = await adapter.optimize(context, {
          dryRun,
          verbose,
          threshold,
        });

        const response = {
          optimizedContext: result.optimizedContext,
          tokensBefore: result.tokensBefore,
          tokensAfter: result.tokensAfter,
          reduction: `${(result.reduction * 100).toFixed(1)}%`,
          entriesProcessed: result.entriesProcessed,
          entriesKept: result.entriesKept,
          durationMs: result.durationMs,
          stateDistribution: result.stateDistribution,
          ...(verbose && result.details ? { details: result.details } : {}),
        };

        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify(response, null, 2),
            },
          ],
        };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify({ error: message }),
            },
          ],
          isError: true,
        };
      }
    },
  );
}

/**
 * Register the cortex_stats tool.
 *
 * Returns optimization statistics from the memory store, including
 * total commands run, tokens saved, and average reduction.
 */
function registerStatsTool(server: McpServer, memory: KVMemory): void {
  server.registerTool(
    'cortex_stats',
    {
      title: 'Cortex Stats',
      description:
        'Get optimization statistics including total commands run, ' +
        'tokens saved, and average reduction percentage.',
      inputSchema: {
        reset: z
          .boolean()
          .optional()
          .default(false)
          .describe('If true, reset all optimization statistics'),
      },
    },
    async ({ reset }) => {
      try {
        if (reset) {
          await memory.clearOptimizationStats();
          return {
            content: [
              {
                type: 'text' as const,
                text: JSON.stringify(
                  {
                    message: 'Optimization statistics have been reset.',
                    totalCommands: 0,
                    totalTokensSaved: 0,
                    averageReduction: '0.0%',
                  },
                  null,
                  2,
                ),
              },
            ],
          };
        }

        const stats = await memory.getOptimizationStats();
        const totalCommands = stats.length;

        const totalTokensSaved = stats.reduce(
          (sum, s) => sum + (s.tokens_before - s.tokens_after),
          0,
        );

        const averageReduction =
          totalCommands > 0
            ? stats.reduce((sum, s) => {
                const reduction =
                  s.tokens_before > 0 ? (s.tokens_before - s.tokens_after) / s.tokens_before : 0;
                return sum + reduction;
              }, 0) / totalCommands
            : 0;

        const recentOptimizations = stats.slice(0, 10).map((s) => ({
          timestamp: new Date(s.timestamp).toISOString(),
          tokensBefore: s.tokens_before,
          tokensAfter: s.tokens_after,
          entriesPruned: s.entries_pruned,
          durationMs: s.duration_ms,
          reduction: `${(
            ((s.tokens_before - s.tokens_after) / Math.max(s.tokens_before, 1)) * 100
          ).toFixed(1)}%`,
        }));

        const response = {
          totalCommands,
          totalTokensSaved,
          averageReduction: `${(averageReduction * 100).toFixed(1)}%`,
          recentOptimizations,
        };

        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify(response, null, 2),
            },
          ],
        };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify({ error: message }),
            },
          ],
          isError: true,
        };
      }
    },
  );
}

/**
 * Register the cortex_search tool.
 *
 * Searches memory entries using FTS5 full-text search.
 * Returns matching entries with score, state, and rank info.
 */
function registerSearchTool(server: McpServer, memory: KVMemory): void {
  server.registerTool(
    'cortex_search',
    {
      title: 'Cortex Search',
      description:
        'Search memory entries using full-text search. ' +
        'Returns matching entries with relevance ranking, score, and state information.',
      inputSchema: {
        query: z.string().describe('Search query text'),
        limit: z
          .number()
          .int()
          .min(1)
          .max(100)
          .optional()
          .default(10)
          .describe('Maximum number of results (1-100, default 10)'),
      },
    },
    async ({ query, limit }) => {
      try {
        const results = await memory.searchFTS(query, limit);

        const response = results.map((r) => ({
          id: r.entry.id,
          content:
            r.entry.content.length > 500 ? `${r.entry.content.slice(0, 500)}...` : r.entry.content,
          score: r.entry.score,
          state: r.entry.state,
          rank: r.rank,
          tags: r.entry.tags,
          isBTSP: r.entry.isBTSP,
        }));

        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify({ results: response, total: response.length }, null, 2),
            },
          ],
        };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify({ error: message }),
            },
          ],
          isError: true,
        };
      }
    },
  );
}

/**
 * Register the cortex_consolidate tool.
 *
 * Runs the consolidation process, which removes decayed entries
 * and merges duplicates in the memory store.
 */
function registerConsolidateTool(server: McpServer, memory: KVMemory): void {
  server.registerTool(
    'cortex_consolidate',
    {
      title: 'Cortex Consolidate',
      description:
        'Run memory consolidation. ' +
        'Removes decayed entries and merges duplicates to reclaim space.',
    },
    async () => {
      try {
        const allIds = await memory.list();
        const allEntries = await Promise.all(
          allIds.map(async (id) => {
            const entry = await memory.get(id);
            return entry;
          }),
        );

        const entries = allEntries.filter((e) => e !== null);

        const compressor = createSleepCompressor();
        const result = compressor.consolidate(entries);

        // Apply changes to memory store
        for (const removed of result.removed) {
          await memory.delete(removed.id);
        }

        for (const kept of result.kept) {
          await memory.put(kept);
        }

        // Run VACUUM to reclaim disk space
        await memory.compact();

        const response = {
          entriesBefore: result.entriesBefore,
          entriesAfter: result.entriesAfter,
          decayedRemoved: result.decayedRemoved,
          duplicatesRemoved: result.duplicatesRemoved,
          compressionRatio: `${(result.compressionRatio * 100).toFixed(1)}%`,
          durationMs: result.durationMs,
          vacuumCompleted: true,
        };

        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify(response, null, 2),
            },
          ],
        };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify({ error: message }),
            },
          ],
          isError: true,
        };
      }
    },
  );
}
