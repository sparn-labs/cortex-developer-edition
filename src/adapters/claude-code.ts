/**
 * Claude Code Adapter - Claude Code-specific optimization pipeline
 *
 * Optimized for Claude Code's conversation patterns, tool use, and context management.
 * Implements the same AgentAdapter interface as GenericAdapter but with Claude-specific tuning.
 */

import { createBTSPEmbedder } from '../core/btsp-embedder.js';
import { createBudgetPruner } from '../core/budget-pruner.js';
import { createConfidenceStates } from '../core/confidence-states.js';
import { createEngramScorer } from '../core/engram-scorer.js';
import type { KVMemory } from '../core/kv-memory.js';
import type { AgentAdapter, OptimizationResult, OptimizeOptions } from '../types/adapter.js';
import type { CortexConfig } from '../types/config.js';
import { parseClaudeCodeContext } from '../utils/context-parser.js';
import { estimateTokens } from '../utils/tokenizer.js';

/**
 * Claude Code-specific optimization profile
 * Tuned for Claude's conversation patterns and tool use
 */
const CLAUDE_CODE_PROFILE = {
  // Preserve conversation turns more aggressively
  conversationBoost: 1.5, // 50% boost for User/Assistant exchanges

  // BTSP patterns specific to Claude Code
  btspPatterns: [
    // Error patterns
    /\b(error|exception|failure|fatal|critical|panic)\b/i,
    /^\s+at\s+.*\(.*:\d+:\d+\)/m, // Stack traces
    /^Error:/m,

    // Git conflict markers
    /^<<<<<<< /m,
    /^=======/m,
    /^>>>>>>> /m,

    // Tool use patterns (important for context)
    /<function_calls>/,
    /<invoke>/,
    /<tool_use>/,

    // File operation results (often critical)
    /ENOENT|EACCES|EISDIR|EEXIST/,
  ],
};

/**
 * Create a Claude Code adapter instance
 * @param memory - KV memory store
 * @param config - Cortex configuration
 * @returns AgentAdapter instance optimized for Claude Code
 */
export function createClaudeCodeAdapter(memory: KVMemory, config: CortexConfig): AgentAdapter {
  // Create core modules with Claude Code-optimized settings
  const pruner = createBudgetPruner({
    tokenBudget: config.realtime.tokenBudget,
    decay: config.decay,
    states: config.states,
  });

  const scorer = createEngramScorer(config.decay);
  const states = createConfidenceStates(config.states);
  const btsp = createBTSPEmbedder({ customPatterns: config.btspPatterns });

  async function optimize(
    context: string,
    options: OptimizeOptions = {},
  ): Promise<OptimizationResult> {
    const startTime = Date.now();

    // Parse context into entries
    // For Claude Code, we parse by conversation turns and tool uses
    const entries = parseClaudeCodeContext(context);

    // Apply BTSP detection with Claude Code-specific patterns
    const entriesWithBTSP = entries.map((entry) => {
      const isBTSP = CLAUDE_CODE_PROFILE.btspPatterns.some((pattern) =>
        pattern.test(entry.content),
      );

      if (isBTSP) {
        const btspEntry = btsp.createBTSPEntry(entry.content, [...entry.tags, 'claude-code'], {
          originalTimestamp: entry.timestamp,
        });
        // Preserve original timestamp
        return {
          ...btspEntry,
          timestamp: entry.timestamp,
        };
      }

      return entry;
    });

    // Apply conversation boost to User/Assistant exchanges
    const boostedEntries = entriesWithBTSP.map((entry) => {
      const isConversationTurn =
        entry.content.trim().startsWith('User:') || entry.content.trim().startsWith('Assistant:');

      if (isConversationTurn) {
        return {
          ...entry,
          score: entry.score * CLAUDE_CODE_PROFILE.conversationBoost,
        };
      }

      return entry;
    });

    // Score entries with decay, preserving conversation boost
    const scoredEntries = boostedEntries.map((entry) => {
      const decayScore = scorer.calculateScore(entry);
      const isConversationTurn =
        entry.content.trim().startsWith('User:') || entry.content.trim().startsWith('Assistant:');

      // For conversation turns, apply boost on top of decay score instead of losing it
      const finalScore = isConversationTurn
        ? Math.min(1.0, decayScore * CLAUDE_CODE_PROFILE.conversationBoost)
        : decayScore;

      return {
        ...entry,
        score: finalScore,
      };
    });

    // Calculate states
    const entriesWithStates = scoredEntries.map((entry) => {
      const state = states.calculateState(entry);
      return {
        ...entry,
        state,
      };
    });

    // Prune entries to fit within token budget
    const pruneResult = pruner.pruneToFit(entriesWithStates);

    // Store kept entries in memory (if not dry-run)
    if (!options.dryRun) {
      for (const entry of pruneResult.kept) {
        await memory.put(entry);
      }

      // Record optimization stats
      await memory.recordOptimization({
        timestamp: Date.now(),
        tokens_before: pruneResult.originalTokens,
        tokens_after: pruneResult.prunedTokens,
        entries_pruned: pruneResult.removed.length,
        duration_ms: Date.now() - startTime,
      });
    }

    // Build optimized context from kept entries
    const optimizedContext = pruneResult.kept.map((entry) => entry.content).join('\n');

    // Calculate state distribution
    const stateDistribution = states.getDistribution(pruneResult.kept);

    // Build result
    const result: OptimizationResult = {
      optimizedContext,
      tokensBefore: pruneResult.originalTokens,
      tokensAfter: pruneResult.prunedTokens,
      reduction:
        pruneResult.originalTokens > 0
          ? (pruneResult.originalTokens - pruneResult.prunedTokens) / pruneResult.originalTokens
          : 0,
      entriesProcessed: entries.length,
      entriesKept: pruneResult.kept.length,
      durationMs: Date.now() - startTime,
      stateDistribution,
    };

    // Add verbose details if requested
    if (options.verbose) {
      result.details = pruneResult.kept.map((entry) => ({
        id: entry.id,
        score: entry.score,
        state: entry.state || 'unknown',
        isBTSP: entry.tags.includes('btsp'),
        tokens: estimateTokens(entry.content),
      }));
    }

    return result;
  }

  return {
    optimize,
  };
}
