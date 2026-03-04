/**
 * Generic Adapter - Agent-agnostic optimization pipeline
 *
 * Orchestrates all optimization modules to process context memory.
 */

import { randomUUID } from 'node:crypto';
import { createBTSPEmbedder } from '../core/btsp-embedder.js';
import { createConfidenceStates } from '../core/confidence-states.js';
import { createEngramScorer } from '../core/engram-scorer.js';
import type { KVMemory } from '../core/kv-memory.js';
import { createSparsePruner } from '../core/sparse-pruner.js';
import type { AgentAdapter, OptimizationResult, OptimizeOptions } from '../types/adapter.js';
import type { CortexConfig } from '../types/config.js';
import type { MemoryEntry } from '../types/memory.js';
import { hashContent } from '../utils/hash.js';
import { estimateTokens } from '../utils/tokenizer.js';

/**
 * Create a generic adapter instance
 * @param memory - KV memory store
 * @param config - Cortex configuration
 * @returns AgentAdapter instance
 */
export function createGenericAdapter(memory: KVMemory, config: CortexConfig): AgentAdapter {
  const pruner = createSparsePruner(config.pruning);
  const scorer = createEngramScorer(config.decay);
  const states = createConfidenceStates(config.states);
  const btsp = createBTSPEmbedder({ customPatterns: config.btspPatterns });

  async function optimize(
    context: string,
    options: OptimizeOptions = {},
  ): Promise<OptimizationResult> {
    const startTime = Date.now();

    // Parse context into entries (line-based for simplicity)
    const lines = context.split('\n').filter((line) => line.trim().length > 0);
    const now = Date.now();
    const entries: MemoryEntry[] = lines.map((content, index) => {
      const isBTSP = btsp.detectBTSP(content);
      return {
        id: randomUUID(),
        content,
        hash: hashContent(content),
        timestamp: now + index, // Unique timestamps preserve ordering
        score: isBTSP ? 1.0 : 0.5,
        ttl: config.decay.defaultTTL * 3600,
        state: 'ready' as const,
        accessCount: 0,
        tags: [],
        metadata: {},
        isBTSP,
      };
    });

    // Calculate original token count
    const tokensBefore = entries.reduce((sum, e) => sum + estimateTokens(e.content), 0);

    // Step 1: Update scores with decay
    const scoredEntries = entries.map((entry) => ({
      ...entry,
      score: scorer.calculateScore(entry),
    }));

    // Step 2: Transition states based on scores
    const statedEntries = scoredEntries.map((entry) => states.transition(entry));

    // Step 3: Apply sparse pruning
    const pruneResult = pruner.prune(statedEntries);

    // Step 4: Keep active and ready entries, discard silent
    const optimizedEntries = pruneResult.kept.filter(
      (e) => e.state === 'active' || e.state === 'ready',
    );

    // Calculate final token count
    const tokensAfter = optimizedEntries.reduce((sum, e) => sum + estimateTokens(e.content), 0);

    // Reconstruct optimized context
    const optimizedContext = optimizedEntries.map((e) => e.content).join('\n');

    // Store entries in memory (if not dry run)
    if (!options.dryRun) {
      for (const entry of optimizedEntries) {
        await memory.put(entry);
      }

      // Record optimization statistics
      await memory.recordOptimization({
        timestamp: Date.now(),
        tokens_before: tokensBefore,
        tokens_after: tokensAfter,
        entries_pruned: entries.length - optimizedEntries.length,
        duration_ms: Date.now() - startTime,
      });
    }

    // Get state distribution
    const distribution = states.getDistribution(optimizedEntries);

    const result: OptimizationResult = {
      optimizedContext,
      tokensBefore,
      tokensAfter,
      reduction: tokensBefore > 0 ? (tokensBefore - tokensAfter) / tokensBefore : 0,
      entriesProcessed: entries.length,
      entriesKept: optimizedEntries.length,
      stateDistribution: distribution,
      durationMs: Date.now() - startTime,
    };

    // Add verbose details if requested
    if (options.verbose) {
      result.details = optimizedEntries.map((e) => ({
        id: e.id,
        score: e.score,
        state: e.state,
        isBTSP: e.isBTSP,
        tokens: estimateTokens(e.content),
      }));
    }

    return result;
  }

  return {
    optimize,
  };
}
