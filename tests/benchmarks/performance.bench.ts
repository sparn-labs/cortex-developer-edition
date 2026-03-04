/**
 * Performance Benchmarks
 *
 * Validates performance targets:
 * - Incremental optimization: <50ms
 * - Full optimization: <500ms for 10K entries
 * - Budget pruning: <100ms for 1K entries
 * - Context pipeline: <10ms ingestion
 */

import { bench, describe } from 'vitest';
import { createBudgetPruner } from '../../src/core/budget-pruner.js';
import { createContextPipeline } from '../../src/core/context-pipeline.js';
import { createIncrementalOptimizer } from '../../src/core/incremental-optimizer.js';
import type { MemoryEntry } from '../../src/types/memory.js';
import { hashContent } from '../../src/utils/hash.js';

// Test data generators
function createEntry(content: string, isBTSP = false): MemoryEntry {
  return {
    id: Math.random().toString(),
    content,
    hash: hashContent(content),
    timestamp: Date.now(),
    score: 0.5,
    ttl: 24 * 3600,
    state: 'ready',
    accessCount: 0,
    tags: [],
    metadata: {},
    isBTSP,
  };
}

function generateEntries(count: number): MemoryEntry[] {
  return Array.from({ length: count }, (_, i) =>
    createEntry(
      `Entry ${i}: ${Math.random().toString(36).substring(7)} with some content to fill tokens and make it realistic for testing purposes. This is message number ${i} in the sequence.`,
    ),
  );
}

const config = {
  tokenBudget: 50000,
  decay: { defaultTTL: 24, decayThreshold: 0.95 },
  states: { activeThreshold: 0.7, readyThreshold: 0.3 },
  fullOptimizationInterval: 50,
};

describe('Budget Pruner Performance', () => {
  bench('prune 100 entries', () => {
    const pruner = createBudgetPruner(config);
    const entries = generateEntries(100);
    pruner.pruneToFit(entries);
  });

  bench('prune 500 entries', () => {
    const pruner = createBudgetPruner(config);
    const entries = generateEntries(500);
    pruner.pruneToFit(entries);
  });

  bench('prune 1000 entries', () => {
    const pruner = createBudgetPruner(config);
    const entries = generateEntries(1000);
    pruner.pruneToFit(entries);
  });

  bench('priority scoring (100 entries)', () => {
    const pruner = createBudgetPruner(config);
    const entries = generateEntries(100);
    for (const entry of entries) {
      pruner.priorityScore(entry, entries);
    }
  });
});

describe('Incremental Optimizer Performance', () => {
  bench('incremental optimization (10 new entries)', () => {
    const optimizer = createIncrementalOptimizer(config);
    const entries = generateEntries(10);
    optimizer.optimizeIncremental(entries);
  });

  bench('incremental optimization (100 new entries)', () => {
    const optimizer = createIncrementalOptimizer(config);
    const entries = generateEntries(100);
    optimizer.optimizeIncremental(entries);
  });

  bench('full optimization (1000 entries)', () => {
    const optimizer = createIncrementalOptimizer(config);
    const entries = generateEntries(1000);
    optimizer.optimizeFull(entries);
  });

  bench('full optimization (10000 entries)', () => {
    const optimizer = createIncrementalOptimizer(config);
    const entries = generateEntries(10000);
    optimizer.optimizeFull(entries);
  });

  bench('state serialization', () => {
    const optimizer = createIncrementalOptimizer(config);
    const entries = generateEntries(100);
    optimizer.optimizeIncremental(entries);
    const state = optimizer.getState();
    const newOptimizer = createIncrementalOptimizer(config);
    newOptimizer.restoreState(state);
  });
});

describe('Context Pipeline Performance', () => {
  bench('ingest small message', () => {
    const pipeline = createContextPipeline({ ...config, windowSize: 500 });
    pipeline.ingest('User: Hello\nAssistant: Hi there!');
  });

  bench('ingest medium conversation', () => {
    const pipeline = createContextPipeline({ ...config, windowSize: 500 });
    const conversation = Array.from(
      { length: 10 },
      (_, i) => `User: Message ${i}\nAssistant: Response ${i}`,
    ).join('\n');
    pipeline.ingest(conversation);
  });

  bench('ingest large context', () => {
    const pipeline = createContextPipeline({ ...config, windowSize: 500 });
    const context = Array.from(
      { length: 100 },
      (_, i) =>
        `User: Message ${i} with more content\nAssistant: Response ${i} with detailed information`,
    ).join('\n');
    pipeline.ingest(context);
  });

  bench('get chronological context', () => {
    const pipeline = createContextPipeline({ ...config, windowSize: 500 });
    // Pre-populate
    for (let i = 0; i < 50; i++) {
      pipeline.ingest(`User: Message ${i}\nAssistant: Response ${i}`);
    }
    // Benchmark retrieval
    pipeline.getContext();
  });

  bench('pipeline with eviction (high load)', () => {
    const pipeline = createContextPipeline({ ...config, windowSize: 100 });
    for (let i = 0; i < 200; i++) {
      pipeline.ingest(`User: Message ${i} with substantial content to trigger eviction`);
    }
  });
});

describe('End-to-End Performance', () => {
  bench('complete optimization cycle', () => {
    const pipeline = createContextPipeline({ ...config, windowSize: 500 });

    // Simulate a real session
    for (let i = 0; i < 50; i++) {
      pipeline.ingest(`User: Query ${i}\nAssistant: Response ${i} with detailed explanation`);
    }

    pipeline.getContext();
    pipeline.getStats();
  });

  bench('heavy session (1000 messages)', () => {
    const pipeline = createContextPipeline({ ...config, windowSize: 500 });

    for (let i = 0; i < 1000; i++) {
      pipeline.ingest(`User: Message ${i}\nAssistant: Response ${i}`);
    }

    pipeline.getContext();
  });
});
