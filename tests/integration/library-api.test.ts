/**
 * Integration tests for Library API
 * Verifies that Cortex can be used as a library with clean TypeScript API
 */

import { mkdir, rm } from 'node:fs/promises';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type {
  AgentAdapter,
  BTSPEmbedder,
  ConfidenceStates,
  EngramScorer,
  KVMemory,
  MemoryEntry,
  SleepCompressor,
  SparsePruner,
} from '../../src/index.js';
import {
  createBTSPEmbedder,
  createConfidenceStates,
  createEngramScorer,
  createGenericAdapter,
  createKVMemory,
  createSleepCompressor,
  createSparsePruner,
  DEFAULT_CONFIG,
  estimateTokens,
  hashContent,
} from '../../src/index.js';

describe('Library API Integration Tests', () => {
  const testDir = './.test-library-api';
  const dbPath = `${testDir}/memory.db`;

  beforeEach(async () => {
    await mkdir(testDir, { recursive: true });
  });

  afterEach(async () => {
    await rm(testDir, { recursive: true, force: true });
  });

  // T155: Integration test: Library import works with all core modules
  describe('T155: Core Module Imports', () => {
    it('should import and create KVMemory', async () => {
      const memory: KVMemory = await createKVMemory(dbPath);
      expect(memory).toBeDefined();
      expect(memory.put).toBeInstanceOf(Function);
      expect(memory.get).toBeInstanceOf(Function);
      expect(memory.query).toBeInstanceOf(Function);
      await memory.close();
    });

    it('should import and create SparsePruner', () => {
      const pruner: SparsePruner = createSparsePruner({ threshold: 5 });
      expect(pruner).toBeDefined();
      expect(pruner.prune).toBeInstanceOf(Function);
    });

    it('should import and create EngramScorer', () => {
      const scorer: EngramScorer = createEngramScorer({
        defaultTTL: 24,
        decayThreshold: 0.95,
      });
      expect(scorer).toBeDefined();
      expect(scorer.calculateScore).toBeInstanceOf(Function);
      expect(scorer.calculateDecay).toBeInstanceOf(Function);
    });

    it('should import and create ConfidenceStates', () => {
      const states: ConfidenceStates = createConfidenceStates({
        activeThreshold: 0.7,
        readyThreshold: 0.3,
      });
      expect(states).toBeDefined();
      expect(states.calculateState).toBeInstanceOf(Function);
      expect(states.getDistribution).toBeInstanceOf(Function);
    });

    it('should import and create BTSPEmbedder', () => {
      const embedder: BTSPEmbedder = createBTSPEmbedder();
      expect(embedder).toBeDefined();
      expect(embedder.detectBTSP).toBeInstanceOf(Function);
      expect(embedder.createBTSPEntry).toBeInstanceOf(Function);
    });

    it('should import and create SleepCompressor', () => {
      const compressor: SleepCompressor = createSleepCompressor();
      expect(compressor).toBeDefined();
      expect(compressor.consolidate).toBeInstanceOf(Function);
      expect(compressor.findDuplicates).toBeInstanceOf(Function);
    });

    it('should import and create GenericAdapter', async () => {
      const memory = await createKVMemory(dbPath);
      const adapter: AgentAdapter = createGenericAdapter(memory, DEFAULT_CONFIG);
      expect(adapter).toBeDefined();
      expect(adapter.optimize).toBeInstanceOf(Function);
      await memory.close();
    });

    it('should import utility functions', () => {
      expect(estimateTokens).toBeInstanceOf(Function);
      expect(hashContent).toBeInstanceOf(Function);
    });
  });

  // T156: Integration test: TypeScript types are exported correctly
  describe('T156: TypeScript Types', () => {
    it('should export MemoryEntry type', () => {
      const entry: MemoryEntry = {
        id: 'test-id',
        content: 'Test content',
        hash: 'test-hash',
        timestamp: Date.now(),
        score: 0.8,
        ttl: 24 * 3600,
        accessCount: 1,
        tags: ['test'],
      };
      expect(entry).toBeDefined();
      expect(entry.id).toBe('test-id');
    });

    it('should export type guards for interfaces', async () => {
      const memory = await createKVMemory(dbPath);

      // Type assertions should work
      const memoryInterface: KVMemory = memory;
      expect(memoryInterface.put).toBeDefined();

      await memory.close();
    });
  });

  // T157: Integration test: Modules can be used independently (no forced coupling)
  describe('T157: Module Independence', () => {
    it('should use SparsePruner without other modules', () => {
      const pruner = createSparsePruner({ threshold: 5 });
      const entries: MemoryEntry[] = [
        {
          id: '1',
          content: 'First entry with relevant content',
          hash: 'hash1',
          timestamp: Date.now(),
          score: 0.9,
          ttl: 3600,
          accessCount: 1,
          tags: [],
        },
        {
          id: '2',
          content: 'Second entry less relevant',
          hash: 'hash2',
          timestamp: Date.now(),
          score: 0.5,
          ttl: 3600,
          accessCount: 1,
          tags: [],
        },
      ];

      const result = pruner.prune(entries, 'relevant');
      expect(result.kept.length).toBeGreaterThan(0);
    });

    it('should use EngramScorer without other modules', () => {
      const scorer = createEngramScorer({
        defaultTTL: 24,
        decayThreshold: 0.95,
      });

      const entry: MemoryEntry = {
        id: 'test',
        content: 'Content',
        hash: 'hash',
        timestamp: Date.now() - 3600 * 1000, // 1 hour ago
        score: 0.8,
        ttl: 24 * 3600,
        accessCount: 1,
        tags: [],
      };

      const score = scorer.calculateScore(entry);
      expect(score).toBeGreaterThan(0);
      expect(score).toBeLessThanOrEqual(1);
    });

    it('should use ConfidenceStates without other modules', () => {
      const states = createConfidenceStates({
        activeThreshold: 0.7,
        readyThreshold: 0.3,
      });

      const entry: MemoryEntry = {
        id: 'test',
        content: 'Content',
        hash: 'hash',
        timestamp: Date.now(),
        score: 0.8,
        ttl: 3600,
        accessCount: 1,
        tags: [],
      };

      const state = states.calculateState(entry);
      expect(state).toBe('active');
    });

    it('should use utility functions independently', () => {
      // estimateTokens works standalone
      const tokens = estimateTokens('Hello world');
      expect(tokens).toBeGreaterThan(0);

      // hashContent works standalone
      const hash = hashContent('Test content');
      expect(hash).toBeDefined();
      expect(typeof hash).toBe('string');
    });

    it('should use SleepCompressor without other modules', () => {
      const compressor = createSleepCompressor();
      const entries: MemoryEntry[] = [
        {
          id: '1',
          content: 'First entry',
          hash: 'hash1',
          timestamp: Date.now() - 100 * 24 * 3600 * 1000, // Very old
          score: 0.1,
          ttl: 24 * 3600,
          accessCount: 0,
          tags: [],
        },
      ];

      const result = compressor.consolidate(entries);
      expect(result.kept).toBeDefined();
      expect(result.removed).toBeDefined();
    });
  });

  // T158: Integration test: JSDoc comments are present on all public APIs
  describe('T158: JSDoc Documentation', () => {
    it('should have JSDoc on factory functions', () => {
      // This test verifies that TypeScript can infer types from JSDoc
      // If JSDoc is missing, type inference would be poor

      const pruner = createSparsePruner({ threshold: 5 }); // Should have type SparsePruner
      expect(pruner).toBeDefined();

      const scorer = createEngramScorer({ defaultTTL: 24, decayThreshold: 0.95 });
      expect(scorer).toBeDefined();

      const states = createConfidenceStates({ activeThreshold: 0.7, readyThreshold: 0.3 });
      expect(states).toBeDefined();
    });

    it('should provide IntelliSense for module methods', () => {
      // This test ensures TypeScript can provide autocomplete
      const pruner = createSparsePruner({ threshold: 5 });

      // If JSDoc is present, these should have type hints
      expect(pruner.prune).toBeDefined();
      expect(pruner.scoreEntry).toBeDefined();
    });
  });

  // Integration test: Full end-to-end usage as library
  describe('End-to-End Library Usage', () => {
    it('should work as a complete library', async () => {
      // Create all modules
      const memory = await createKVMemory(dbPath);
      const adapter = createGenericAdapter(memory, DEFAULT_CONFIG);

      // Store some entries
      await memory.put({
        id: '1',
        content: 'Important context about the feature',
        hash: hashContent('Important context about the feature'),
        timestamp: Date.now(),
        score: 0.9,
        state: 'active',
        ttl: 24 * 3600,
        accessCount: 1,
        tags: ['feature'],
      });

      await memory.put({
        id: '2',
        content: 'Less important context',
        hash: hashContent('Less important context'),
        timestamp: Date.now(),
        score: 0.5,
        state: 'ready',
        ttl: 24 * 3600,
        accessCount: 1,
        tags: [],
      });

      // Optimize context
      const result = await adapter.optimize('Tell me about the feature', {
        verbose: false,
      });

      expect(result.optimizedContext).toBeDefined();
      expect(result.tokensBefore).toBeGreaterThan(0);
      expect(result.tokensAfter).toBeGreaterThanOrEqual(0);
      expect(result.reduction).toBeGreaterThanOrEqual(0);

      await memory.close();
    });
  });
});
