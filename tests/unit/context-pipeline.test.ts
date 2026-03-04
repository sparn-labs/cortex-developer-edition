/**
 * Context Pipeline Tests
 */

import { beforeEach, describe, expect, it } from 'vitest';
import { createContextPipeline } from '../../src/core/context-pipeline.js';

describe('Context Pipeline', () => {
  const config = {
    tokenBudget: 500,
    decay: { defaultTTL: 24, decayThreshold: 0.95 },
    states: { activeThreshold: 0.7, readyThreshold: 0.3 },
    windowSize: 10,
    fullOptimizationInterval: 50,
  };

  let pipeline: ReturnType<typeof createContextPipeline>;

  beforeEach(() => {
    pipeline = createContextPipeline(config);
  });

  describe('ingest', () => {
    it('should parse and ingest Claude Code context', () => {
      const context = 'User: Hello\nAssistant: Hi there!';

      const count = pipeline.ingest(context);

      expect(count).toBeGreaterThan(0);
    });

    it('should track total ingested entries', () => {
      pipeline.ingest('User: First message');
      const stats1 = pipeline.getStats();

      pipeline.ingest('User: Second message');
      const stats2 = pipeline.getStats();

      expect(stats2.totalIngested).toBeGreaterThan(stats1.totalIngested);
    });

    it('should attach metadata to entries', () => {
      const metadata = { sessionId: 'test-123', custom: 'value' };

      pipeline.ingest('User: Test', metadata);

      const entries = pipeline.getEntries();
      expect(entries.length).toBeGreaterThan(0);

      const firstEntry = entries[0];
      expect(firstEntry?.metadata.sessionId).toBe('test-123');
      expect(firstEntry?.metadata.custom).toBe('value');
    });

    it('should enforce window size limit', () => {
      const smallWindowConfig = { ...config, windowSize: 3 };
      const smallPipeline = createContextPipeline(smallWindowConfig);

      // Ingest more entries than window size
      for (let i = 0; i < 10; i++) {
        smallPipeline.ingest(`User: Message ${i}`);
      }

      const stats = smallPipeline.getStats();
      expect(stats.currentEntries).toBeLessThanOrEqual(3);
    });

    it('should track evicted entries', () => {
      const smallConfig = { ...config, windowSize: 2, tokenBudget: 50 };
      const smallPipeline = createContextPipeline(smallConfig);

      smallPipeline.ingest('User: First very long message that takes many tokens');
      smallPipeline.ingest('User: Second very long message that takes many tokens');
      smallPipeline.ingest('User: Third very long message that takes many tokens');

      const stats = smallPipeline.getStats();
      expect(stats.evictedEntries).toBeGreaterThan(0);
    });

    it('should return 0 for empty content', () => {
      const count = pipeline.ingest('');

      expect(count).toBe(0);
    });
  });

  describe('getContext', () => {
    it('should return chronologically ordered context', () => {
      pipeline.ingest('User: First\nAssistant: Response 1');

      // Wait a bit
      const start = Date.now();
      while (Date.now() - start < 5) {
        // Busy wait
      }

      pipeline.ingest('User: Second\nAssistant: Response 2');

      const context = pipeline.getContext();

      // Should contain content in order
      expect(context).toContain('First');
      expect(context).toContain('Second');

      // First should come before Second
      const firstIndex = context.indexOf('First');
      const secondIndex = context.indexOf('Second');
      expect(firstIndex).toBeLessThan(secondIndex);
    });

    it('should separate entries with double newlines', () => {
      pipeline.ingest('User: Hello\nAssistant: Hi');

      const context = pipeline.getContext();

      // Should have proper separation
      expect(context).toContain('\n\n');
    });

    it('should return empty string for empty pipeline', () => {
      const context = pipeline.getContext();

      expect(context).toBe('');
    });
  });

  describe('getEntries', () => {
    it('should return entries in chronological order', () => {
      pipeline.ingest('User: Message 1');

      const start = Date.now();
      while (Date.now() - start < 5) {
        // Busy wait
      }

      pipeline.ingest('User: Message 2');

      const entries = pipeline.getEntries();

      expect(entries.length).toBeGreaterThan(0);

      // Verify chronological order
      for (let i = 1; i < entries.length; i++) {
        expect(entries[i]?.timestamp).toBeGreaterThanOrEqual(entries[i - 1]?.timestamp);
      }
    });

    it('should return empty array for empty pipeline', () => {
      const entries = pipeline.getEntries();

      expect(entries).toEqual([]);
    });
  });

  describe('getStats', () => {
    it('should track current token count', () => {
      pipeline.ingest('User: Short');

      const stats = pipeline.getStats();

      expect(stats.currentTokens).toBeGreaterThan(0);
    });

    it('should calculate budget utilization', () => {
      pipeline.ingest('User: Test message');

      const stats = pipeline.getStats();

      expect(stats.budgetUtilization).toBeGreaterThanOrEqual(0);
      expect(stats.budgetUtilization).toBeLessThanOrEqual(1);
    });

    it('should include optimizer stats', () => {
      pipeline.ingest('User: Test');

      const stats = pipeline.getStats();

      expect(stats.optimizer).toBeDefined();
      expect(stats.optimizer.cachedEntries).toBeGreaterThanOrEqual(0);
      expect(stats.optimizer.uniqueTerms).toBeGreaterThanOrEqual(0);
    });
  });

  describe('clear', () => {
    it('should reset all state', () => {
      pipeline.ingest('User: Message 1');
      pipeline.ingest('User: Message 2');

      pipeline.clear();

      const stats = pipeline.getStats();

      expect(stats.totalIngested).toBe(0);
      expect(stats.currentEntries).toBe(0);
      expect(stats.currentTokens).toBe(0);
      expect(stats.evictedEntries).toBe(0);
      expect(stats.optimizer.cachedEntries).toBe(0);
    });

    it('should allow ingestion after clear', () => {
      pipeline.ingest('User: Before clear');
      pipeline.clear();

      const count = pipeline.ingest('User: After clear');

      expect(count).toBeGreaterThan(0);

      const entries = pipeline.getEntries();
      expect(entries.length).toBeGreaterThan(0);
    });
  });

  describe('token budget enforcement', () => {
    it('should stay within token budget', () => {
      const strictConfig = { ...config, tokenBudget: 100 };
      const strictPipeline = createContextPipeline(strictConfig);

      // Ingest lots of content
      for (let i = 0; i < 20; i++) {
        strictPipeline.ingest(`User: Message ${i} with additional content to consume tokens`);
      }

      const stats = strictPipeline.getStats();
      expect(stats.currentTokens).toBeLessThanOrEqual(100);
    });
  });
});
