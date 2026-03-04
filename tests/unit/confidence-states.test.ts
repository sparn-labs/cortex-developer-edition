import { beforeEach, describe, expect, it } from 'vitest';
import { createConfidenceStates } from '../../src/core/confidence-states.js';
import type { MemoryEntry } from '../../src/types/memory.js';

describe('ConfidenceStates', () => {
  let states: ReturnType<typeof createConfidenceStates>;

  beforeEach(() => {
    states = createConfidenceStates({
      activeThreshold: 0.7,
      readyThreshold: 0.3,
    });
  });

  it("returns 'silent' for score <0.3", () => {
    const entry: MemoryEntry = {
      id: 'test',
      content: 'test',
      hash: 'hash',
      timestamp: Date.now(),
      score: 0.2,
      ttl: 3600,
      state: 'ready', // Will be recalculated
      accessCount: 0,
      tags: [],
      metadata: {},
      isBTSP: false,
    };

    const newState = states.calculateState(entry);
    expect(newState).toBe('silent');
  });

  it("returns 'ready' for score 0.3 to <0.7", () => {
    const testCases = [0.3, 0.5, 0.69];

    for (const score of testCases) {
      const entry: MemoryEntry = {
        id: 'test',
        content: 'test',
        hash: 'hash',
        timestamp: Date.now(),
        score,
        ttl: 3600,
        state: 'silent',
        accessCount: 0,
        tags: [],
        metadata: {},
        isBTSP: false,
      };

      const newState = states.calculateState(entry);
      expect(newState).toBe('ready');
    }
  });

  it("returns 'active' for score >=0.7", () => {
    for (const score of [0.7, 0.9, 1.0]) {
      const entry: MemoryEntry = {
        id: 'test',
        content: 'test',
        hash: 'hash',
        timestamp: Date.now(),
        score,
        ttl: 3600,
        state: 'silent',
        accessCount: 0,
        tags: [],
        metadata: {},
        isBTSP: false,
      };

      const newState = states.calculateState(entry);
      expect(newState).toBe('active');
    }
  });

  it("returns 'active' for isBTSP=true regardless of score", () => {
    const entry: MemoryEntry = {
      id: 'btsp',
      content: 'critical error trace',
      hash: 'hash',
      timestamp: Date.now(),
      score: 0.1, // Very low score
      ttl: 3600,
      state: 'silent',
      accessCount: 0,
      tags: [],
      metadata: {},
      isBTSP: true, // One-shot learned
    };

    const newState = states.calculateState(entry);
    expect(newState).toBe('active'); // BTSP overrides score
  });

  it('transition updates entry state correctly', () => {
    const entry: MemoryEntry = {
      id: 'test',
      content: 'test',
      hash: 'hash',
      timestamp: Date.now(),
      score: 0.8,
      ttl: 3600,
      state: 'silent', // Old state
      accessCount: 0,
      tags: [],
      metadata: {},
      isBTSP: false,
    };

    const updated = states.transition(entry);

    expect(updated.state).toBe('active'); // Should transition to active
    expect(updated.id).toBe(entry.id); // Same entry
    expect(updated.score).toBe(entry.score); // Score unchanged
  });
});
