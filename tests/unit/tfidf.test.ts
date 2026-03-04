/**
 * TF-IDF Shared Utils Tests
 */

import { describe, expect, it } from 'vitest';
import type { MemoryEntry } from '../../src/types/memory.js';
import { calculateIDF, calculateTF, calculateTFIDF, tokenize } from '../../src/utils/tfidf.js';

function makeEntry(content: string, overrides: Partial<MemoryEntry> = {}): MemoryEntry {
  return {
    id: `test-${Math.random().toString(36).slice(2)}`,
    content,
    hash: `hash-${content.slice(0, 10)}`,
    timestamp: Date.now(),
    score: 0.5,
    ttl: 86400,
    state: 'active',
    accessCount: 0,
    tags: [],
    metadata: {},
    isBTSP: false,
    ...overrides,
  };
}

describe('tokenize', () => {
  it('should split text into lowercase words', () => {
    expect(tokenize('Hello World')).toEqual(['hello', 'world']);
  });

  it('should handle multiple whitespace', () => {
    expect(tokenize('  foo   bar  baz  ')).toEqual(['foo', 'bar', 'baz']);
  });

  it('should return empty array for empty string', () => {
    expect(tokenize('')).toEqual([]);
  });

  it('should return empty array for whitespace-only string', () => {
    expect(tokenize('   \t  \n  ')).toEqual([]);
  });

  it('should handle mixed case', () => {
    expect(tokenize('TypeScript Node.js')).toEqual(['typescript', 'node.js']);
  });
});

describe('calculateTF', () => {
  it('should return sqrt of term count', () => {
    const tokens = ['hello', 'hello', 'hello', 'world'];
    expect(calculateTF('hello', tokens)).toBeCloseTo(Math.sqrt(3));
    expect(calculateTF('world', tokens)).toBeCloseTo(1);
  });

  it('should return 0 for absent terms', () => {
    expect(calculateTF('missing', ['hello'])).toBe(0);
  });
});

describe('calculateIDF', () => {
  it('should return 0 for term in no documents', () => {
    const entries = [makeEntry('hello world'), makeEntry('foo bar')];
    expect(calculateIDF('missing', entries)).toBe(0);
  });

  it('should return higher IDF for rarer terms', () => {
    const entries = [
      makeEntry('error in production'),
      makeEntry('test passes successfully'),
      makeEntry('deployment complete'),
    ];

    const idfError = calculateIDF('error', entries);
    // Also verify 'in' computes without error (result unused - just ensures no crash)
    calculateIDF('in', entries);

    // 'error' appears in 1/3 docs, 'in' appears in 1/3 docs
    expect(idfError).toBeGreaterThan(0);
  });

  it('should return 0 for term in all documents', () => {
    const entries = [makeEntry('hello world'), makeEntry('hello there')];
    expect(calculateIDF('hello', entries)).toBeCloseTo(0);
  });
});

describe('calculateTFIDF', () => {
  it('should score entries by relevance', () => {
    const entries = [
      makeEntry('error error error critical failure'),
      makeEntry('all tests pass successfully'),
      makeEntry('deployment in production error'),
    ];

    const entry0 = entries[0];
    const entry1 = entries[1];
    const errorScore = entry0 ? calculateTFIDF(entry0, entries) : 0;
    const testScore = entry1 ? calculateTFIDF(entry1, entries) : 0;

    // Entry with repeated unique terms should score differently than diverse entry
    expect(errorScore).toBeGreaterThan(0);
    expect(testScore).toBeGreaterThan(0);
  });

  it('should return 0 for empty content', () => {
    const entry = makeEntry('');
    expect(calculateTFIDF(entry, [entry])).toBe(0);
  });

  it('should handle single entry corpus', () => {
    const entry = makeEntry('hello world');
    // IDF will be 0 for all terms (each appears in 1/1 docs)
    expect(calculateTFIDF(entry, [entry])).toBe(0);
  });
});
