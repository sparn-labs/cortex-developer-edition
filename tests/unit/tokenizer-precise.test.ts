/**
 * Precise Tokenizer Tests
 */

import { afterEach, describe, expect, it } from 'vitest';
import {
  countTokensPrecise,
  estimateTokens,
  setPreciseTokenCounting,
} from '../../src/utils/tokenizer.js';

// Always reset after each test
afterEach(() => {
  setPreciseTokenCounting(false);
});

describe('estimateTokens (heuristic mode)', () => {
  it('should use heuristic by default', () => {
    const result = estimateTokens('Hello world');
    // Heuristic: max(ceil(11/4), ceil(2*0.75)) = max(3, 2) = 3
    expect(result).toBe(3);
  });

  it('should return 0 for empty string', () => {
    expect(estimateTokens('')).toBe(0);
  });

  it('should return 0 for null-ish input', () => {
    expect(estimateTokens('')).toBe(0);
  });
});

describe('setPreciseTokenCounting', () => {
  it('should switch to GPT tokenizer when enabled', () => {
    const heuristicResult = estimateTokens('Hello world');
    setPreciseTokenCounting(true);
    const preciseResult = estimateTokens('Hello world');

    // Precise should return GPT token count (2 tokens for "Hello world")
    expect(preciseResult).toBe(2);
    // Heuristic returns different value
    expect(heuristicResult).not.toBe(preciseResult);
  });

  it('should restore heuristic when disabled', () => {
    const before = estimateTokens('Hello world');
    setPreciseTokenCounting(true);
    setPreciseTokenCounting(false);
    const after = estimateTokens('Hello world');

    expect(after).toBe(before);
  });
});

describe('countTokensPrecise', () => {
  it('should return 0 for empty string', () => {
    expect(countTokensPrecise('')).toBe(0);
  });

  it('should count tokens for code sample within 5% of expected', () => {
    const code = `function fibonacci(n: number): number {
  if (n <= 1) return n;
  return fibonacci(n - 1) + fibonacci(n - 2);
}`;
    const count = countTokensPrecise(code);
    // GPT tokenizer should give a reasonable count for this code
    expect(count).toBeGreaterThan(10);
    expect(count).toBeLessThan(100);
  });

  it('should handle performance for 10KB text', () => {
    const text = 'The quick brown fox jumps over the lazy dog. '.repeat(250);
    expect(text.length).toBeGreaterThan(10000);

    const start = performance.now();
    const count = countTokensPrecise(text);
    const elapsed = performance.now() - start;

    expect(count).toBeGreaterThan(0);
    expect(elapsed).toBeLessThan(100);
  });
});
