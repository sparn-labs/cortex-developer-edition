/**
 * Token estimation utilities.
 * Supports both heuristic (~90% accuracy) and precise (GPT tokenizer, ~95%+ accuracy) modes.
 */

import { encode } from 'gpt-tokenizer';

/** Module-level flag for precise token counting */
let usePrecise = false;

/**
 * Enable or disable precise token counting using GPT tokenizer.
 * When enabled, estimateTokens() uses gpt-tokenizer for ~95%+ accuracy on code.
 * When disabled (default), uses fast whitespace heuristic.
 *
 * @param enabled - Whether to use precise counting
 */
export function setPreciseTokenCounting(enabled: boolean): void {
  usePrecise = enabled;
}

/**
 * Count tokens precisely using GPT tokenizer.
 *
 * @param text - Text to count
 * @returns Exact token count
 */
export function countTokensPrecise(text: string): number {
  if (!text || text.length === 0) {
    return 0;
  }
  return encode(text).length;
}

/**
 * Estimate token count for text.
 *
 * In default (heuristic) mode: ~90% accuracy, very fast.
 * In precise mode: ~95%+ accuracy using GPT tokenizer.
 *
 * @param text - Text to count
 * @returns Estimated token count
 */
export function estimateTokens(text: string): number {
  if (!text || text.length === 0) {
    return 0;
  }

  if (usePrecise) {
    return encode(text).length;
  }

  // Split on whitespace to get words
  const words = text.split(/\s+/).filter((w) => w.length > 0);
  const wordCount = words.length;

  // Character-based estimate
  const charCount = text.length;
  const charEstimate = Math.ceil(charCount / 4);

  // Word-based estimate
  const wordEstimate = Math.ceil(wordCount * 0.75);

  // Return the maximum of both estimates (more conservative)
  return Math.max(wordEstimate, charEstimate);
}
