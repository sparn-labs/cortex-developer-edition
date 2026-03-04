/**
 * BTSP Embedder - Implements behavioral timescale synaptic plasticity
 *
 * Application: Detect high-importance patterns and mark for permanent retention.
 */

import { randomUUID } from 'node:crypto';
import type { MemoryEntry } from '../types/memory.js';
import { hashContent } from '../utils/hash.js';

export interface BTSPEmbedder {
  /**
   * Detect if content contains BTSP patterns (errors, stack traces, conflicts, git diffs)
   * @param content - Content to analyze
   * @returns True if BTSP pattern detected
   */
  detectBTSP(content: string): boolean;

  /**
   * Create a new memory entry marked as BTSP (one-shot learned)
   * @param content - Entry content
   * @param tags - Optional tags
   * @param metadata - Optional metadata
   * @returns BTSP-marked memory entry
   */
  createBTSPEntry(
    content: string,
    tags?: string[],
    metadata?: Record<string, unknown>,
  ): MemoryEntry;
}

/**
 * Create a BTSP embedder instance
 * @returns BTSPEmbedder instance
 */
export interface BTSPEmbedderConfig {
  /** Additional regex pattern strings to detect BTSP events */
  customPatterns?: string[];
}

export function createBTSPEmbedder(config?: BTSPEmbedderConfig): BTSPEmbedder {
  // Patterns that indicate critical events
  const BTSP_PATTERNS: RegExp[] = [
    // Error patterns
    /\b(error|exception|failure|fatal|critical|panic)\b/i,
    /\b(TypeError|ReferenceError|SyntaxError|RangeError|URIError)\b/,
    /\bENOENT|EACCES|ECONNREFUSED|ETIMEDOUT\b/,

    // Stack trace patterns
    /^\s+at\s+.*\(.*:\d+:\d+\)/m, // JavaScript stack trace
    /^\s+at\s+.*\.[a-zA-Z]+:\d+/m, // Python/Ruby stack trace

    // Git diff new files
    /^new file mode \d+$/m,
    /^--- \/dev\/null$/m,

    // Merge conflict markers
    /^<<<<<<< /m,
    /^=======/m,
    /^>>>>>>> /m,
  ];

  // Merge custom patterns (silently skip invalid regex)
  if (config?.customPatterns) {
    for (const pattern of config.customPatterns) {
      try {
        BTSP_PATTERNS.push(new RegExp(pattern));
      } catch {
        // Invalid regex — silently ignore
      }
    }
  }

  function detectBTSP(content: string): boolean {
    return BTSP_PATTERNS.some((pattern) => pattern.test(content));
  }

  function createBTSPEntry(
    content: string,
    tags: string[] = [],
    metadata: Record<string, unknown> = {},
  ): MemoryEntry {
    return {
      id: randomUUID(),
      content,
      hash: hashContent(content),
      timestamp: Date.now(),
      score: 1.0, // Maximum initial score
      ttl: 365 * 24 * 3600, // 1 year in seconds (long retention)
      state: 'active', // Always active
      accessCount: 0,
      tags: [...tags, 'btsp'],
      metadata,
      isBTSP: true,
    };
  }

  return {
    detectBTSP,
    createBTSPEntry,
  };
}
