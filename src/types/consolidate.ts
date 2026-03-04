/**
 * Sleep compressor (consolidation) types.
 * Periodic consolidation removes decayed entries and merges duplicates.
 */

import type { MemoryEntry } from './memory.js';

/**
 * Result of a consolidation operation.
 */
export interface ConsolidateResult {
  /** Entries kept after consolidation */
  kept: MemoryEntry[];

  /** Entries removed during consolidation */
  removed: MemoryEntry[];

  /** Entries before consolidation */
  entriesBefore: number;

  /** Entries after consolidation */
  entriesAfter: number;

  /** Number of decayed entries removed */
  decayedRemoved: number;

  /** Number of duplicate entries merged */
  duplicatesRemoved: number;

  /** Compression ratio (0.0-1.0) */
  compressionRatio: number;

  /** Consolidation duration in milliseconds */
  durationMs: number;
}

/**
 * Group of duplicate entries.
 */
export interface DuplicateGroup {
  /** Entries in this duplicate group */
  entries: MemoryEntry[];

  /** Similarity score (0.0-1.0) */
  similarity: number;
}
