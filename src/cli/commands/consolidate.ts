/**
 * Consolidate Command - Periodic memory consolidation
 */

import type { KVMemory } from '../../core/kv-memory.js';
import { createSleepCompressor } from '../../core/sleep-compressor.js';

export interface ConsolidateCommandOptions {
  /** Memory store instance */
  memory: KVMemory;
}

export interface ConsolidateCommandResult {
  /** Entries before consolidation */
  entriesBefore: number;
  /** Entries after consolidation */
  entriesAfter: number;
  /** Decayed entries removed */
  decayedRemoved: number;
  /** Duplicate entries merged */
  duplicatesRemoved: number;
  /** Compression ratio (0.0-1.0) */
  compressionRatio: number;
  /** Duration in milliseconds */
  durationMs: number;
  /** VACUUM completed */
  vacuumCompleted: boolean;
}

/**
 * Execute the consolidate command
 * @param options - Command options
 * @returns Consolidation result
 */
export async function consolidateCommand(
  options: ConsolidateCommandOptions,
): Promise<ConsolidateCommandResult> {
  const { memory } = options;

  // Get all entries from memory
  const allIds = await memory.list();
  const allEntries = await Promise.all(
    allIds.map(async (id) => {
      const entry = await memory.get(id);
      return entry;
    }),
  );

  // Filter out nulls
  const entries = allEntries.filter((e) => e !== null);

  // Run consolidation
  const compressor = createSleepCompressor();
  const result = compressor.consolidate(entries);

  // Update memory: remove old entries, keep consolidated ones
  for (const removed of result.removed) {
    await memory.delete(removed.id);
  }

  for (const kept of result.kept) {
    await memory.put(kept);
  }

  // Run VACUUM to reclaim space
  await memory.compact();

  return {
    entriesBefore: result.entriesBefore,
    entriesAfter: result.entriesAfter,
    decayedRemoved: result.decayedRemoved,
    duplicatesRemoved: result.duplicatesRemoved,
    compressionRatio: result.compressionRatio,
    durationMs: result.durationMs,
    vacuumCompleted: true,
  };
}
