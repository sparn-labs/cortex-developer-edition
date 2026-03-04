/**
 * Core memory entry types for Cortex's context optimization engine.
 * Memory model with time-based decay and state transitions.
 */

/**
 * Confidence state for memory entries.
 * Entries are classified as silent, ready, or active based on score.
 */
export type ConfidenceState = 'silent' | 'ready' | 'active';

/**
 * Represents a single context memory entry with optimization metadata.
 *
 * State transitions:
 * - score ≤ 0.3 → silent (not included in context)
 * - 0.3 < score ≤ 0.7 → ready (included if space permits)
 * - score > 0.7 → active (always included)
 * - isBTSP = true → active (bypass score check)
 */
export interface MemoryEntry {
  /** Unique identifier (UUID v4) */
  id: string;

  /** The actual memory content/context data */
  content: string;

  /** SHA-256 hash of content for deduplication */
  hash: string;

  /** Unix timestamp (seconds) of creation */
  timestamp: number;

  /** Current engram score (0.0-1.0) */
  score: number;

  /** Time-to-live in seconds remaining */
  ttl: number;

  /** Confidence state */
  state: ConfidenceState;

  /** Number of times accessed/retrieved */
  accessCount: number;

  /** User-defined tags for categorization */
  tags: string[];

  /** Additional key-value pairs */
  metadata: Record<string, unknown>;

  /** Flag indicating one-shot learned entry (BTSP) */
  isBTSP: boolean;
}

/**
 * Query filters for memory store operations.
 */
export interface MemoryQueryFilters {
  state?: ConfidenceState;
  minScore?: number;
  maxScore?: number;
  tags?: string[];
  isBTSP?: boolean;
  limit?: number;
  offset?: number;
}

/**
 * State distribution aggregation.
 */
export interface StateDistribution {
  active: number;
  ready: number;
  silent: number;
  total: number;
}
