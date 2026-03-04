/**
 * Content hashing utilities.
 * Uses SHA-256 for deduplication.
 */

import { createHash } from 'node:crypto';

/**
 * Generate SHA-256 hash of content for deduplication.
 *
 * @param content - Content to hash
 * @returns 64-character hex string (SHA-256)
 *
 * @example
 * ```typescript
 * const hash = hashContent('Hello world');
 * console.log(hash.length); // 64
 * ```
 */
export function hashContent(content: string): string {
  return createHash('sha256').update(content, 'utf8').digest('hex');
}
