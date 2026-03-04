/**
 * Shared TF-IDF utilities
 *
 * Centralized text tokenization and TF-IDF scoring used by
 * sparse-pruner, budget-pruner, incremental-optimizer, and sleep-compressor.
 */

import type { MemoryEntry } from '../types/memory.js';

/**
 * Tokenize text into lowercase words
 */
export function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .split(/\s+/)
    .filter((word) => word.length > 0);
}

/**
 * Calculate term frequency with sqrt capping
 */
export function calculateTF(term: string, tokens: string[]): number {
  const count = tokens.filter((t) => t === term).length;
  return Math.sqrt(count);
}

/**
 * Calculate inverse document frequency across entries
 */
export function calculateIDF(term: string, allEntries: MemoryEntry[]): number {
  const totalDocs = allEntries.length;
  const docsWithTerm = allEntries.filter((entry) => {
    const tokens = tokenize(entry.content);
    return tokens.includes(term);
  }).length;

  if (docsWithTerm === 0) return 0;

  return Math.log(totalDocs / docsWithTerm);
}

/**
 * Calculate TF-IDF score for an entry relative to a corpus
 */
export function calculateTFIDF(entry: MemoryEntry, allEntries: MemoryEntry[]): number {
  const tokens = tokenize(entry.content);
  if (tokens.length === 0) return 0;

  const uniqueTerms = [...new Set(tokens)];
  let totalScore = 0;

  for (const term of uniqueTerms) {
    const tf = calculateTF(term, tokens);
    const idf = calculateIDF(term, allEntries);
    totalScore += tf * idf;
  }

  // Normalize by entry length
  return totalScore / tokens.length;
}

/**
 * Pre-computed TF-IDF index for O(1) document frequency lookups.
 * Eliminates O(n^2) bottleneck when scoring multiple entries.
 */
export interface TFIDFIndex {
  /** Map of term -> number of documents containing the term */
  documentFrequency: Map<string, number>;
  /** Total number of documents in the corpus */
  totalDocuments: number;
}

/**
 * Build a pre-computed TF-IDF index from a set of entries.
 * Iterates all entries once to build document frequency map.
 *
 * @param entries - Corpus of memory entries
 * @returns Pre-computed index for use with scoreTFIDF()
 */
export function createTFIDFIndex(entries: MemoryEntry[]): TFIDFIndex {
  const documentFrequency = new Map<string, number>();

  for (const entry of entries) {
    const tokens = tokenize(entry.content);
    const uniqueTerms = new Set(tokens);

    for (const term of uniqueTerms) {
      documentFrequency.set(term, (documentFrequency.get(term) || 0) + 1);
    }
  }

  return {
    documentFrequency,
    totalDocuments: entries.length,
  };
}

/**
 * Score an entry using a pre-computed TF-IDF index.
 * Uses pre-computed document frequencies instead of re-tokenizing all entries.
 *
 * @param entry - Entry to score
 * @param index - Pre-computed TF-IDF index from createTFIDFIndex()
 * @returns TF-IDF score (higher = more distinctive)
 */
export function scoreTFIDF(entry: MemoryEntry, index: TFIDFIndex): number {
  const tokens = tokenize(entry.content);
  if (tokens.length === 0) return 0;

  const uniqueTerms = new Set(tokens);
  let totalScore = 0;

  for (const term of uniqueTerms) {
    const tf = calculateTF(term, tokens);
    const docsWithTerm = index.documentFrequency.get(term) || 0;

    if (docsWithTerm === 0) continue;

    const idf = Math.log(index.totalDocuments / docsWithTerm);
    totalScore += tf * idf;
  }

  // Normalize by entry length
  return totalScore / tokens.length;
}
