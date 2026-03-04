/**
 * File Tracker - Incremental file reading with byte position tracking
 *
 * Tracks read positions for files to enable efficient incremental reading.
 * Handles JSONL partial line buffering for incomplete writes.
 *
 * Use case: Monitor Claude Code session JSONL files and only read new lines
 * as they're appended, without re-reading the entire file.
 */

import { closeSync, openSync, readSync, statSync } from 'node:fs';

export interface FilePosition {
  /** File path */
  path: string;
  /** Last read byte position */
  position: number;
  /** Partial line buffer (for JSONL incomplete writes) */
  partialLine: string;
  /** Last modification time */
  lastModified: number;
  /** File size at last read */
  lastSize: number;
}

export interface FileTracker {
  /**
   * Read new content from file since last read
   * @param filePath - File to read
   * @returns New content as array of lines (empty if no new content)
   */
  readNewLines(filePath: string): string[];

  /**
   * Get current position for a file
   * @param filePath - File path
   * @returns File position or null if not tracked
   */
  getPosition(filePath: string): FilePosition | null;

  /**
   * Reset position for a file (start from beginning on next read)
   * @param filePath - File path
   */
  resetPosition(filePath: string): void;

  /**
   * Clear all tracked positions
   */
  clearAll(): void;

  /**
   * Get all tracked file paths
   * @returns Array of tracked file paths
   */
  getTrackedFiles(): string[];
}

/**
 * Create a file tracker instance
 * @returns FileTracker instance
 */
export function createFileTracker(): FileTracker {
  // Track positions by file path
  const positions = new Map<string, FilePosition>();

  function readNewLines(filePath: string): string[] {
    try {
      // Get current file stats
      const stats = statSync(filePath);
      const currentSize = stats.size;
      const currentModified = stats.mtimeMs;

      // Get or initialize position
      let pos = positions.get(filePath);

      if (!pos) {
        // First read: start from beginning
        pos = {
          path: filePath,
          position: 0,
          partialLine: '',
          lastModified: currentModified,
          lastSize: 0,
        };
        positions.set(filePath, pos);
      }

      // Check if file was truncated or is same size
      if (currentSize < pos.lastSize || currentSize === pos.position) {
        // File truncated or no new content
        if (currentSize < pos.lastSize) {
          // Reset position if truncated
          pos.position = 0;
          pos.partialLine = '';
        }
        return [];
      }

      // Read only new bytes from last position (delta read)
      const bytesToRead = currentSize - pos.position;
      const buffer = Buffer.alloc(bytesToRead);
      const fd = openSync(filePath, 'r');
      try {
        readSync(fd, buffer, 0, bytesToRead, pos.position);
      } finally {
        closeSync(fd);
      }

      // Convert to string and combine with partial line
      const newContent = (pos.partialLine + buffer.toString('utf-8')).split('\n');

      // Last element might be incomplete (no trailing newline yet)
      const partialLine = newContent.pop() || '';

      // Update position
      pos.position = currentSize;
      pos.partialLine = partialLine;
      pos.lastModified = currentModified;
      pos.lastSize = currentSize;

      // Return complete lines (filter empty)
      return newContent.filter((line) => line.trim().length > 0);
    } catch (_error) {
      // File doesn't exist or can't be read
      // Return empty array (fail silently for watcher use case)
      return [];
    }
  }

  function getPosition(filePath: string): FilePosition | null {
    return positions.get(filePath) || null;
  }

  function resetPosition(filePath: string): void {
    positions.delete(filePath);
  }

  function clearAll(): void {
    positions.clear();
  }

  function getTrackedFiles(): string[] {
    return Array.from(positions.keys());
  }

  return {
    readNewLines,
    getPosition,
    resetPosition,
    clearAll,
    getTrackedFiles,
  };
}
