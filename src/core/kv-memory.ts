/**
 * KV Memory Store Module
 * Key-value storage with dual index/value tables.
 * Separates what to store (content) from how to retrieve it (index with scores and state).
 */

import { copyFileSync, existsSync } from 'node:fs';
import Database from 'better-sqlite3';
import type { MemoryEntry, MemoryQueryFilters } from '../types/memory.js';

/**
 * Optimization statistics record.
 */
export interface OptimizationStats {
  id: number;
  timestamp: number;
  tokens_before: number;
  tokens_after: number;
  entries_pruned: number;
  duration_ms: number;
}

/**
 * KV Memory interface.
 */
/**
 * FTS5 search result with rank score.
 */
export interface FTSResult {
  entry: MemoryEntry;
  rank: number;
}

export interface KVMemory {
  /** Store a memory entry */
  put(entry: MemoryEntry): Promise<void>;

  /** Retrieve a memory entry by ID */
  get(id: string): Promise<MemoryEntry | null>;

  /** Query entries by filters */
  query(filters: MemoryQueryFilters): Promise<MemoryEntry[]>;

  /** Delete a memory entry */
  delete(id: string): Promise<void>;

  /** List all entry IDs */
  list(): Promise<string[]>;

  /** Compact database (remove expired entries) */
  compact(): Promise<number>;

  /** Close database connection */
  close(): Promise<void>;

  /** Record optimization statistics */
  recordOptimization(stats: Omit<OptimizationStats, 'id'>): Promise<void>;

  /** Get all optimization statistics */
  getOptimizationStats(): Promise<OptimizationStats[]>;

  /** Clear all optimization statistics */
  clearOptimizationStats(): Promise<void>;

  /** Full-text search using FTS5 */
  searchFTS(query: string, limit?: number): Promise<FTSResult[]>;
}

/**
 * Create a timestamped backup of the database
 * @param dbPath - Path to database file
 * @returns Path to backup file
 */
function createBackup(dbPath: string): string {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupPath = `${dbPath}.backup-${timestamp}`;

  try {
    copyFileSync(dbPath, backupPath);
    process.stderr.write(`✓ Database backed up to: ${backupPath}\n`);
    return backupPath;
  } catch (error) {
    process.stderr.write(`Warning: Could not create backup: ${error}\n`);
    return '';
  }
}

/**
 * Create KV Memory store with SQLite backend.
 *
 * Initializes database with dual table schema:
 * - entries_index: Fast lookups (id, hash, timestamp, score, ttl, state, accessCount, isBTSP)
 * - entries_value: Content storage (id, content, tags, metadata)
 *
 * @param dbPath - Path to SQLite database file
 * @returns KVMemory instance
 */
export async function createKVMemory(dbPath: string): Promise<KVMemory> {
  // Detect database corruption and create backup
  let db: Database.Database;
  try {
    db = new Database(dbPath);

    // Quick integrity check
    const integrityCheck = db.pragma('quick_check', { simple: true });
    if (integrityCheck !== 'ok') {
      process.stderr.write('⚠ Database corruption detected!\n');

      // Close corrupted db before backup/recovery
      db.close();

      // Create backup before attempting recovery
      if (existsSync(dbPath)) {
        const backupPath = createBackup(dbPath);
        if (backupPath) {
          process.stderr.write(`Backup created at: ${backupPath}\n`);
        }
      }

      // Try to recover
      process.stderr.write('Attempting database recovery...\n');
      db = new Database(dbPath);
    }
  } catch (error) {
    process.stderr.write(`⚠ Database error detected: ${error}\n`);

    // Create backup if database exists
    if (existsSync(dbPath)) {
      createBackup(dbPath);
      process.stderr.write('Creating new database...\n');
    }

    db = new Database(dbPath);
  }

  // Enable WAL mode for better concurrency
  db.pragma('journal_mode = WAL');

  // Enable foreign key enforcement (SQLite disables by default)
  db.pragma('foreign_keys = ON');

  // Create entries_index table
  db.exec(`
    CREATE TABLE IF NOT EXISTS entries_index (
      id TEXT PRIMARY KEY NOT NULL,
      hash TEXT UNIQUE NOT NULL,
      timestamp INTEGER NOT NULL,
      score REAL NOT NULL DEFAULT 0.0 CHECK(score >= 0.0 AND score <= 1.0),
      ttl INTEGER NOT NULL CHECK(ttl >= 0),
      state TEXT NOT NULL CHECK(state IN ('silent', 'ready', 'active')),
      accessCount INTEGER NOT NULL DEFAULT 0 CHECK(accessCount >= 0),
      isBTSP INTEGER NOT NULL DEFAULT 0 CHECK(isBTSP IN (0, 1)),
      created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
    );
  `);

  // Create entries_value table
  db.exec(`
    CREATE TABLE IF NOT EXISTS entries_value (
      id TEXT PRIMARY KEY NOT NULL,
      content TEXT NOT NULL,
      tags TEXT,
      metadata TEXT,
      FOREIGN KEY (id) REFERENCES entries_index(id) ON DELETE CASCADE
    );
  `);

  // Create optimization_stats table
  db.exec(`
    CREATE TABLE IF NOT EXISTS optimization_stats (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
      tokens_before INTEGER NOT NULL,
      tokens_after INTEGER NOT NULL,
      entries_pruned INTEGER NOT NULL,
      duration_ms INTEGER NOT NULL
    );
  `);

  // Create indexes
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_entries_state ON entries_index(state);
    CREATE INDEX IF NOT EXISTS idx_entries_score ON entries_index(score DESC);
    CREATE INDEX IF NOT EXISTS idx_entries_hash ON entries_index(hash);
    CREATE INDEX IF NOT EXISTS idx_entries_timestamp ON entries_index(timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_stats_timestamp ON optimization_stats(timestamp DESC);
  `);

  // Create FTS5 virtual table for full-text search
  db.exec(`
    CREATE VIRTUAL TABLE IF NOT EXISTS entries_fts USING fts5(id, content, tokenize='porter');
  `);

  // Create triggers to keep FTS in sync
  // Note: triggers use INSERT OR REPLACE pattern since FTS5 doesn't support UPSERT
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS entries_fts_insert
    AFTER INSERT ON entries_value
    BEGIN
      INSERT OR REPLACE INTO entries_fts(id, content) VALUES (NEW.id, NEW.content);
    END;
  `);

  db.exec(`
    CREATE TRIGGER IF NOT EXISTS entries_fts_delete
    AFTER DELETE ON entries_value
    BEGIN
      DELETE FROM entries_fts WHERE id = OLD.id;
    END;
  `);

  db.exec(`
    CREATE TRIGGER IF NOT EXISTS entries_fts_update
    AFTER UPDATE ON entries_value
    BEGIN
      DELETE FROM entries_fts WHERE id = OLD.id;
      INSERT INTO entries_fts(id, content) VALUES (NEW.id, NEW.content);
    END;
  `);

  // Backfill existing data into FTS table
  db.exec(`
    INSERT OR IGNORE INTO entries_fts(id, content)
    SELECT id, content FROM entries_value
    WHERE id NOT IN (SELECT id FROM entries_fts);
  `);

  // Prepare statements for better performance
  const putIndexStmt = db.prepare(`
    INSERT OR REPLACE INTO entries_index
    (id, hash, timestamp, score, ttl, state, accessCount, isBTSP)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const putValueStmt = db.prepare(`
    INSERT OR REPLACE INTO entries_value
    (id, content, tags, metadata)
    VALUES (?, ?, ?, ?)
  `);

  const getStmt = db.prepare(`
    SELECT
      i.id, i.hash, i.timestamp, i.score, i.ttl, i.state, i.accessCount, i.isBTSP,
      v.content, v.tags, v.metadata
    FROM entries_index i
    JOIN entries_value v ON i.id = v.id
    WHERE i.id = ?
  `);

  const deleteIndexStmt = db.prepare('DELETE FROM entries_index WHERE id = ?');
  const deleteValueStmt = db.prepare('DELETE FROM entries_value WHERE id = ?');

  return {
    async put(entry: MemoryEntry): Promise<void> {
      const transaction = db.transaction(() => {
        putIndexStmt.run(
          entry.id,
          entry.hash,
          entry.timestamp,
          entry.score,
          entry.ttl,
          entry.state,
          entry.accessCount,
          entry.isBTSP ? 1 : 0,
        );

        putValueStmt.run(
          entry.id,
          entry.content,
          JSON.stringify(entry.tags),
          JSON.stringify(entry.metadata),
        );
      });

      transaction();
    },

    async get(id: string): Promise<MemoryEntry | null> {
      const row = getStmt.get(id) as unknown;

      if (!row) {
        return null;
      }

      const r = row as {
        id: string;
        hash: string;
        timestamp: number;
        score: number;
        ttl: number;
        state: string;
        accessCount: number;
        isBTSP: number;
        content: string;
        tags: string | null;
        metadata: string | null;
      };

      return {
        id: r.id,
        content: r.content,
        hash: r.hash,
        timestamp: r.timestamp,
        score: r.score,
        ttl: r.ttl,
        state: r.state as 'silent' | 'ready' | 'active',
        accessCount: r.accessCount,
        tags: r.tags ? JSON.parse(r.tags) : [],
        metadata: r.metadata ? JSON.parse(r.metadata) : {},
        isBTSP: r.isBTSP === 1,
      };
    },

    async query(filters: MemoryQueryFilters): Promise<MemoryEntry[]> {
      let sql = `
        SELECT
          i.id, i.hash, i.timestamp, i.score, i.ttl, i.state, i.accessCount, i.isBTSP,
          v.content, v.tags, v.metadata
        FROM entries_index i
        JOIN entries_value v ON i.id = v.id
        WHERE 1=1
      `;

      const params: unknown[] = [];

      if (filters.state) {
        sql += ' AND i.state = ?';
        params.push(filters.state);
      }

      if (filters.minScore !== undefined) {
        sql += ' AND i.score >= ?';
        params.push(filters.minScore);
      }

      if (filters.maxScore !== undefined) {
        sql += ' AND i.score <= ?';
        params.push(filters.maxScore);
      }

      if (filters.isBTSP !== undefined) {
        sql += ' AND i.isBTSP = ?';
        params.push(filters.isBTSP ? 1 : 0);
      }

      if (filters.tags && filters.tags.length > 0) {
        for (const tag of filters.tags) {
          sql += ' AND v.tags LIKE ?';
          params.push(`%"${tag}"%`);
        }
      }

      sql += ' ORDER BY i.score DESC';

      if (filters.limit) {
        sql += ' LIMIT ?';
        params.push(filters.limit);

        if (filters.offset) {
          sql += ' OFFSET ?';
          params.push(filters.offset);
        }
      }

      const stmt = db.prepare(sql);
      const rows = stmt.all(...params) as unknown[];

      return rows.map((row) => {
        const r = row as {
          id: string;
          hash: string;
          timestamp: number;
          score: number;
          ttl: number;
          state: string;
          accessCount: number;
          isBTSP: number;
          content: string;
          tags: string | null;
          metadata: string | null;
        };

        return {
          id: r.id,
          content: r.content,
          hash: r.hash,
          timestamp: r.timestamp,
          score: r.score,
          ttl: r.ttl,
          state: r.state as 'silent' | 'ready' | 'active',
          accessCount: r.accessCount,
          tags: r.tags ? JSON.parse(r.tags) : [],
          metadata: r.metadata ? JSON.parse(r.metadata) : {},
          isBTSP: r.isBTSP === 1,
        };
      });
    },

    async delete(id: string): Promise<void> {
      const transaction = db.transaction(() => {
        deleteIndexStmt.run(id);
        deleteValueStmt.run(id);
      });

      transaction();
    },

    async list(): Promise<string[]> {
      const stmt = db.prepare('SELECT id FROM entries_index');
      const rows = stmt.all() as { id: string }[];
      return rows.map((r) => r.id);
    },

    async compact(): Promise<number> {
      const before = db.prepare('SELECT COUNT(*) as count FROM entries_index').get() as {
        count: number;
      };

      // Remove expired non-BTSP entries: timestamp (ms) + ttl (seconds)*1000 < now
      const now = Date.now();
      db.prepare('DELETE FROM entries_index WHERE isBTSP = 0 AND (timestamp + ttl * 1000) < ?').run(
        now,
      );

      // Also remove non-BTSP entries with zero TTL
      db.exec('DELETE FROM entries_index WHERE isBTSP = 0 AND ttl <= 0');

      // Decay-based removal: remove non-BTSP entries with decay >= 0.95
      const candidates = db
        .prepare('SELECT id, timestamp, ttl FROM entries_index WHERE isBTSP = 0')
        .all() as Array<{ id: string; timestamp: number; ttl: number }>;

      for (const row of candidates) {
        const ageSeconds = Math.max(0, (now - row.timestamp) / 1000);
        const ttlSeconds = row.ttl;
        if (ttlSeconds <= 0) continue;
        const decay = 1 - Math.exp(-ageSeconds / ttlSeconds);
        if (decay >= 0.95) {
          db.prepare('DELETE FROM entries_index WHERE id = ?').run(row.id);
        }
      }

      // Clean up orphaned value entries
      db.exec('DELETE FROM entries_value WHERE id NOT IN (SELECT id FROM entries_index)');

      db.exec('VACUUM');

      const after = db.prepare('SELECT COUNT(*) as count FROM entries_index').get() as {
        count: number;
      };

      return before.count - after.count;
    },

    async close(): Promise<void> {
      db.close();
    },

    async recordOptimization(stats: Omit<OptimizationStats, 'id'>): Promise<void> {
      const stmt = db.prepare(`
        INSERT INTO optimization_stats (timestamp, tokens_before, tokens_after, entries_pruned, duration_ms)
        VALUES (?, ?, ?, ?, ?)
      `);

      stmt.run(
        stats.timestamp,
        stats.tokens_before,
        stats.tokens_after,
        stats.entries_pruned,
        stats.duration_ms,
      );

      // Retain only last 1000 stats to prevent unbounded growth
      db.prepare(
        'DELETE FROM optimization_stats WHERE id NOT IN (SELECT id FROM optimization_stats ORDER BY timestamp DESC LIMIT 1000)',
      ).run();
    },

    async getOptimizationStats(): Promise<OptimizationStats[]> {
      const stmt = db.prepare(`
        SELECT id, timestamp, tokens_before, tokens_after, entries_pruned, duration_ms
        FROM optimization_stats
        ORDER BY timestamp DESC
      `);

      const rows = stmt.all() as OptimizationStats[];
      return rows;
    },

    async clearOptimizationStats(): Promise<void> {
      db.exec('DELETE FROM optimization_stats');
    },

    async searchFTS(query: string, limit = 10): Promise<FTSResult[]> {
      if (!query || query.trim().length === 0) return [];

      // Sanitize query: strip FTS5 special characters to prevent syntax errors
      const sanitized = query.replace(/[{}()[\]"':*^~]/g, ' ').trim();
      if (sanitized.length === 0) return [];

      const stmt = db.prepare(`
        SELECT
          f.id, f.content, rank,
          i.hash, i.timestamp, i.score, i.ttl, i.state, i.accessCount, i.isBTSP,
          v.tags, v.metadata
        FROM entries_fts f
        JOIN entries_index i ON f.id = i.id
        JOIN entries_value v ON f.id = v.id
        WHERE entries_fts MATCH ?
        ORDER BY rank
        LIMIT ?
      `);

      try {
        const rows = stmt.all(sanitized, limit) as Array<{
          id: string;
          content: string;
          rank: number;
          hash: string;
          timestamp: number;
          score: number;
          ttl: number;
          state: string;
          accessCount: number;
          isBTSP: number;
          tags: string | null;
          metadata: string | null;
        }>;

        return rows.map((r) => ({
          entry: {
            id: r.id,
            content: r.content,
            hash: r.hash,
            timestamp: r.timestamp,
            score: r.score,
            ttl: r.ttl,
            state: r.state as 'silent' | 'ready' | 'active',
            accessCount: r.accessCount,
            tags: r.tags ? JSON.parse(r.tags) : [],
            metadata: r.metadata ? JSON.parse(r.metadata) : {},
            isBTSP: r.isBTSP === 1,
          },
          rank: r.rank,
        }));
      } catch {
        // FTS query error (bad syntax despite sanitization) — return empty
        return [];
      }
    },
  };
}
