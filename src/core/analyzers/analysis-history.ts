/**
 * Analysis History — SQLite-backed score history for trend tracking.
 *
 * Stores scores from each analysis run and provides trend computation.
 * Uses the same .cortex/memory.db database (new table).
 */

import Database from 'better-sqlite3';

export interface AnalysisHistoryEntry {
  id: number;
  timestamp: number;
  score: number;
  grade: string;
  categories: Record<string, { score: number; maxPoints: number }>;
  totalFiles: number;
  totalFindings: number;
  projectPath: string;
  mode: string;
}

export interface AnalysisHistory {
  record(entry: Omit<AnalysisHistoryEntry, 'id'>): AnalysisHistoryEntry;
  getRecent(limit?: number): AnalysisHistoryEntry[];
  getLastFull(): AnalysisHistoryEntry | null;
  close(): void;
}

const MAX_ENTRIES = 500;

export function createAnalysisHistory(dbPath: string): AnalysisHistory {
  const db = new Database(dbPath);
  let closed = false;

  try {
    db.pragma('journal_mode = WAL');

    db.exec(`
      CREATE TABLE IF NOT EXISTS analysis_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER NOT NULL,
        score REAL NOT NULL,
        grade TEXT NOT NULL,
        categories TEXT NOT NULL,
        total_files INTEGER NOT NULL,
        total_findings INTEGER NOT NULL,
        project_path TEXT NOT NULL,
        mode TEXT NOT NULL DEFAULT 'full'
      );
    `);

    db.exec(`
      CREATE INDEX IF NOT EXISTS idx_analysis_history_ts ON analysis_history(timestamp);
      CREATE INDEX IF NOT EXISTS idx_analysis_history_mode ON analysis_history(mode);
    `);
  } catch (err) {
    db.close();
    throw err;
  }

  const insertStmt = db.prepare(`
    INSERT INTO analysis_history (timestamp, score, grade, categories, total_files, total_findings, project_path, mode)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const recentStmt = db.prepare('SELECT * FROM analysis_history ORDER BY timestamp DESC LIMIT ?');

  const lastFullStmt = db.prepare(
    "SELECT * FROM analysis_history WHERE mode = 'full' ORDER BY timestamp DESC LIMIT 1",
  );

  const countStmt = db.prepare('SELECT COUNT(*) as cnt FROM analysis_history');

  const pruneStmt = db.prepare(
    `DELETE FROM analysis_history WHERE id NOT IN (
      SELECT id FROM analysis_history ORDER BY timestamp DESC LIMIT ?
    )`,
  );

  function ensureOpen(): void {
    if (closed) throw new Error('AnalysisHistory is already closed');
  }

  function rowToEntry(row: Record<string, unknown>): AnalysisHistoryEntry {
    let categories: Record<string, { score: number; maxPoints: number }> = {};
    try {
      categories = JSON.parse((row['categories'] as string) || '{}');
    } catch {
      // Corrupt JSON — default to empty
    }

    return {
      id: row['id'] as number,
      timestamp: row['timestamp'] as number,
      score: row['score'] as number,
      grade: row['grade'] as string,
      categories,
      totalFiles: row['total_files'] as number,
      totalFindings: row['total_findings'] as number,
      projectPath: row['project_path'] as string,
      mode: row['mode'] as string,
    };
  }

  return {
    record(entry: Omit<AnalysisHistoryEntry, 'id'>): AnalysisHistoryEntry {
      ensureOpen();
      const result = insertStmt.run(
        entry.timestamp,
        entry.score,
        entry.grade,
        JSON.stringify(entry.categories),
        entry.totalFiles,
        entry.totalFindings,
        entry.projectPath,
        entry.mode,
      );

      // Auto-prune to MAX_ENTRIES
      const { cnt } = countStmt.get() as { cnt: number };
      if (cnt > MAX_ENTRIES) {
        pruneStmt.run(MAX_ENTRIES);
      }

      return { ...entry, id: Number(result.lastInsertRowid) };
    },

    getRecent(limit = 10): AnalysisHistoryEntry[] {
      ensureOpen();
      const safeLimit = Math.max(1, Math.min(limit, MAX_ENTRIES));
      const rows = recentStmt.all(safeLimit) as Record<string, unknown>[];
      return rows.map(rowToEntry);
    },

    getLastFull(): AnalysisHistoryEntry | null {
      ensureOpen();
      const row = lastFullStmt.get() as Record<string, unknown> | undefined;
      return row ? rowToEntry(row) : null;
    },

    close(): void {
      if (!closed) {
        closed = true;
        db.close();
      }
    },
  };
}

/**
 * Compute score trend delta between current and last full analysis.
 */
export function computeTrend(
  currentScore: number,
  lastEntry: AnalysisHistoryEntry | null,
): { delta: number; label: string } | null {
  if (!lastEntry) return null;
  const delta = Math.round((currentScore - lastEntry.score) * 10) / 10;
  if (delta === 0) return { delta: 0, label: '(no change)' };
  const sign = delta > 0 ? '+' : '';
  return { delta, label: `(${sign}${delta} since last run)` };
}
