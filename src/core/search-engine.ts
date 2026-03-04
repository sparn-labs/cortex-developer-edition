/**
 * Search Engine - Hybrid FTS5 + ripgrep search
 *
 * Deterministic search without embeddings:
 * 1. FTS5 for full-text search with stemming (porter tokenizer)
 * 2. ripgrep fallback for exact pattern/regex matching
 * 3. Fusion scoring with dedup across both sources
 */

import { execFileSync, execSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { extname, join, relative } from 'node:path';
import Database from 'better-sqlite3';

export interface SearchResult {
  filePath: string;
  lineNumber: number;
  content: string;
  score: number;
  context: string[];
  engram_score: number;
}

export interface SearchOpts {
  maxResults?: number;
  fileGlob?: string;
  useRipgrep?: boolean;
  includeContext?: boolean;
}

export interface IndexStats {
  filesIndexed: number;
  totalLines: number;
  duration: number;
}

export interface SearchEngine {
  /** Initialize the search database */
  init(projectRoot: string): Promise<void>;

  /** Index files into FTS5 */
  index(paths?: string[]): Promise<IndexStats>;

  /** Search using hybrid FTS5 + ripgrep */
  search(query: string, opts?: SearchOpts): Promise<SearchResult[]>;

  /** Re-index all files */
  refresh(): Promise<IndexStats>;

  /** Close the database */
  close(): Promise<void>;
}

/**
 * Check if ripgrep is available
 */
function hasRipgrep(): boolean {
  try {
    execSync('rg --version', { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

/**
 * Run ripgrep search
 */
function ripgrepSearch(query: string, projectRoot: string, opts: SearchOpts = {}): SearchResult[] {
  try {
    const args = ['--line-number', '--no-heading', '--color=never'];

    if (opts.fileGlob) {
      args.push('--glob', opts.fileGlob);
    }

    // Ignore common dirs
    args.push(
      '--glob',
      '!node_modules',
      '--glob',
      '!dist',
      '--glob',
      '!.git',
      '--glob',
      '!.cortex',
      '--glob',
      '!coverage',
    );

    const maxResults = opts.maxResults || 20;
    args.push('--max-count', String(maxResults));

    // Include context lines
    if (opts.includeContext) {
      args.push('-C', '2');
    }

    // Use execFileSync to avoid shell injection - args passed as array
    args.push('--', query, projectRoot);
    const output = execFileSync('rg', args, { encoding: 'utf-8', maxBuffer: 10 * 1024 * 1024 });

    const results: SearchResult[] = [];
    const lines = output.split('\n').filter(Boolean);

    for (const line of lines) {
      // Parse rg output: file:line:content
      const match = line.match(/^(.+?):(\d+):(.*)/);
      if (match) {
        const filePath = relative(projectRoot, match[1] || '').replace(/\\/g, '/');
        const lineNumber = Number.parseInt(match[2] || '0', 10);
        const content = (match[3] || '').trim();

        results.push({
          filePath,
          lineNumber,
          content,
          score: 0.8, // Exact match gets high base score
          context: [],
          engram_score: 0,
        });
      }
    }

    return results.slice(0, maxResults);
  } catch {
    return [];
  }
}

/**
 * Collect indexable files from a directory
 */
function collectIndexableFiles(
  dir: string,
  projectRoot: string,
  ignoreDirs = ['node_modules', 'dist', '.git', '.cortex', 'coverage'],
  exts = ['.ts', '.tsx', '.js', '.jsx', '.json', '.md', '.yaml', '.yml'],
): string[] {
  const files: string[] = [];

  try {
    const entries = readdirSync(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = join(dir, entry.name);

      if (entry.isDirectory()) {
        if (!ignoreDirs.includes(entry.name)) {
          files.push(...collectIndexableFiles(fullPath, projectRoot, ignoreDirs, exts));
        }
      } else if (entry.isFile() && exts.includes(extname(entry.name))) {
        // Skip large files (>100KB)
        try {
          const stat = statSync(fullPath);
          if (stat.size < 100 * 1024) {
            files.push(relative(projectRoot, fullPath).replace(/\\/g, '/'));
          }
        } catch {
          // Skip
        }
      }
    }
  } catch {
    // Skip inaccessible directories
  }

  return files;
}

/**
 * Create a search engine instance
 */
export function createSearchEngine(dbPath: string): SearchEngine {
  let db: Database.Database | null = null;
  let projectRoot = '';
  const rgAvailable = hasRipgrep();

  async function init(root: string): Promise<void> {
    // Close existing connection if re-initializing
    if (db) {
      try {
        db.close();
      } catch {
        /* ignore */
      }
    }
    projectRoot = root;
    db = new Database(dbPath);
    db.pragma('journal_mode = WAL');

    // Create FTS5 virtual table
    db.exec(`
      CREATE VIRTUAL TABLE IF NOT EXISTS search_index USING fts5(
        filepath, line_number, content, tokenize='porter'
      );
    `);

    // Create metadata table for tracking index state
    db.exec(`
      CREATE TABLE IF NOT EXISTS search_meta (
        filepath TEXT PRIMARY KEY,
        mtime INTEGER NOT NULL,
        indexed_at INTEGER NOT NULL
      );
    `);
  }

  async function index(paths?: string[]): Promise<IndexStats> {
    if (!db) throw new Error('Search engine not initialized. Call init() first.');

    const startTime = Date.now();

    const filesToIndex = paths || collectIndexableFiles(projectRoot, projectRoot);

    let filesIndexed = 0;
    let totalLines = 0;

    const insertStmt = db.prepare(
      'INSERT INTO search_index(filepath, line_number, content) VALUES (?, ?, ?)',
    );
    const metaStmt = db.prepare(
      'INSERT OR REPLACE INTO search_meta(filepath, mtime, indexed_at) VALUES (?, ?, ?)',
    );
    const checkMeta = db.prepare('SELECT mtime FROM search_meta WHERE filepath = ?');
    const deleteFile = db.prepare('DELETE FROM search_index WHERE filepath = ?');

    const transaction = db.transaction(() => {
      for (const filePath of filesToIndex) {
        const fullPath = join(projectRoot, filePath);

        if (!existsSync(fullPath)) continue;

        try {
          const stat = statSync(fullPath);
          const existing = checkMeta.get(filePath) as { mtime: number } | undefined;

          // Skip if file hasn't changed
          if (existing && existing.mtime >= stat.mtimeMs) {
            continue;
          }

          // Remove old index entries for this file
          deleteFile.run(filePath);

          const content = readFileSync(fullPath, 'utf-8');
          const lines = content.split('\n');

          for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            if (line && line.trim().length > 0) {
              insertStmt.run(filePath, i + 1, line);
              totalLines++;
            }
          }

          metaStmt.run(filePath, stat.mtimeMs, Date.now());
          filesIndexed++;
        } catch {
          // Skip problematic files
        }
      }
    });

    transaction();

    return {
      filesIndexed,
      totalLines,
      duration: Date.now() - startTime,
    };
  }

  async function search(query: string, opts: SearchOpts = {}): Promise<SearchResult[]> {
    if (!db) throw new Error('Search engine not initialized. Call init() first.');

    const maxResults = opts.maxResults || 10;
    const results: SearchResult[] = [];
    const seen = new Set<string>(); // Dedup key: filepath:lineNumber

    // 1. FTS5 search
    try {
      // Escape FTS5 special characters and scope to content column
      const ftsQuery = query
        .replace(/['"*(){}[\]^~\\:]/g, ' ')
        .trim()
        .split(/\s+/)
        .filter((w) => w.length > 0)
        .map((w) => `content:${w}`)
        .join(' ');

      if (ftsQuery.length > 0) {
        let sql = `
          SELECT filepath, line_number, content, rank
          FROM search_index
          WHERE search_index MATCH ?
        `;
        const params: unknown[] = [ftsQuery];

        if (opts.fileGlob) {
          // Convert glob to LIKE pattern
          const likePattern = opts.fileGlob.replace(/\*/g, '%').replace(/\?/g, '_');
          sql += ' AND filepath LIKE ?';
          params.push(likePattern);
        }

        sql += ' ORDER BY rank LIMIT ?';
        params.push(maxResults * 2); // Fetch extra for dedup

        const rows = db.prepare(sql).all(...params) as Array<{
          filepath: string;
          line_number: number;
          content: string;
          rank: number;
        }>;

        for (const row of rows) {
          const key = `${row.filepath}:${row.line_number}`;
          if (!seen.has(key)) {
            seen.add(key);

            // FTS5 rank is negative (lower = better match)
            const score = Math.min(1, Math.max(0, 1 + row.rank / 10));

            const context: string[] = [];
            if (opts.includeContext) {
              // Get surrounding lines using CAST for numeric comparison
              const contextRows = db
                .prepare(
                  `SELECT content FROM search_index WHERE filepath = ? AND CAST(line_number AS INTEGER) BETWEEN ? AND ? ORDER BY CAST(line_number AS INTEGER)`,
                )
                .all(row.filepath, row.line_number - 2, row.line_number + 2) as Array<{
                content: string;
              }>;
              context.push(...contextRows.map((r) => r.content));
            }

            results.push({
              filePath: row.filepath,
              lineNumber: row.line_number,
              content: row.content,
              score,
              context,
              engram_score: 0,
            });
          }
        }
      }
    } catch {
      // FTS5 query failed, fall through to ripgrep
    }

    // 2. ripgrep search (if available and requested or as supplement)
    if (rgAvailable && opts.useRipgrep !== false) {
      const rgResults = ripgrepSearch(query, projectRoot, opts);

      for (const result of rgResults) {
        const key = `${result.filePath}:${result.lineNumber}`;
        if (!seen.has(key)) {
          seen.add(key);
          results.push(result);
        }
      }
    }

    // Sort by score descending and limit
    results.sort((a, b) => b.score - a.score);
    return results.slice(0, maxResults);
  }

  async function refresh(): Promise<IndexStats> {
    if (!db) throw new Error('Search engine not initialized. Call init() first.');

    // Clear all index data
    db.exec('DELETE FROM search_index');
    db.exec('DELETE FROM search_meta');

    return index();
  }

  async function close(): Promise<void> {
    if (db) {
      db.close();
      db = null;
    }
  }

  return {
    init,
    index,
    search,
    refresh,
    close,
  };
}
