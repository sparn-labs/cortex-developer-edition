/**
 * Dashboard Stats — Pure function that reads .cortex/memory.db and formats
 * a compact dashboard summary for injection into Claude Code hooks.
 *
 * No React dependency. Opens DB connections in try/finally to ensure cleanup.
 */

import { existsSync, statSync } from 'node:fs';
import Database from 'better-sqlite3';

/**
 * Format a compact dashboard summary from the Cortex database.
 *
 * @param dbPath - Path to .cortex/memory.db
 * @param _projectRoot - Project root (reserved for future use)
 * @returns Formatted dashboard string, or null if DB doesn't exist
 */
export function formatDashboardStats(dbPath: string, _projectRoot: string): string | null {
  if (!existsSync(dbPath)) {
    return null;
  }

  let db: Database.Database | null = null;
  try {
    db = new Database(dbPath, { readonly: true });

    const lines: string[] = [];

    // --- Entry count + state distribution ---
    const entryCount = getEntryCount(db);
    const stateDistribution = getStateDistribution(db);
    const dbSizeBytes = statSync(dbPath).size;
    const dbSizeMB = (dbSizeBytes / (1024 * 1024)).toFixed(1);

    const stateParts = Object.entries(stateDistribution)
      .filter(([, count]) => count > 0)
      .map(([state, count]) => `${capitalize(state)}:${count}`)
      .join(' ');

    lines.push(
      `[cortex-dashboard] Entries: ${entryCount} (${stateParts || 'none'}) | DB: ${dbSizeMB}MB`,
    );

    // --- Optimization stats ---
    const optStats = getOptimizationStats(db);
    if (optStats.total > 0) {
      const savedTokens = formatTokens(optStats.totalSaved);
      lines.push(
        `[cortex-dashboard] Optimizations: ${optStats.total} total | Saved: ${savedTokens} tokens | Avg: ${optStats.avgReduction.toFixed(1)}%`,
      );

      if (optStats.recent.length > 0) {
        const recentParts = optStats.recent
          .map((r) => `${r.reduction.toFixed(1)}% (${r.durationMs}ms)`)
          .join(' | ');
        lines.push(`[cortex-dashboard] Last ${optStats.recent.length}: ${recentParts}`);
      }
    }

    // --- Debt stats ---
    const debtStats = getDebtStats(db);
    if (debtStats.open > 0 || debtStats.overdue > 0) {
      lines.push(
        `[cortex-dashboard] Debt: ${debtStats.open} open${debtStats.overdue > 0 ? `, ${debtStats.overdue} overdue` : ''}`,
      );
    }

    return lines.length > 0 ? lines.join('\n') : null;
  } catch {
    return null;
  } finally {
    if (db) {
      try {
        db.close();
      } catch {
        // ignore close errors
      }
    }
  }
}

function getEntryCount(db: Database.Database): number {
  try {
    const row = db.prepare('SELECT COUNT(*) as count FROM entries_index').get() as
      | { count: number }
      | undefined;
    return row?.count ?? 0;
  } catch {
    return 0;
  }
}

function getStateDistribution(db: Database.Database): Record<string, number> {
  const result: Record<string, number> = { active: 0, ready: 0, silent: 0 };
  try {
    const rows = db
      .prepare('SELECT state, COUNT(*) as count FROM entries_index GROUP BY state')
      .all() as Array<{ state: string; count: number }>;
    for (const row of rows) {
      result[row.state] = row.count;
    }
  } catch {
    // table may not exist yet
  }
  return result;
}

interface RecentOptStat {
  reduction: number;
  durationMs: number;
}

function getOptimizationStats(db: Database.Database): {
  total: number;
  totalSaved: number;
  avgReduction: number;
  recent: RecentOptStat[];
} {
  const empty = { total: 0, totalSaved: 0, avgReduction: 0, recent: [] as RecentOptStat[] };
  try {
    const rows = db
      .prepare(
        'SELECT tokens_before, tokens_after, duration_ms FROM optimization_stats ORDER BY timestamp DESC',
      )
      .all() as Array<{ tokens_before: number; tokens_after: number; duration_ms: number }>;

    if (rows.length === 0) return empty;

    let totalSaved = 0;
    let totalReduction = 0;

    for (const row of rows) {
      const saved = row.tokens_before - row.tokens_after;
      totalSaved += saved;
      if (row.tokens_before > 0) {
        totalReduction += (saved / row.tokens_before) * 100;
      }
    }

    const recent = rows.slice(0, 3).map((row) => ({
      reduction:
        row.tokens_before > 0
          ? ((row.tokens_before - row.tokens_after) / row.tokens_before) * 100
          : 0,
      durationMs: row.duration_ms,
    }));

    return {
      total: rows.length,
      totalSaved,
      avgReduction: totalReduction / rows.length,
      recent,
    };
  } catch {
    return empty;
  }
}

function getDebtStats(db: Database.Database): { open: number; overdue: number } {
  try {
    const openRow = db
      .prepare("SELECT COUNT(*) as count FROM tech_debt WHERE status != 'resolved'")
      .get() as { count: number } | undefined;
    const overdueRow = db
      .prepare(
        "SELECT COUNT(*) as count FROM tech_debt WHERE status != 'resolved' AND repayment_date < ?",
      )
      .get(Date.now()) as { count: number } | undefined;
    return {
      open: openRow?.count ?? 0,
      overdue: overdueRow?.count ?? 0,
    };
  } catch {
    return { open: 0, overdue: 0 };
  }
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function formatTokens(n: number): string {
  if (n >= 1000) {
    return `${(n / 1000).toFixed(1)}K`;
  }
  return String(n);
}
