/**
 * Debt Tracker - Technical debt management
 *
 * Tracks technical debt with mandatory repayment dates,
 * severity levels, and token cost estimates.
 * Stored in SQLite alongside the main memory.db.
 */

import { randomUUID } from 'node:crypto';
import Database from 'better-sqlite3';

export type DebtSeverity = 'P0' | 'P1' | 'P2';
export type DebtStatus = 'open' | 'in_progress' | 'resolved';

export interface TechDebt {
  id: string;
  description: string;
  created_at: number;
  repayment_date: number;
  severity: DebtSeverity;
  token_cost: number;
  files_affected: string[];
  status: DebtStatus;
  resolution_tokens?: number;
  resolved_at?: number;
}

export interface DebtStats {
  total: number;
  open: number;
  in_progress: number;
  resolved: number;
  overdue: number;
  totalTokenCost: number;
  resolvedTokenCost: number;
  repaymentRate: number;
}

export interface DebtTracker {
  /** Add a new tech debt item */
  add(debt: Omit<TechDebt, 'id' | 'created_at' | 'status'>): Promise<TechDebt>;

  /** List all debts, optionally filtered */
  list(filter?: {
    status?: DebtStatus;
    severity?: DebtSeverity;
    overdue?: boolean;
  }): Promise<TechDebt[]>;

  /** Get a specific debt by ID */
  get(id: string): Promise<TechDebt | null>;

  /** Update debt status */
  resolve(id: string, resolutionTokens?: number): Promise<void>;

  /** Update debt status to in_progress */
  start(id: string): Promise<void>;

  /** Delete a debt item */
  remove(id: string): Promise<void>;

  /** Get debt statistics */
  stats(): Promise<DebtStats>;

  /** Get P0 debts for CLAUDE.md inclusion */
  getCritical(): Promise<TechDebt[]>;

  /** Close database */
  close(): Promise<void>;
}

/**
 * Create a debt tracker instance
 */
export function createDebtTracker(dbPath: string): DebtTracker {
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');

  // Create debt table
  db.exec(`
    CREATE TABLE IF NOT EXISTS tech_debt (
      id TEXT PRIMARY KEY NOT NULL,
      description TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      repayment_date INTEGER NOT NULL,
      severity TEXT NOT NULL CHECK(severity IN ('P0', 'P1', 'P2')),
      token_cost INTEGER NOT NULL DEFAULT 0,
      files_affected TEXT NOT NULL DEFAULT '[]',
      status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'in_progress', 'resolved')),
      resolution_tokens INTEGER,
      resolved_at INTEGER
    );
  `);

  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_debt_status ON tech_debt(status);
    CREATE INDEX IF NOT EXISTS idx_debt_severity ON tech_debt(severity);
    CREATE INDEX IF NOT EXISTS idx_debt_repayment ON tech_debt(repayment_date);
  `);

  const insertStmt = db.prepare(`
    INSERT INTO tech_debt (id, description, created_at, repayment_date, severity, token_cost, files_affected, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'open')
  `);

  const getStmt = db.prepare('SELECT * FROM tech_debt WHERE id = ?');

  function rowToDebt(row: Record<string, unknown>): TechDebt {
    return {
      id: row['id'] as string,
      description: row['description'] as string,
      created_at: row['created_at'] as number,
      repayment_date: row['repayment_date'] as number,
      severity: row['severity'] as DebtSeverity,
      token_cost: row['token_cost'] as number,
      files_affected: JSON.parse((row['files_affected'] as string) || '[]'),
      status: row['status'] as DebtStatus,
      resolution_tokens: row['resolution_tokens'] as number | undefined,
      resolved_at: row['resolved_at'] as number | undefined,
    };
  }

  async function add(debt: Omit<TechDebt, 'id' | 'created_at' | 'status'>): Promise<TechDebt> {
    const id = randomUUID().split('-')[0] || 'debt';
    const created_at = Date.now();

    insertStmt.run(
      id,
      debt.description,
      created_at,
      debt.repayment_date,
      debt.severity,
      debt.token_cost,
      JSON.stringify(debt.files_affected),
    );

    return {
      id,
      created_at,
      status: 'open',
      description: debt.description,
      repayment_date: debt.repayment_date,
      severity: debt.severity,
      token_cost: debt.token_cost,
      files_affected: debt.files_affected,
    };
  }

  async function list(
    filter: { status?: DebtStatus; severity?: DebtSeverity; overdue?: boolean } = {},
  ): Promise<TechDebt[]> {
    let sql = 'SELECT * FROM tech_debt WHERE 1=1';
    const params: unknown[] = [];

    if (filter.status) {
      sql += ' AND status = ?';
      params.push(filter.status);
    }

    if (filter.severity) {
      sql += ' AND severity = ?';
      params.push(filter.severity);
    }

    if (filter.overdue) {
      sql += ' AND repayment_date < ? AND status != ?';
      params.push(Date.now());
      params.push('resolved');
    }

    sql += ' ORDER BY severity ASC, repayment_date ASC';

    const rows = db.prepare(sql).all(...params) as Array<Record<string, unknown>>;
    return rows.map(rowToDebt);
  }

  async function get(id: string): Promise<TechDebt | null> {
    const row = getStmt.get(id) as Record<string, unknown> | undefined;
    if (!row) return null;
    return rowToDebt(row);
  }

  async function resolve(id: string, resolutionTokens?: number): Promise<void> {
    const result = db
      .prepare(
        'UPDATE tech_debt SET status = ?, resolution_tokens = ?, resolved_at = ? WHERE id = ?',
      )
      .run('resolved', resolutionTokens ?? null, Date.now(), id);
    if (result.changes === 0) {
      throw new Error(`Debt not found: ${id}`);
    }
  }

  async function start(id: string): Promise<void> {
    const result = db
      .prepare('UPDATE tech_debt SET status = ? WHERE id = ?')
      .run('in_progress', id);
    if (result.changes === 0) {
      throw new Error(`Debt not found: ${id}`);
    }
  }

  async function remove(id: string): Promise<void> {
    db.prepare('DELETE FROM tech_debt WHERE id = ?').run(id);
  }

  async function stats(): Promise<DebtStats> {
    const all = db.prepare('SELECT * FROM tech_debt').all() as Array<Record<string, unknown>>;
    const debts = all.map(rowToDebt);

    const now = Date.now();
    const open = debts.filter((d) => d.status === 'open');
    const inProgress = debts.filter((d) => d.status === 'in_progress');
    const resolved = debts.filter((d) => d.status === 'resolved');
    const overdue = debts.filter((d) => d.status !== 'resolved' && d.repayment_date < now);

    const totalTokenCost = debts.reduce((sum, d) => sum + d.token_cost, 0);
    const resolvedTokenCost = resolved.reduce(
      (sum, d) => sum + (d.resolution_tokens || d.token_cost),
      0,
    );

    // Repayment rate: resolved on time / total resolved
    const resolvedOnTime = resolved.filter(
      (d) => d.resolved_at && d.resolved_at <= d.repayment_date,
    ).length;
    const repaymentRate = resolved.length > 0 ? resolvedOnTime / resolved.length : 0;

    return {
      total: debts.length,
      open: open.length,
      in_progress: inProgress.length,
      resolved: resolved.length,
      overdue: overdue.length,
      totalTokenCost,
      resolvedTokenCost,
      repaymentRate,
    };
  }

  async function getCritical(): Promise<TechDebt[]> {
    const rows = db
      .prepare(
        "SELECT * FROM tech_debt WHERE severity = 'P0' AND status != 'resolved' ORDER BY repayment_date ASC",
      )
      .all() as Array<Record<string, unknown>>;
    return rows.map(rowToDebt);
  }

  async function close(): Promise<void> {
    db.close();
  }

  return {
    add,
    list,
    get,
    resolve,
    start,
    remove,
    stats,
    getCritical,
    close,
  };
}
