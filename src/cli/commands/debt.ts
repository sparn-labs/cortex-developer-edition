/**
 * Debt Command - Technical debt tracking
 */

import { resolve } from 'node:path';
import type { DebtSeverity, DebtStats, DebtTracker, TechDebt } from '../../core/debt-tracker.js';
import { createDebtTracker } from '../../core/debt-tracker.js';

export interface DebtCommandOptions {
  subcommand: 'add' | 'list' | 'resolve' | 'stats' | 'start';
  description?: string;
  severity?: string;
  due?: string;
  files?: string[];
  tokenCost?: number;
  id?: string;
  overdue?: boolean;
  json?: boolean;
}

export interface DebtCommandResult {
  debt?: TechDebt;
  debts?: TechDebt[];
  stats?: DebtStats;
  json?: string;
  message: string;
}

export async function debtCommand(options: DebtCommandOptions): Promise<DebtCommandResult> {
  const projectRoot = resolve(process.cwd());
  const dbPath = resolve(projectRoot, '.cortex', 'memory.db');
  const tracker = createDebtTracker(dbPath);

  try {
    switch (options.subcommand) {
      case 'add':
        return handleAdd(tracker, options);
      case 'list':
        return handleList(tracker, options);
      case 'resolve':
        return handleResolve(tracker, options);
      case 'start':
        return handleStart(tracker, options);
      case 'stats':
        return handleStats(tracker, options);
      default:
        throw new Error(`Unknown subcommand: ${options.subcommand}`);
    }
  } finally {
    await tracker.close();
  }
}

async function handleAdd(
  tracker: DebtTracker,
  options: DebtCommandOptions,
): Promise<DebtCommandResult> {
  if (!options.description) {
    throw new Error('Description is required');
  }

  const severity = (options.severity || 'P1') as DebtSeverity;
  if (!['P0', 'P1', 'P2'].includes(severity)) {
    throw new Error('Severity must be P0, P1, or P2');
  }

  let repaymentDate: number;
  if (options.due) {
    repaymentDate = new Date(options.due).getTime();
    if (Number.isNaN(repaymentDate)) {
      throw new Error(`Invalid date: ${options.due}`);
    }
  } else {
    repaymentDate = Date.now() + 14 * 24 * 60 * 60 * 1000;
  }

  const debt = await tracker.add({
    description: options.description,
    repayment_date: repaymentDate,
    severity,
    token_cost: options.tokenCost || 0,
    files_affected: options.files || [],
  });

  const result: DebtCommandResult = {
    debt,
    message: `Debt ${debt.id} added (${severity}): ${options.description}`,
  };

  if (options.json) {
    result.json = JSON.stringify(debt, null, 2);
  }

  return result;
}

async function handleList(
  tracker: DebtTracker,
  options: DebtCommandOptions,
): Promise<DebtCommandResult> {
  const debts = await tracker.list({ overdue: options.overdue });

  const result: DebtCommandResult = {
    debts,
    message: `${debts.length} debt item(s)`,
  };

  if (options.json) {
    result.json = JSON.stringify(debts, null, 2);
  }

  return result;
}

async function handleResolve(
  tracker: DebtTracker,
  options: DebtCommandOptions,
): Promise<DebtCommandResult> {
  if (!options.id) {
    throw new Error('Debt ID is required');
  }

  await tracker.resolve(options.id, options.tokenCost);

  return { message: `Debt ${options.id} resolved` };
}

async function handleStart(
  tracker: DebtTracker,
  options: DebtCommandOptions,
): Promise<DebtCommandResult> {
  if (!options.id) {
    throw new Error('Debt ID is required');
  }

  await tracker.start(options.id);

  return { message: `Debt ${options.id} started` };
}

async function handleStats(
  tracker: DebtTracker,
  options: DebtCommandOptions,
): Promise<DebtCommandResult> {
  const stats = await tracker.stats();

  const result: DebtCommandResult = {
    stats,
    message: `${stats.total} total, ${stats.open} open, ${stats.overdue} overdue, ${(stats.repaymentRate * 100).toFixed(0)}% on-time rate`,
  };

  if (options.json) {
    result.json = JSON.stringify(stats, null, 2);
  }

  return result;
}
