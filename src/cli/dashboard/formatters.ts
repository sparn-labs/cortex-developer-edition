/**
 * Dashboard command output formatters — pure functions.
 *
 * Convert typed command results into OutputLine[] for display in the output panel.
 * One formatter per command, mirroring the display logic in src/cli/index.ts actions.
 */

import { theme } from './theme.js';

export interface OutputLine {
  text: string;
  color?: string;
}

// ── Optimize ──

interface OptimizeResult {
  tokensBefore: number;
  tokensAfter: number;
  reduction: number;
  entriesProcessed: number;
  entriesKept: number;
  durationMs: number;
  outputFile?: string;
}

export function formatOptimize(result: OptimizeResult): OutputLine[] {
  const pct = (result.reduction * 100).toFixed(1);
  return [
    { text: `\u2713 Optimization complete in ${result.durationMs}ms`, color: theme.neuralCyan },
    {
      text: `  Tokens: ${result.tokensBefore} \u2192 ${result.tokensAfter} (${pct}% reduction)`,
    },
    {
      text: `  Entries: processed=${result.entriesProcessed} kept=${result.entriesKept}`,
    },
    ...(result.outputFile
      ? [{ text: `  Output: ${result.outputFile}`, color: theme.dimGray }]
      : []),
  ];
}

// ── Stats ──

interface StatsResult {
  totalCommands: number;
  totalTokensSaved: number;
  averageReduction: number;
  graph?: string;
  resetConfirmed?: boolean;
}

export function formatStats(result: StatsResult): OutputLine[] {
  if (result.resetConfirmed) {
    return [{ text: '\u2713 Statistics reset', color: theme.neuralCyan }];
  }
  const avgPct = (result.averageReduction * 100).toFixed(1);
  const lines: OutputLine[] = [
    { text: 'Optimization Statistics', color: theme.neuralCyan },
    { text: `  Total commands: ${result.totalCommands}` },
    { text: `  Tokens saved:   ${result.totalTokensSaved}` },
    { text: `  Avg reduction:  ${avgPct}%` },
  ];
  if (result.graph) {
    for (const line of result.graph.split('\n')) {
      lines.push({ text: line, color: theme.dimGray });
    }
  }
  return lines;
}

// ── Consolidate ──

interface ConsolidateResult {
  entriesBefore: number;
  entriesAfter: number;
  decayedRemoved: number;
  duplicatesRemoved: number;
  compressionRatio: number;
  durationMs: number;
}

export function formatConsolidate(result: ConsolidateResult): OutputLine[] {
  const pct = (result.compressionRatio * 100).toFixed(1);
  return [
    { text: `\u2713 Consolidation complete in ${result.durationMs}ms`, color: theme.neuralCyan },
    { text: `  Entries: ${result.entriesBefore} \u2192 ${result.entriesAfter}` },
    { text: `  Decayed removed: ${result.decayedRemoved}` },
    { text: `  Duplicates removed: ${result.duplicatesRemoved}` },
    { text: `  Compression: ${pct}%` },
  ];
}

// ── Search ──

interface SearchResultItem {
  filePath: string;
  lineNumber: number;
  content: string;
  score: number;
}

interface SearchCmdResult {
  results?: SearchResultItem[];
  indexStats?: { filesIndexed: number; totalLines: number; duration: number };
  message?: string;
}

export function formatSearch(result: SearchCmdResult): OutputLine[] {
  if (result.indexStats) {
    const s = result.indexStats;
    return [
      {
        text: `\u2713 Indexed ${s.filesIndexed} files (${s.totalLines} lines) in ${s.duration}ms`,
        color: theme.neuralCyan,
      },
    ];
  }

  if (!result.results || result.results.length === 0) {
    return [{ text: result.message || 'No results found', color: theme.dimGray }];
  }

  const lines: OutputLine[] = [
    { text: `${result.results.length} result(s):`, color: theme.neuralCyan },
  ];
  for (const r of result.results) {
    lines.push({
      text: `  ${r.filePath}:${r.lineNumber} (score: ${r.score.toFixed(2)})`,
      color: theme.synapseViolet,
    });
    lines.push({ text: `    ${r.content.trim()}` });
  }
  return lines;
}

// ── Graph ──

interface GraphResult {
  analysis: {
    entryPoints: string[];
    hotPaths: string[];
    orphans: string[];
    totalTokens: number;
    optimizedTokens: number;
  };
  nodeCount: number;
}

export function formatGraph(result: GraphResult): OutputLine[] {
  const a = result.analysis;
  const lines: OutputLine[] = [
    { text: `Graph: ${result.nodeCount} nodes`, color: theme.neuralCyan },
    { text: `  Tokens: ${a.totalTokens} (optimized: ${a.optimizedTokens})` },
  ];
  if (a.hotPaths.length > 0) {
    lines.push({
      text: `  Hot paths: ${a.hotPaths.slice(0, 5).join(', ')}`,
      color: theme.brainPink,
    });
  }
  if (a.orphans.length > 0) {
    lines.push({ text: `  Orphans: ${a.orphans.length}`, color: theme.dimGray });
  }
  return lines;
}

// ── Plan ──

interface PlanResult {
  plan: { id: string; steps: unknown[] };
  message: string;
}

export function formatPlan(result: PlanResult): OutputLine[] {
  return [{ text: `\u2713 ${result.message}`, color: theme.neuralCyan }];
}

// ── Plan List ──

interface PlanListResult {
  plans: Array<{ id: string; task: string; status: string }>;
}

export function formatPlanList(result: PlanListResult): OutputLine[] {
  if (result.plans.length === 0) {
    return [{ text: 'No plans found', color: theme.dimGray }];
  }
  const lines: OutputLine[] = [
    { text: `${result.plans.length} plan(s):`, color: theme.neuralCyan },
  ];
  for (const p of result.plans) {
    const statusColor = p.status === 'completed' ? theme.neuralCyan : theme.synapseViolet;
    lines.push({ text: `  ${p.id} [${p.status}] ${p.task}`, color: statusColor });
  }
  return lines;
}

// ── Exec ──

interface ExecResult {
  constraints: { maxFileReads: number; tokenBudget: number };
  message: string;
}

export function formatExec(result: ExecResult): OutputLine[] {
  return [
    { text: `\u2713 ${result.message}`, color: theme.neuralCyan },
    {
      text: `  Max reads: ${result.constraints.maxFileReads}, Budget: ${result.constraints.tokenBudget} tokens`,
    },
  ];
}

// ── Verify ──

interface VerifyResult {
  verification: {
    success: boolean;
    stepsCompleted: number;
    totalSteps: number;
  };
  message: string;
}

export function formatVerify(result: VerifyResult): OutputLine[] {
  const v = result.verification;
  const icon = v.success ? '\u2713' : '\u2717';
  const color = v.success ? theme.neuralCyan : theme.errorRed;
  return [
    { text: `${icon} ${result.message}`, color },
    { text: `  Steps: ${v.stepsCompleted}/${v.totalSteps} completed` },
  ];
}

// ── Docs ──

interface DocsResult {
  outputPath?: string;
  message: string;
}

export function formatDocs(result: DocsResult): OutputLine[] {
  return [{ text: `\u2713 ${result.message}`, color: theme.neuralCyan }];
}

// ── Debt ──

interface DebtResult {
  debt?: { id: string; severity: string; description: string };
  debts?: Array<{ id: string; severity: string; description: string; status: string }>;
  stats?: { total: number; open: number; overdue: number; repaymentRate: number };
  message: string;
}

export function formatDebt(result: DebtResult): OutputLine[] {
  if (result.stats) {
    const s = result.stats;
    return [
      { text: 'Debt Stats', color: theme.neuralCyan },
      { text: `  Total: ${s.total}, Open: ${s.open}, Overdue: ${s.overdue}` },
      { text: `  Repayment rate: ${(s.repaymentRate * 100).toFixed(0)}%` },
    ];
  }

  if (result.debts) {
    if (result.debts.length === 0) {
      return [{ text: 'No debt items', color: theme.dimGray }];
    }
    const lines: OutputLine[] = [
      { text: `${result.debts.length} debt item(s):`, color: theme.neuralCyan },
    ];
    for (const d of result.debts) {
      const sevColor =
        d.severity === 'P0'
          ? theme.errorRed
          : d.severity === 'P1'
            ? theme.synapseViolet
            : theme.dimGray;
      const desc =
        d.description.length > 40 ? `${d.description.substring(0, 37)}...` : d.description;
      lines.push({
        text: `  [${d.severity}] ${d.id.slice(0, 8)} ${desc} (${d.status})`,
        color: sevColor,
      });
    }
    return lines;
  }

  // Single debt or simple message
  return [{ text: `\u2713 ${result.message}`, color: theme.neuralCyan }];
}

// ── Error ──

export function formatError(err: Error): OutputLine[] {
  return [{ text: `Error: ${err.message}`, color: theme.errorRed }];
}

// ── Help ──

export function formatHelp(): OutputLine[] {
  return [
    { text: 'Available commands:', color: theme.neuralCyan },
    { text: '  optimize --input <text> [--input-file <path>] [--output-file <path>] [--dry-run]' },
    { text: '  stats [--graph] [--reset --confirm-reset]' },
    { text: '  consolidate' },
    { text: '  search <query> [--glob <pattern>] [--max-results <n>]' },
    { text: '  search init | search refresh' },
    { text: '  graph [--entry <file>] [--depth <n>] [--focus <file>]' },
    { text: '  plan <task> [--files <f1,f2>] [--searches <q1,q2>]' },
    { text: '  plan list' },
    { text: '  exec <planId>' },
    { text: '  verify <planId>' },
    { text: '  docs [--output <path>] [--no-graph]' },
    { text: '  debt add <desc> [--severity P0|P1|P2] [--due <date>] [--token-cost <n>]' },
    { text: '  debt list [--overdue]' },
    { text: '  debt resolve <id> [--token-cost <n>]' },
    { text: '  debt start <id>' },
    { text: '  debt stats' },
    { text: '  clear                              Clear output' },
    { text: '  help                               Show this help' },
    { text: '' },
    { text: 'Keybinds:', color: theme.neuralCyan },
    { text: '  :       Enter command mode' },
    { text: '  Escape  Exit command mode' },
    { text: '  Tab     Cycle panel focus' },
    { text: '  q       Quit (in monitor mode)' },
  ];
}
