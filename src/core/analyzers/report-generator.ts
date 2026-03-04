/**
 * Report generator for analysis results.
 * Produces Markdown and JSON output formats.
 */

import { mapGrade } from './scoring.js';
import type {
  ActionPlanItem,
  AnalysisReport,
  AnalyzerFinding,
  CategoryResult,
  FixType,
  ScoreResult,
  Severity,
} from './types.js';

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  major: 1,
  minor: 2,
  info: 3,
};

const SEVERITY_EMOJI: Record<Severity, string> = {
  critical: '[CRITICAL]',
  major: '[MAJOR]',
  minor: '[MINOR]',
  info: '[INFO]',
};

function sortFindings(findings: AnalyzerFinding[]): AnalyzerFinding[] {
  return [...findings].sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 3) - (SEVERITY_ORDER[b.severity] ?? 3),
  );
}

function classifyActionPlan(results: CategoryResult[]): AnalysisReport['actionPlan'] {
  const quickWins: AnalyzerFinding[] = [];
  const structural: AnalyzerFinding[] = [];
  const backlog: AnalyzerFinding[] = [];

  for (const result of results) {
    for (const finding of result.findings) {
      if (finding.severity === 'critical') {
        quickWins.push(finding);
      } else if (finding.severity === 'major') {
        structural.push(finding);
      } else {
        backlog.push(finding);
      }
    }
  }

  return { quickWins, structural, backlog };
}

function renderCategoryTable(report: AnalysisReport): string[] {
  const lines: string[] = [];
  lines.push('### Category Breakdown');
  lines.push('');
  lines.push('| Category | Score | Max | Scaled | Grade |');
  lines.push('|----------|-------|-----|--------|-------|');

  for (const result of report.categoryResults) {
    const cat = report.score.categories[result.category];
    if (!cat) continue;

    if (cat.isNA) {
      lines.push(`| ${result.name} | N/A | ${result.maxPoints} | — | N/A |`);
    } else {
      const catScore = Math.round(cat.scaledScore * 100) / 100;
      const catMax = Math.round(cat.scaledMax * 100) / 100;
      const catPercent = cat.scaledMax > 0 ? (cat.scaledScore / cat.scaledMax) * 100 : 0;
      lines.push(
        `| ${result.name} | ${Math.round(result.score * 100) / 100}/${result.maxPoints} | ${result.maxPoints} | ${catScore}/${catMax} | ${mapGrade(catPercent)} |`,
      );
    }
  }
  return lines;
}

function renderFindings(report: AnalysisReport, verbose: boolean): string[] {
  const lines: string[] = [];
  for (const result of report.categoryResults) {
    if (result.isNA) continue;

    const sorted = sortFindings(result.findings);
    const displayed = verbose ? sorted : sorted.slice(0, 10);

    lines.push(`### ${result.name}`);
    lines.push('');

    if (displayed.length === 0) {
      lines.push('No issues found.');
      lines.push('');
      continue;
    }

    for (const finding of displayed) {
      lines.push(`- ${SEVERITY_EMOJI[finding.severity]} **${finding.ruleId}**: ${finding.title}`);
      lines.push(`  ${finding.description}`);
      if (finding.filePath) {
        const loc = finding.line ? `:${finding.line}` : '';
        lines.push(`  File: \`${finding.filePath}\`${loc}`);
      }
      if (finding.suggestion) lines.push(`  > ${finding.suggestion}`);
      lines.push('');
    }

    if (!verbose && sorted.length > 10) {
      lines.push(`  *... and ${sorted.length - 10} more findings*`);
      lines.push('');
    }
  }
  return lines;
}

function renderActionPlan(actionPlan: AnalysisReport['actionPlan']): string[] {
  const lines: string[] = [];
  const sections: Array<{ items: AnalyzerFinding[]; title: string }> = [
    { items: actionPlan.quickWins, title: 'Quick Wins (Critical)' },
    { items: actionPlan.structural, title: 'Structural Improvements (Major)' },
    { items: actionPlan.backlog, title: 'Backlog (Minor/Info)' },
  ];

  for (const { items, title } of sections) {
    if (items.length === 0) continue;
    lines.push(`### ${title}`);
    lines.push('');
    for (const item of items.slice(0, 5)) {
      lines.push(`- [ ] **${item.ruleId}**: ${item.title} — ${item.description}`);
    }
    lines.push('');
  }
  return lines;
}

export function generateMarkdownReport(report: AnalysisReport, verbose = false): string {
  const lines: string[] = [];

  lines.push('# Cortex Analysis Report');
  lines.push('');
  lines.push(`**Project**: ${report.project.name}`);
  lines.push(`**Path**: ${report.project.path}`);
  lines.push(`**Stack**: ${report.project.stack.join(', ') || 'Unknown'}`);
  lines.push(`**Date**: ${report.timestamp}`);
  lines.push('');
  lines.push('## Score');
  lines.push('');
  lines.push(`**Global Score**: ${report.score.totalScore}/100`);
  lines.push(`**Grade**: ${report.score.grade}`);
  lines.push('');

  lines.push(...renderCategoryTable(report));
  lines.push('');
  lines.push('## Findings');
  lines.push('');
  lines.push(...renderFindings(report, verbose));

  lines.push('## Metrics');
  lines.push('');
  lines.push('| Metric | Value |');
  lines.push('|--------|-------|');
  lines.push(`| Total Files | ${report.metrics.totalFiles} |`);
  lines.push(`| Total Tokens | ${report.metrics.totalTokens.toLocaleString()} |`);
  lines.push(`| Entry Points | ${report.metrics.entryPoints} |`);
  lines.push(`| Hot Paths | ${report.metrics.hotPaths} |`);
  lines.push(`| Orphaned Files | ${report.metrics.orphanedFiles} |`);
  lines.push('');
  lines.push('## Action Plan');
  lines.push('');
  lines.push(...renderActionPlan(report.actionPlan));
  lines.push('---');
  lines.push(`*Generated by Cortex v${report.version}*`);

  return lines.join('\n');
}

const EFFORT_BY_FIX_TYPE: Record<FixType, 'low' | 'medium' | 'high'> = {
  'remove-code': 'low',
  'replace-pattern': 'low',
  'config-change': 'low',
  'add-constraint': 'low',
  'add-index': 'low',
  'add-docs': 'medium',
  'add-test': 'medium',
  'extract-function': 'medium',
  refactor: 'high',
};

export function buildActionPlanItems(results: CategoryResult[]): ActionPlanItem[] {
  const items: ActionPlanItem[] = [];

  for (const result of results) {
    for (const f of result.findings) {
      items.push({
        ruleId: f.ruleId,
        title: f.title,
        description: f.description,
        severity: f.severity,
        pointsRecoverable: f.deduction,
        effort: f.fixType ? (EFFORT_BY_FIX_TYPE[f.fixType] ?? 'medium') : 'medium',
        filePath: f.filePath,
        line: f.line,
        fixable: f.fixable ?? false,
        fixType: f.fixType,
      });
    }
  }

  return items;
}

export function generateJSONReport(report: AnalysisReport): string {
  const issues = report.categoryResults.flatMap((r) =>
    r.findings.map((f) => ({
      id: f.ruleId,
      severity: f.severity,
      title: f.title,
      description: f.description,
      file: f.filePath,
      line: f.line,
      suggestion: f.suggestion,
      deduction: f.deduction,
      fixable: f.fixable ?? false,
      fixType: f.fixType ?? null,
    })),
  );

  const actionPlanItems = buildActionPlanItems(report.categoryResults);

  const output = {
    cortex_analyze: {
      version: report.version,
      timestamp: report.timestamp,
      project: report.project,
      score: {
        global: report.score.totalScore,
        grade: report.score.grade,
        categories: report.score.categories,
      },
      issues,
      metrics: report.metrics,
      action_plan: {
        quick_wins: report.actionPlan.quickWins.map(summarizeFinding),
        structural: report.actionPlan.structural.map(summarizeFinding),
        backlog: report.actionPlan.backlog.map(summarizeFinding),
        items: actionPlanItems,
      },
    },
  };

  return JSON.stringify(output, null, 2);
}

function summarizeFinding(f: AnalyzerFinding): {
  id: string;
  title: string;
  description: string;
  severity: string;
  fixable: boolean;
  fixType: string | null;
} {
  return {
    id: f.ruleId,
    title: f.title,
    description: f.description,
    severity: f.severity,
    fixable: f.fixable ?? false,
    fixType: f.fixType ?? null,
  };
}

export function buildReport(
  score: ScoreResult,
  categoryResults: CategoryResult[],
  projectName: string,
  projectPath: string,
  stack: string[],
  totalFiles: number,
  totalTokens: number,
  entryPoints: number,
  hotPaths: number,
  orphanedFiles: number,
  version: string,
): AnalysisReport {
  return {
    version,
    timestamp: new Date().toISOString(),
    project: { name: projectName, path: projectPath, stack },
    score,
    categoryResults,
    metrics: { totalFiles, totalTokens, entryPoints, hotPaths, orphanedFiles },
    actionPlan: classifyActionPlan(categoryResults),
  };
}
