/**
 * Analyze Command
 *
 * Orchestrates context building, analyzer execution, scoring, and reporting.
 * Supports full, changed-files, and single-file analysis modes.
 */

import { existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import {
  type AnalysisHistory,
  computeTrend,
  createAnalysisHistory,
} from '../../core/analyzers/analysis-history.js';
import { createArchitectureAnalyzer } from '../../core/analyzers/architecture-analyzer.js';
import { diffFindings, loadBaseline, saveBaseline } from '../../core/analyzers/baseline.js';
import {
  buildAnalysisContext,
  buildChangedFilesContext,
  buildSingleFileContext,
  getProjectName,
} from '../../core/analyzers/context-builder.js';
import { createDatabaseAnalyzer } from '../../core/analyzers/database-analyzer.js';
import { createQualityAnalyzer } from '../../core/analyzers/quality-analyzer.js';
import {
  buildReport,
  generateJSONReport,
  generateMarkdownReport,
} from '../../core/analyzers/report-generator.js';
import { computeScore } from '../../core/analyzers/scoring.js';
import { createSecurityAnalyzer } from '../../core/analyzers/security-analyzer.js';
import { createTestDocsAnalyzer } from '../../core/analyzers/testdocs-analyzer.js';
import { createTokenAnalyzer } from '../../core/analyzers/token-analyzer.js';
import type {
  AnalysisCategory,
  AnalysisReport,
  Analyzer,
  AnalyzeThresholds,
  CategoryResult,
} from '../../core/analyzers/types.js';
import { postProcessFindings } from '../../core/analyzers/types.js';

export interface AnalyzeCommandOptions {
  path?: string;
  focus?: string;
  json?: boolean;
  output?: string;
  verbose?: boolean;
  audit?: boolean;
  thresholds?: Partial<AnalyzeThresholds>;
  changed?: string | boolean;
  file?: string;
  history?: boolean;
  saveBaseline?: boolean;
  diff?: boolean;
}

export interface AnalyzeCommandResult {
  report: AnalysisReport;
  markdown: string;
  json?: string;
  trend?: { delta: number; label: string } | null;
  historyEntries?: Array<{ timestamp: number; score: number; grade: string }>;
  baselineDiff?: {
    newFindings: number;
    fixedFindings: number;
    unchanged: number;
    scoreChange: number;
  };
  mode: 'full' | 'changed' | 'file';
  modeDetail?: string;
}

const ALL_ANALYZERS: Array<() => Analyzer> = [
  createArchitectureAnalyzer,
  createQualityAnalyzer,
  createDatabaseAnalyzer,
  createSecurityAnalyzer,
  createTokenAnalyzer,
  createTestDocsAnalyzer,
];

const CATEGORY_MAP: Record<string, AnalysisCategory> = {
  architecture: 'architecture',
  quality: 'quality',
  database: 'database',
  security: 'security',
  tokens: 'tokens',
  tests: 'tests',
};

function getDbPath(projectRoot: string): string {
  return join(projectRoot, '.cortex', 'memory.db');
}

export async function analyzeCommand(
  options: AnalyzeCommandOptions,
): Promise<AnalyzeCommandResult> {
  const projectRoot = resolve(options.path || process.cwd());

  // Determine analysis mode
  let mode: 'full' | 'changed' | 'file' = 'full';
  let modeDetail: string | undefined;

  // Build shared analysis context based on mode
  let context: Awaited<ReturnType<typeof buildAnalysisContext>>;
  if (options.file) {
    mode = 'file';
    modeDetail = options.file;
    context = await buildSingleFileContext(projectRoot, options.file, options.thresholds);
  } else if (options.changed !== undefined) {
    mode = 'changed';
    const ref = typeof options.changed === 'string' ? options.changed : 'HEAD~1';
    modeDetail = ref;
    context = await buildChangedFilesContext(projectRoot, ref, options.thresholds);
  } else {
    context = await buildAnalysisContext(projectRoot, options.thresholds);
  }

  // Determine which analyzers to run
  let analyzers = ALL_ANALYZERS.map((create) => create());

  if (options.focus) {
    const focusCategories = options.focus
      .split(',')
      .map((c) => c.trim().toLowerCase())
      .filter((c) => c in CATEGORY_MAP)
      .map((c) => CATEGORY_MAP[c]) as AnalysisCategory[];

    if (focusCategories.length > 0) {
      analyzers = analyzers.filter((a) => focusCategories.includes(a.category));
    }
  }

  // Run all analyzers with post-processing (finding caps per rule)
  const results: CategoryResult[] = [];
  for (const analyzer of analyzers) {
    const raw = await analyzer.analyze(context);
    results.push(postProcessFindings(raw));
  }

  // Compute score with N/A redistribution
  const score = computeScore(results);

  // Build report
  const projectName = getProjectName(projectRoot);
  const report = buildReport(
    score,
    results,
    projectName,
    projectRoot,
    [...context.stackTags],
    context.files.size,
    context.graphAnalysis.totalTokens,
    context.graphAnalysis.entryPoints.length,
    context.graphAnalysis.hotPaths.length,
    context.graphAnalysis.orphans.length,
    '2.0',
  );

  const markdown = generateMarkdownReport(report, options.verbose);

  const result: AnalyzeCommandResult = { report, markdown, mode, modeDetail };

  if (options.json) {
    result.json = generateJSONReport(report);
  }

  // Score history tracking
  const dbPath = getDbPath(projectRoot);
  let history: AnalysisHistory | null = null;

  if (existsSync(join(projectRoot, '.cortex'))) {
    try {
      history = createAnalysisHistory(dbPath);

      // Record this analysis
      const totalFindings = results.reduce((sum, r) => sum + r.findings.length, 0);
      const categories: Record<string, { score: number; maxPoints: number }> = {};
      for (const r of results) {
        categories[r.category] = { score: r.score, maxPoints: r.maxPoints };
      }

      history.record({
        timestamp: Date.now(),
        score: score.totalScore,
        grade: score.grade,
        categories,
        totalFiles: context.files.size,
        totalFindings: totalFindings,
        projectPath: projectRoot,
        mode,
      });

      // Compute trend (compare against last full run)
      if (mode === 'full') {
        const entries = history.getRecent(2);
        // The last full entry before this one
        const previous = entries.length > 1 ? entries[1] : null;
        result.trend = previous
          ? computeTrend(score.totalScore, { ...previous, id: previous.id })
          : null;
      }

      // Show history if requested
      if (options.history) {
        const recent = history.getRecent(20);
        result.historyEntries = recent.map((e) => ({
          timestamp: e.timestamp,
          score: e.score,
          grade: e.grade,
        }));
      }
    } catch {
      // History tracking is best-effort
    } finally {
      history?.close();
    }
  }

  // Baseline operations (best-effort — don't lose analysis results on failure)
  if (options.saveBaseline) {
    try {
      saveBaseline(projectRoot, report);
    } catch {
      // Baseline save is best-effort
    }
  }

  if (options.diff) {
    try {
      const baseline = loadBaseline(projectRoot);
      if (baseline) {
        const allFindings = report.categoryResults.flatMap((r) => r.findings);
        const delta = diffFindings(allFindings, baseline.findings);
        result.baselineDiff = {
          newFindings: delta.newFindings.length,
          fixedFindings: delta.fixedFindings.length,
          unchanged: delta.unchanged.length,
          scoreChange: Math.round((score.totalScore - baseline.score) * 10) / 10,
        };
      }
    } catch {
      // Baseline diff is best-effort
    }
  }

  return result;
}
