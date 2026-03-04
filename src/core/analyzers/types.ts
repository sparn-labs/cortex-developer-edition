/**
 * Shared types for the multi-dimensional codebase analyzer.
 */

import type { DependencyGraph, DependencyNode, GraphAnalysis } from '../dependency-graph.js';
import type { CortexIgnore } from './cortexignore.js';

export type AnalysisCategory =
  | 'architecture'
  | 'quality'
  | 'database'
  | 'security'
  | 'tokens'
  | 'tests';

export type Severity = 'critical' | 'major' | 'minor' | 'info';

export type Grade = 'S' | 'A+++' | 'A++' | 'A+' | 'A' | 'B' | 'B-' | 'C' | 'D' | 'Zero';

export type FixType =
  | 'extract-function'
  | 'replace-pattern'
  | 'add-constraint'
  | 'add-index'
  | 'add-test'
  | 'add-docs'
  | 'remove-code'
  | 'refactor'
  | 'config-change';

export interface AnalyzerFinding {
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  filePath?: string;
  line?: number;
  suggestion?: string;
  deduction: number;
  fixable?: boolean;
  fixType?: FixType;
}

export interface ActionPlanItem {
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  pointsRecoverable: number;
  effort: 'low' | 'medium' | 'high';
  filePath?: string;
  line?: number;
  fixable: boolean;
  fixType?: FixType;
}

export interface CategoryResult {
  category: AnalysisCategory;
  name: string;
  maxPoints: number;
  score: number;
  isNA: boolean;
  findings: AnalyzerFinding[];
}

export interface Analyzer {
  readonly category: AnalysisCategory;
  readonly name: string;
  readonly maxPoints: number;
  analyze(context: AnalysisContext): Promise<CategoryResult>;
}

export interface GitLogEntry {
  hash: string;
  date: string;
  filesChanged: string[];
}

export interface AnalysisContext {
  projectRoot: string;
  files: Map<string, string>;
  extensions: Set<string>;
  dependencyGraph: DependencyGraph;
  graphAnalysis: GraphAnalysis;
  nodes: Map<string, DependencyNode>;
  stackTags: Set<string>;
  gitAvailable: boolean;
  gitLog: GitLogEntry[];
  config: AnalyzeThresholds;
  ignore: CortexIgnore;
}

export interface AnalyzeThresholds {
  maxCyclomaticComplexity: number;
  maxFunctionLength: number;
  maxFileLength: number;
  maxCouplingCa: number;
  maxCouplingCe: number;
  maxDIT: number;
  minTestCoverage: number;
  layerRules: Record<string, string[]>;
  secretsIgnorePatterns: string[];
  excludePatterns: string[];
}

export const DEFAULT_THRESHOLDS: AnalyzeThresholds = {
  maxCyclomaticComplexity: 15,
  maxFunctionLength: 50,
  maxFileLength: 500,
  maxCouplingCa: 15,
  maxCouplingCe: 12,
  maxDIT: 4,
  minTestCoverage: 60,
  layerRules: {},
  secretsIgnorePatterns: [],
  excludePatterns: [],
};

export interface ScoreResult {
  totalScore: number;
  grade: Grade;
  categories: Record<
    string,
    { score: number; maxPoints: number; scaledScore: number; scaledMax: number; isNA: boolean }
  >;
}

/**
 * Post-process findings: apply per-rule caps and filter suppressed lines.
 * Call after each analyzer's analyze() to keep finding lists manageable.
 */
export function postProcessFindings(
  result: CategoryResult,
  maxFindingsPerRule = 5,
): CategoryResult {
  // Cap findings per rule ID
  const countByRule = new Map<string, number>();
  const capped: AnalyzerFinding[] = [];

  for (const finding of result.findings) {
    const count = countByRule.get(finding.ruleId) ?? 0;
    if (count < maxFindingsPerRule) {
      capped.push(finding);
      countByRule.set(finding.ruleId, count + 1);
    }
  }

  return { ...result, findings: capped };
}

/**
 * Check if a line is suppressed via `// cortex-ignore` comment on the previous line.
 */
export function isLineSuppressed(content: string, lineNumber: number): boolean {
  const lines = content.split('\n');
  if (lineNumber <= 0 || lineNumber > lines.length) return false;
  const prevLine = lines[lineNumber - 2]; // lineNumber is 1-based
  if (!prevLine) return false;
  return prevLine.includes('cortex-ignore');
}

export interface AnalysisReport {
  version: string;
  timestamp: string;
  project: { name: string; path: string; stack: string[] };
  score: ScoreResult;
  categoryResults: CategoryResult[];
  metrics: {
    totalFiles: number;
    totalTokens: number;
    entryPoints: number;
    hotPaths: number;
    orphanedFiles: number;
  };
  actionPlan: {
    quickWins: AnalyzerFinding[];
    structural: AnalyzerFinding[];
    backlog: AnalyzerFinding[];
  };
}
