/**
 * Baseline management for analysis delta mode.
 *
 * Saves/loads baseline analysis results and computes diffs.
 * Fingerprints use ruleId + filePath + title (not line numbers)
 * so findings survive line shifts across edits.
 */

import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { AnalysisReport, AnalyzerFinding } from './types.js';

export interface BaselineFinding {
  ruleId: string;
  filePath?: string;
  severity: string;
  title: string;
  fingerprint: string;
}

export interface AnalysisBaseline {
  timestamp: string;
  score: number;
  grade: string;
  findings: BaselineFinding[];
}

const BASELINE_FILE = 'analyze-baseline.json';

/**
 * Create a stable fingerprint for a finding.
 * Uses ruleId + filePath + title — not line numbers.
 */
export function fingerprint(finding: { ruleId: string; filePath?: string; title: string }): string {
  const input = `${finding.ruleId}::${finding.filePath ?? ''}::${finding.title}`;
  return createHash('sha256').update(input).digest('hex').slice(0, 16);
}

/**
 * Save current analysis results as baseline.
 */
export function saveBaseline(projectRoot: string, report: AnalysisReport): void {
  const cortexDir = join(projectRoot, '.cortex');
  if (!existsSync(cortexDir)) {
    mkdirSync(cortexDir, { recursive: true });
  }

  const allFindings = report.categoryResults.flatMap((r) => r.findings);

  const baseline: AnalysisBaseline = {
    timestamp: report.timestamp,
    score: report.score.totalScore,
    grade: report.score.grade,
    findings: allFindings.map((f) => ({
      ruleId: f.ruleId,
      filePath: f.filePath,
      severity: f.severity,
      title: f.title,
      fingerprint: fingerprint(f),
    })),
  };

  writeFileSync(join(cortexDir, BASELINE_FILE), JSON.stringify(baseline, null, 2), 'utf-8');
}

/**
 * Load previously saved baseline.
 */
export function loadBaseline(projectRoot: string): AnalysisBaseline | null {
  const filePath = join(projectRoot, '.cortex', BASELINE_FILE);
  if (!existsSync(filePath)) return null;

  try {
    const content = readFileSync(filePath, 'utf-8');
    return JSON.parse(content) as AnalysisBaseline;
  } catch {
    return null;
  }
}

/**
 * Diff current findings against a baseline.
 */
export function diffFindings(
  current: AnalyzerFinding[],
  baselineFindings: BaselineFinding[],
): {
  newFindings: AnalyzerFinding[];
  fixedFindings: BaselineFinding[];
  unchanged: BaselineFinding[];
} {
  const baselineMap = new Map<string, BaselineFinding>();
  for (const bf of baselineFindings) {
    baselineMap.set(bf.fingerprint, bf);
  }

  const currentFingerprints = new Set<string>();
  const newFindings: AnalyzerFinding[] = [];

  for (const finding of current) {
    const fp = fingerprint(finding);
    currentFingerprints.add(fp);
    if (!baselineMap.has(fp)) {
      newFindings.push(finding);
    }
  }

  const fixedFindings: BaselineFinding[] = [];
  const unchanged: BaselineFinding[] = [];

  for (const bf of baselineFindings) {
    if (currentFingerprints.has(bf.fingerprint)) {
      unchanged.push(bf);
    } else {
      fixedFindings.push(bf);
    }
  }

  return { newFindings, fixedFindings, unchanged };
}
