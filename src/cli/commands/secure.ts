/**
 * `cortex secure [path]` — Enterprise security analyzer command.
 * 10 OWASP 2025-aligned defense layers, 100-point weighted scoring.
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { applyAutoFixes } from '../../core/secure/auto-fix.js';
import { runSecureAudit } from '../../core/secure/engine.js';
import { generateSecureJSON, generateSecureMarkdown } from '../../core/secure/report.js';
import type { SecureGrade, SecureReport } from '../../core/secure/types.js';

export interface SecureCommandOptions {
  path?: string;
  fix?: boolean;
  ci?: boolean;
  minGrade?: string;
  failOn?: string;
  layer?: string;
  compare?: string;
  output?: string;
  outputFile?: string;
  quick?: boolean;
  compliance?: string;
  verbose?: boolean;
}

export interface SecureCommandResult {
  report: SecureReport;
  markdown: string;
  json?: string;
  fixResult?: { applied: number; skipped: number };
  exitCode: number;
}

const GRADE_ORDER: SecureGrade[] = [
  'Zero',
  'D',
  'C',
  'B-',
  'B',
  'B+',
  'A-',
  'A',
  'A+',
  'A++',
  'A+++',
  'S',
];

function gradeIndex(grade: string): number {
  return GRADE_ORDER.indexOf(grade as SecureGrade);
}

function severityMeetsThreshold(severity: string, threshold: string): boolean {
  const order = ['info', 'low', 'medium', 'high', 'critical'];
  return order.indexOf(severity) >= order.indexOf(threshold);
}

export async function secureCommand(options: SecureCommandOptions): Promise<SecureCommandResult> {
  const projectPath = resolve(options.path || process.cwd());

  // Run the audit
  const report = await runSecureAudit({
    path: projectPath,
    fix: options.fix,
    ci: options.ci,
    minGrade: options.minGrade,
    failOn: options.failOn,
    layer: options.layer,
    compare: options.compare,
    output: options.output,
    outputFile: options.outputFile,
    quick: options.quick,
    compliance: options.compliance,
    verbose: options.verbose,
  });

  // Apply auto-fixes if requested
  let fixResult: { applied: number; skipped: number } | undefined;
  if (options.fix) {
    const autoFixResult = applyAutoFixes(projectPath, report.findings);
    fixResult = { applied: autoFixResult.applied, skipped: autoFixResult.skipped };
  }

  // Generate output
  const markdown = generateSecureMarkdown(report);
  const json = options.output === 'json' ? generateSecureJSON(report) : undefined;

  // Write to file if requested
  if (options.outputFile) {
    const content = options.output === 'json' ? generateSecureJSON(report) : markdown;
    writeFileSync(options.outputFile, content, 'utf-8');
  }

  // Compare with previous report
  if (options.compare && existsSync(options.compare)) {
    try {
      const previousRaw = readFileSync(options.compare, 'utf-8');
      const previous: SecureReport = JSON.parse(previousRaw);
      const delta = report.score.global - previous.score.global;
      const newFindings = report.findings.length - previous.findings.length;

      // Inject comparison into report output (appended to markdown)
      const comparison = [
        '\n## Comparison with Previous Report',
        '',
        `| Metric | Previous | Current | Delta |`,
        `|--------|----------|---------|-------|`,
        `| Score | ${previous.score.global} | ${report.score.global} | ${delta >= 0 ? '+' : ''}${delta.toFixed(1)} |`,
        `| Grade | ${previous.score.grade} | ${report.score.grade} | — |`,
        `| Findings | ${previous.findings.length} | ${report.findings.length} | ${newFindings >= 0 ? '+' : ''}${newFindings} |`,
        '',
      ].join('\n');

      // This is visible in the console output
      if (!options.outputFile) {
        console.log(comparison);
      }
    } catch {
      // Comparison file invalid — skip
    }
  }

  // CI mode — determine exit code
  let exitCode = 0;

  if (options.ci) {
    // Check minimum grade
    if (options.minGrade) {
      const currentIdx = gradeIndex(report.score.grade);
      const requiredIdx = gradeIndex(options.minGrade);
      if (currentIdx < requiredIdx) {
        exitCode = 1;
      }
    }

    // Check fail-on severity
    if (options.failOn) {
      const threshold = options.failOn;
      const hasFailingSeverity = report.findings.some((f) =>
        severityMeetsThreshold(f.severity, threshold),
      );
      if (hasFailingSeverity) {
        exitCode = 1;
      }
    }

    // Default CI behavior: fail on critical
    if (!options.minGrade && !options.failOn) {
      const hasCritical = report.findings.some((f) => f.severity === 'critical');
      if (hasCritical) exitCode = 1;
    }
  }

  return { report, markdown, json, fixResult, exitCode };
}

export function displaySecureReport(
  result: SecureCommandResult,
  colors: {
    neuralCyan: (s: string) => string;
    synapseViolet: (s: string) => string;
    errorRed: (s: string) => string;
    brainPink: (s: string) => string;
    dim: (s: string) => string;
    bold: (s: string) => string;
  },
): void {
  const { report, fixResult } = result;

  // Header
  console.log(`\n${colors.brainPink('━'.repeat(60))}`);
  console.log(colors.bold(`  CORTEX SECURITY AUDIT`));
  console.log(colors.brainPink('━'.repeat(60)));

  // Score display
  const gradeColor =
    report.score.global >= 80
      ? colors.neuralCyan
      : report.score.global >= 50
        ? colors.synapseViolet
        : colors.errorRed;

  console.log(
    `\n  Score: ${gradeColor(`${report.score.global}/100`)}  Grade: ${gradeColor(report.score.grade)}`,
  );
  console.log(`  Stack: ${colors.dim(report.project.stack.join(', ') || 'Unknown')}`);

  // Layer summary
  console.log(`\n${colors.bold('  Layer Scores:')}`);
  const sortedLayers = Object.values(report.score.layers).sort((a, b) => a.layer - b.layer);
  for (const layer of sortedLayers) {
    const bar = getScoreBar(layer.score, layer.weight);
    const layerColor =
      layer.score >= layer.weight * 0.8
        ? colors.neuralCyan
        : layer.score >= layer.weight * 0.5
          ? colors.synapseViolet
          : colors.errorRed;

    console.log(
      `  L${String(layer.layer).padStart(2, ' ')} ${layer.name.padEnd(32)} ${bar} ${layerColor(`${layer.score.toFixed(1)}/${layer.weight}`)} ${colors.dim(layer.grade)}`,
    );
  }

  // Findings summary
  const criticals = report.findings.filter((f) => f.severity === 'critical').length;
  const highs = report.findings.filter((f) => f.severity === 'high').length;
  const mediums = report.findings.filter((f) => f.severity === 'medium').length;
  const lows = report.findings.filter((f) => f.severity === 'low').length;
  const infos = report.findings.filter((f) => f.severity === 'info').length;

  console.log(`\n${colors.bold('  Findings:')} ${report.findings.length} total`);
  if (criticals > 0) console.log(`  ${colors.errorRed(`  ${criticals} critical`)}`);
  if (highs > 0) console.log(`  ${colors.errorRed(`  ${highs} high`)}`);
  if (mediums > 0) console.log(`  ${colors.synapseViolet(`  ${mediums} medium`)}`);
  if (lows > 0) console.log(`  ${colors.dim(`  ${lows} low`)}`);
  if (infos > 0) console.log(`  ${colors.dim(`  ${infos} info`)}`);

  // Compliance
  console.log(
    `\n${colors.bold('  Compliance:')} ${report.compliance.framework.toUpperCase()} — ${report.compliance.passRate}% pass rate`,
  );

  // Auto-fix results
  if (fixResult) {
    console.log(
      `\n${colors.bold('  Auto-Fix:')} ${colors.neuralCyan(`${fixResult.applied} applied`)}, ${colors.dim(`${fixResult.skipped} skipped`)}`,
    );
  }

  // Remediation hint
  const immediateCount = report.remediationRoadmap.immediate.length;
  if (immediateCount > 0) {
    console.log(
      `\n  ${colors.synapseViolet(`${immediateCount} immediate fix(es) available`)} — run with --fix to apply`,
    );
  }

  console.log(`\n${colors.brainPink('━'.repeat(60))}\n`);
}

function getScoreBar(score: number, weight: number): string {
  const ratio = weight > 0 ? score / weight : 1;
  const filled = Math.round(ratio * 16);
  const empty = 16 - filled;
  return `[${'#'.repeat(filled)}${'.'.repeat(empty)}]`;
}
