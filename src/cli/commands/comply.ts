/**
 * `cortex comply [path]` — Legal & regulatory compliance analyzer command.
 * 8 compliance layers (GDPR, CCPA, HIPAA, SOC2), 100-point weighted scoring.
 */

import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { runComplyAudit } from '../../core/comply/engine.js';
import { generateComplyJSON, generateComplyMarkdown } from '../../core/comply/report.js';
import type { ComplyGrade, ComplyReport } from '../../core/comply/types.js';

export interface ComplyCommandOptions {
  path?: string;
  ci?: boolean;
  minGrade?: string;
  failOn?: string;
  framework?: string;
  layer?: string;
  output?: string;
  outputFile?: string;
  quick?: boolean;
  verbose?: boolean;
}

export interface ComplyCommandResult {
  report: ComplyReport;
  markdown: string;
  json?: string;
  exitCode: number;
}

const GRADE_ORDER: ComplyGrade[] = [
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
  return GRADE_ORDER.indexOf(grade as ComplyGrade);
}

function severityMeetsThreshold(severity: string, threshold: string): boolean {
  const order = ['info', 'low', 'medium', 'high', 'critical'];
  return order.indexOf(severity) >= order.indexOf(threshold);
}

export async function complyCommand(options: ComplyCommandOptions): Promise<ComplyCommandResult> {
  const projectPath = resolve(options.path || process.cwd());

  // Run the audit
  const report = await runComplyAudit({
    path: projectPath,
    ci: options.ci,
    minGrade: options.minGrade,
    failOn: options.failOn,
    framework: options.framework,
    layer: options.layer,
    output: options.output,
    outputFile: options.outputFile,
    quick: options.quick,
    verbose: options.verbose,
  });

  // Generate output
  const markdown = generateComplyMarkdown(report);
  const json = options.output === 'json' ? generateComplyJSON(report) : undefined;

  // Write to file if requested
  if (options.outputFile) {
    const content = options.output === 'json' ? generateComplyJSON(report) : markdown;
    writeFileSync(options.outputFile, content, 'utf-8');
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

  return { report, markdown, json, exitCode };
}

export function displayComplyReport(
  result: ComplyCommandResult,
  colors: {
    neuralCyan: (s: string) => string;
    synapseViolet: (s: string) => string;
    errorRed: (s: string) => string;
    brainPink: (s: string) => string;
    dim: (s: string) => string;
    bold: (s: string) => string;
  },
): void {
  const { report } = result;

  // Header
  console.log(`\n${colors.brainPink('━'.repeat(60))}`);
  console.log(colors.bold('  CORTEX COMPLIANCE AUDIT'));
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
  console.log(
    `  Frameworks: ${colors.dim(report.frameworks.map((f) => f.toUpperCase()).join(', '))}`,
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
      `  L${String(layer.layer).padStart(2, ' ')} ${layer.name.padEnd(36)} ${bar} ${layerColor(`${layer.score.toFixed(1)}/${layer.weight}`)} ${colors.dim(layer.grade)}`,
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

  // Framework compliance rates
  if (report.frameworkMatrices.length > 0) {
    console.log(`\n${colors.bold('  Framework Compliance:')}`);
    for (const matrix of report.frameworkMatrices) {
      const rateColor =
        matrix.complianceRate >= 70
          ? colors.neuralCyan
          : matrix.complianceRate >= 40
            ? colors.synapseViolet
            : colors.errorRed;
      console.log(
        `    ${matrix.framework.toUpperCase().padEnd(6)} ${rateColor(`${matrix.complianceRate}%`)}`,
      );
    }
  }

  // Data flow summary
  if (report.dataFlow.totalDataTypes > 0) {
    console.log(
      `\n${colors.bold('  Data Flow:')} ${report.dataFlow.totalDataTypes} data types collected`,
    );
    console.log(`    Consent coverage:    ${report.dataFlow.consentCoverage}%`);
    console.log(`    Encryption coverage: ${report.dataFlow.encryptionCoverage}%`);
  }

  // Remediation hint
  const immediateCount = report.remediationRoadmap.immediate.length;
  if (immediateCount > 0) {
    console.log(
      `\n  ${colors.synapseViolet(`${immediateCount} immediate fix(es) available`)} — use --output markdown for details`,
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
