/**
 * Report generation for cortex comply — Markdown + JSON output.
 */

import type { ComplyFinding, ComplyReport } from './types.js';

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function severityBadge(severity: string): string {
  return `[${severity.toUpperCase()}]`;
}

function formatScore(score: number, weight: number): string {
  return `${score.toFixed(1)}/${weight}`;
}

function generateExecutiveSummary(report: ComplyReport): string {
  const criticalCount = report.findings.filter((f) => f.severity === 'critical').length;
  const highCount = report.findings.filter((f) => f.severity === 'high').length;
  const mediumCount = report.findings.filter((f) => f.severity === 'medium').length;
  const lowCount = report.findings.filter((f) => f.severity === 'low').length;
  const infoCount = report.findings.filter((f) => f.severity === 'info').length;

  let status: string;
  if (report.score.global >= 80) status = 'GOOD — Compliance posture is strong';
  else if (report.score.global >= 60) status = 'FAIR — Some compliance gaps need attention';
  else if (report.score.global >= 35) status = 'POOR — Significant compliance gaps present';
  else status = 'CRITICAL — Immediate compliance action required';

  const frameworkRates = report.frameworkMatrices
    .map((m) => `${m.framework.toUpperCase()}: ${m.complianceRate}%`)
    .join(', ');

  const lines = [
    '## Executive Summary',
    '',
    '| Metric | Value |',
    '|--------|-------|',
    `| **Score** | **${report.score.global}/100** |`,
    `| **Grade** | **${report.score.grade}** |`,
    `| **Status** | ${status} |`,
    `| **Frameworks** | ${report.frameworks.map((f) => f.toUpperCase()).join(', ')} |`,
    `| **Findings** | ${report.findings.length} total |`,
    `| Critical | ${criticalCount} |`,
    `| High | ${highCount} |`,
    `| Medium | ${mediumCount} |`,
    `| Low | ${lowCount} |`,
    `| Info | ${infoCount} |`,
    `| **Stack** | ${report.project.stack.join(', ') || 'Unknown'} |`,
    `| **Compliance Rates** | ${frameworkRates || 'N/A'} |`,
    '',
  ];

  return lines.join('\n');
}

function generateScorecard(report: ComplyReport): string {
  const lines = [
    '## Compliance Scorecard',
    '',
    '| # | Layer | Score | Grade | Checks |',
    '|---|-------|-------|-------|--------|',
  ];

  const sortedLayers = Object.values(report.score.layers).sort((a, b) => a.layer - b.layer);
  for (const layer of sortedLayers) {
    lines.push(
      `| L${layer.layer} | ${layer.name} | ${formatScore(layer.score, layer.weight)} | ${layer.grade} | ${layer.passed}/${layer.total} |`,
    );
  }

  lines.push('');
  return lines.join('\n');
}

function generateCriticalFindings(report: ComplyReport): string {
  const criticals = report.findings
    .filter((f) => f.severity === 'critical' || f.severity === 'high')
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4));

  if (criticals.length === 0) {
    return '## Critical & High Findings\n\nNo critical or high severity findings.\n\n';
  }

  const lines = [
    '## Critical & High Findings',
    '',
    '| ID | Severity | Title | Regulation | File | Effort |',
    '|----|----------|-------|------------|------|--------|',
  ];

  for (const f of criticals) {
    const file = f.evidence.file.length > 30 ? `...${f.evidence.file.slice(-27)}` : f.evidence.file;
    const regulation = f.regulation
      .map((r) => `${r.framework.toUpperCase()} ${r.article}`)
      .join(', ');
    const regTruncated = regulation.length > 35 ? `${regulation.substring(0, 32)}...` : regulation;
    lines.push(
      `| ${f.id} | ${severityBadge(f.severity)} | ${f.title} | ${regTruncated} | ${file} | ${f.fix.effort} |`,
    );
  }

  lines.push('');
  return lines.join('\n');
}

function generateFrameworkMatrices(report: ComplyReport): string {
  if (report.frameworkMatrices.length === 0) {
    return '## Framework Compliance Matrices\n\nNo frameworks selected.\n\n';
  }

  const sections: string[] = ['## Framework Compliance Matrices', ''];

  for (const matrix of report.frameworkMatrices) {
    sections.push(
      `### ${matrix.framework.toUpperCase()} — ${matrix.complianceRate}% Compliance Rate`,
    );
    sections.push('');
    sections.push('| Article | Title | Status | Findings |');
    sections.push('|---------|-------|--------|----------|');

    for (const item of matrix.items) {
      const statusLabel =
        item.status === 'compliant'
          ? 'COMPLIANT'
          : item.status === 'non-compliant'
            ? 'NON-COMPLIANT'
            : item.status === 'partial'
              ? 'PARTIAL'
              : 'N/A';
      sections.push(
        `| ${item.article} | ${item.title} | ${statusLabel} | ${item.findings.length > 0 ? item.findings.join(', ') : '-'} |`,
      );
    }

    sections.push('');
  }

  return sections.join('\n');
}

function generateDataFlowSummary(report: ComplyReport): string {
  const df = report.dataFlow;

  if (df.totalDataTypes === 0) {
    return '## Data Flow Summary\n\nNo PII data flows detected.\n\n';
  }

  const lines = [
    '## Data Flow Summary',
    '',
    '| Metric | Value |',
    '|--------|-------|',
    `| Data Types Collected | ${df.totalDataTypes} |`,
    `| Consent Coverage | ${df.consentCoverage}% |`,
    `| Encryption Coverage | ${df.encryptionCoverage}% |`,
    '',
  ];

  if (df.items.length > 0) {
    lines.push('| Data Type | Category | Consent | Encrypted | Retention |');
    lines.push('|-----------|----------|---------|-----------|-----------|');

    for (const item of df.items) {
      lines.push(
        `| ${item.dataType} | ${item.category} | ${item.hasConsent ? 'Yes' : 'No'} | ${item.hasEncryption ? 'Yes' : 'No'} | ${item.hasRetentionPolicy ? 'Yes' : 'No'} |`,
      );
    }

    lines.push('');
  }

  return lines.join('\n');
}

function generateStrengths(report: ComplyReport): string {
  const strengths: string[] = [];

  const sortedLayers = Object.values(report.score.layers).sort((a, b) => a.layer - b.layer);

  for (const layer of sortedLayers) {
    if (layer.score >= layer.weight * 0.8) {
      strengths.push(
        `- **L${layer.layer} ${layer.name}**: ${layer.grade} — ${layer.passed}/${layer.total} checks passed`,
      );
    }
  }

  for (const matrix of report.frameworkMatrices) {
    if (matrix.complianceRate >= 70) {
      strengths.push(
        `- **${matrix.framework.toUpperCase()} Compliance**: ${matrix.complianceRate}%`,
      );
    }
  }

  if (report.findings.filter((f) => f.severity === 'critical').length === 0) {
    strengths.push('- **Zero critical compliance findings detected**');
  }

  if (strengths.length === 0) {
    return '## Strengths\n\nNo significant compliance strengths identified. Focus on addressing critical findings first.\n\n';
  }

  return `## Strengths\n\n${strengths.join('\n')}\n\n`;
}

function generateRemediationRoadmap(report: ComplyReport): string {
  const rm = report.remediationRoadmap;

  const lines = [
    '## Remediation Roadmap',
    '',
    `**Total**: ${rm.totalFindings} findings | **Auto-fixable**: ${rm.automatable}`,
    '',
  ];

  if (rm.immediate.length > 0) {
    lines.push('### Immediate (this week)');
    lines.push('');
    for (const item of rm.immediate) {
      lines.push(
        `- ${severityBadge(item.severity)} **${item.findingId}**: ${item.title}${item.automated ? ' [auto-fix]' : ''}`,
      );
    }
    lines.push('');
  }

  if (rm.sprint.length > 0) {
    lines.push('### Sprint (this cycle)');
    lines.push('');
    for (const item of rm.sprint) {
      lines.push(
        `- ${severityBadge(item.severity)} **${item.findingId}**: ${item.title}${item.automated ? ' [auto-fix]' : ''}`,
      );
    }
    lines.push('');
  }

  if (rm.quarter.length > 0) {
    lines.push('### Quarter (planned)');
    lines.push('');
    for (const item of rm.quarter) {
      lines.push(`- ${severityBadge(item.severity)} **${item.findingId}**: ${item.title}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

function generateDetailedFindings(report: ComplyReport): string {
  if (report.findings.length === 0) {
    return '## Detailed Findings\n\nNo findings to report.\n\n';
  }

  const sorted = [...report.findings].sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4),
  );

  const lines = ['## Detailed Findings', ''];

  const bySeverity = new Map<string, ComplyFinding[]>();
  for (const f of sorted) {
    const existing = bySeverity.get(f.severity) ?? [];
    existing.push(f);
    bySeverity.set(f.severity, existing);
  }

  for (const [severity, findings] of bySeverity) {
    lines.push(
      `### ${severityBadge(severity)} ${severity.charAt(0).toUpperCase() + severity.slice(1)} (${findings.length})`,
    );
    lines.push('');

    for (const f of findings) {
      lines.push(`#### ${f.id}: ${f.title}`);
      lines.push('');
      lines.push(`- **Layer**: L${f.layer} — ${f.layerName}`);
      const regs = f.regulation
        .map((r) => `${r.framework.toUpperCase()} ${r.article} (${r.title})`)
        .join(' | ');
      lines.push(`- **Regulation**: ${regs}`);
      lines.push(`- **Impact**: ${f.impact}`);
      lines.push(`- **File**: ${f.evidence.file}${f.evidence.line ? `:${f.evidence.line}` : ''}`);
      if (f.evidence.snippet) {
        lines.push(`- **Evidence**: \`${f.evidence.snippet.substring(0, 100)}\``);
      }
      lines.push('');
      lines.push(`**Fix** (${f.fix.effort}${f.fix.automated ? ', auto-fixable' : ''}):`);
      lines.push(f.fix.description);
      lines.push('');
    }
  }

  return lines.join('\n');
}

export function generateComplyMarkdown(report: ComplyReport): string {
  const sections = [
    '# Cortex Compliance Audit Report',
    '',
    `> **Project**: ${report.project.name} | **Date**: ${report.timestamp.split('T')[0]} | **Version**: ${report.version}`,
    '',
    generateExecutiveSummary(report),
    generateScorecard(report),
    generateCriticalFindings(report),
    generateStrengths(report),
    generateFrameworkMatrices(report),
    generateDataFlowSummary(report),
    generateRemediationRoadmap(report),
    generateDetailedFindings(report),
    '---',
    `*Generated by Cortex Compliance Analyzer v${report.version}*`,
    '',
  ];

  return sections.join('\n');
}

export function generateComplyJSON(report: ComplyReport): string {
  return JSON.stringify(report, null, 2);
}
