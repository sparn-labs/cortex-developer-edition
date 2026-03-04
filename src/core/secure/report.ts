/**
 * Report generation for cortex secure — Markdown + JSON output.
 */

import type { SecureFinding, SecureReport } from './types.js';

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function gradeColor(grade: string): string {
  if (grade === 'S' || grade.startsWith('A')) return grade;
  if (grade.startsWith('B')) return grade;
  return grade;
}

function severityBadge(severity: string): string {
  return `[${severity.toUpperCase()}]`;
}

function formatScore(score: number, weight: number): string {
  return `${score.toFixed(1)}/${weight}`;
}

function generateExecutiveSummary(report: SecureReport): string {
  const criticalCount = report.findings.filter((f) => f.severity === 'critical').length;
  const highCount = report.findings.filter((f) => f.severity === 'high').length;
  const mediumCount = report.findings.filter((f) => f.severity === 'medium').length;
  const lowCount = report.findings.filter((f) => f.severity === 'low').length;
  const infoCount = report.findings.filter((f) => f.severity === 'info').length;

  let status: string;
  if (report.score.global >= 80) status = 'GOOD — Security posture is strong';
  else if (report.score.global >= 60) status = 'FAIR — Some improvements needed';
  else if (report.score.global >= 35) status = 'POOR — Significant vulnerabilities present';
  else status = 'CRITICAL — Immediate action required';

  const lines = [
    `## Executive Summary`,
    '',
    `| Metric | Value |`,
    `|--------|-------|`,
    `| **Score** | **${report.score.global}/100** |`,
    `| **Grade** | **${gradeColor(report.score.grade)}** |`,
    `| **Status** | ${status} |`,
    `| **Findings** | ${report.findings.length} total |`,
    `| Critical | ${criticalCount} |`,
    `| High | ${highCount} |`,
    `| Medium | ${mediumCount} |`,
    `| Low | ${lowCount} |`,
    `| Info | ${infoCount} |`,
    `| **Stack** | ${report.project.stack.join(', ') || 'Unknown'} |`,
    `| **Compliance** | ${report.compliance.framework}: ${report.compliance.passRate}% |`,
    '',
  ];

  return lines.join('\n');
}

function generateScorecard(report: SecureReport): string {
  const lines = [
    '## Security Scorecard',
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

function generateCriticalFindings(report: SecureReport): string {
  const criticals = report.findings
    .filter((f) => f.severity === 'critical' || f.severity === 'high')
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4));

  if (criticals.length === 0) {
    return '## Critical & High Findings\n\nNo critical or high severity findings.\n\n';
  }

  const lines = [
    '## Critical & High Findings',
    '',
    '| ID | Severity | Title | OWASP | File | Effort |',
    '|----|----------|-------|-------|------|--------|',
  ];

  for (const f of criticals) {
    const file = f.evidence.file.length > 30 ? `...${f.evidence.file.slice(-27)}` : f.evidence.file;
    lines.push(
      `| ${f.id} | ${severityBadge(f.severity)} | ${f.title} | ${f.owasp} | ${file} | ${f.fix.effort} |`,
    );
  }

  lines.push('');
  return lines.join('\n');
}

function generateDetailedFindings(report: SecureReport): string {
  if (report.findings.length === 0) {
    return '## Detailed Findings\n\nNo findings to report.\n\n';
  }

  const sorted = [...report.findings].sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4),
  );

  const lines = ['## Detailed Findings', ''];

  // Group by severity
  const bySeverity = new Map<string, SecureFinding[]>();
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
      lines.push(
        `- **OWASP**: ${f.owasp}${f.cwe ? ` | ${f.cwe}` : ''}${f.cvss ? ` | CVSS ${f.cvss}` : ''}`,
      );
      lines.push(`- **Impact**: ${f.impact}`);
      lines.push(`- **File**: ${f.evidence.file}${f.evidence.line ? `:${f.evidence.line}` : ''}`);
      if (f.evidence.snippet) {
        lines.push(`- **Evidence**: \`${f.evidence.snippet.substring(0, 100)}\``);
      }
      lines.push('');
      lines.push(`**Fix** (${f.fix.effort}${f.fix.automated ? ', auto-fixable' : ''}):`);
      lines.push(f.fix.description);
      if (f.fix.codeBefore || f.fix.codeAfter) {
        if (f.fix.codeBefore) {
          lines.push('```diff');
          lines.push(`- ${f.fix.codeBefore}`);
          lines.push('```');
        }
        if (f.fix.codeAfter) {
          lines.push('```diff');
          lines.push(`+ ${f.fix.codeAfter}`);
          lines.push('```');
        }
      }
      lines.push('');
    }
  }

  return lines.join('\n');
}

function generateStrengths(report: SecureReport): string {
  const strengths: string[] = [];

  const sortedLayers = Object.values(report.score.layers).sort((a, b) => a.layer - b.layer);

  for (const layer of sortedLayers) {
    if (layer.score >= layer.weight * 0.8) {
      strengths.push(
        `- **L${layer.layer} ${layer.name}**: ${layer.grade} — ${layer.passed}/${layer.total} checks passed`,
      );
    }
  }

  if (report.compliance.passRate >= 70) {
    strengths.push(`- **Compliance**: ${report.compliance.passRate}% OWASP Top 10 coverage`);
  }

  if (report.findings.filter((f) => f.severity === 'critical').length === 0) {
    strengths.push('- **Zero critical vulnerabilities detected**');
  }

  if (strengths.length === 0) {
    return '## Strengths\n\nNo significant security strengths identified. Focus on addressing critical findings first.\n\n';
  }

  return `## Strengths\n\n${strengths.join('\n')}\n\n`;
}

function generateComplianceMatrix(report: SecureReport): string {
  const lines = [
    '## Compliance Matrix',
    '',
    `**Framework**: ${report.compliance.framework.toUpperCase()} | **Pass Rate**: ${report.compliance.passRate}%`,
    '',
    '| Control | Description | Status | Findings |',
    '|---------|-------------|--------|----------|',
  ];

  for (const item of report.compliance.items) {
    const statusIcon =
      item.status === 'pass'
        ? 'PASS'
        : item.status === 'fail'
          ? 'FAIL'
          : item.status === 'partial'
            ? 'PARTIAL'
            : 'N/A';
    lines.push(
      `| ${item.control} | ${item.description} | ${statusIcon} | ${item.findings.length > 0 ? item.findings.join(', ') : '-'} |`,
    );
  }

  lines.push('');
  return lines.join('\n');
}

function generateAttackSurface(report: SecureReport): string {
  const as = report.attackSurface;

  return [
    '## Attack Surface Summary',
    '',
    '| Metric | Count |',
    '|--------|-------|',
    `| API Endpoints | ${as.totalEndpoints} |`,
    `| Authenticated | ${as.authenticatedEndpoints} |`,
    `| Unauthenticated | ${as.unauthenticatedEndpoints} |`,
    `| Rate Limited | ${as.rateLimitedEndpoints} |`,
    `| Public Files | ${as.publicFiles} |`,
    `| External Dependencies | ${as.externalDependencies} |`,
    `| Input Points | ${as.inputPoints} |`,
    `| Crypto Usages | ${as.cryptoUsages} |`,
    '',
  ].join('\n');
}

function generateRemediationRoadmap(report: SecureReport): string {
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

export function generateSecureMarkdown(report: SecureReport): string {
  const sections = [
    `# Cortex Security Audit Report`,
    '',
    `> **Project**: ${report.project.name} | **Date**: ${report.timestamp.split('T')[0]} | **Version**: ${report.version}`,
    '',
    generateExecutiveSummary(report),
    generateScorecard(report),
    generateCriticalFindings(report),
    generateStrengths(report),
    generateComplianceMatrix(report),
    generateAttackSurface(report),
    generateRemediationRoadmap(report),
    generateDetailedFindings(report),
    '---',
    `*Generated by Cortex Security Analyzer v${report.version}*`,
    '',
  ];

  return sections.join('\n');
}

export function generateSecureJSON(report: SecureReport): string {
  return JSON.stringify(report, null, 2);
}
