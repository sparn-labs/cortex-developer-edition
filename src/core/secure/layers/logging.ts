/**
 * Layer 9 — Logging & Monitoring (8%)
 * OWASP A09:2025 — Security Logging and Monitoring Failures
 */

import type { LayerResult, SecureFinding } from '../types.js';
import { getLayerName, getLayerWeight } from '../types.js';

const LAYER = 9;
const WEIGHT = getLayerWeight(LAYER);
const NAME = getLayerName(LAYER);

function isTestFile(path: string): boolean {
  return /\.(test|spec)\.|__tests__|\/tests\/|\/fixtures\/|benchmarks\/|\.bench\./i.test(path);
}

function isSecureFile(path: string): boolean {
  return /secure\/|layers\//.test(path) && path.endsWith('.ts');
}

function isNonCodeFile(path: string): boolean {
  return /\.md$|\.txt$|\.ya?ml$|\/docs?\//i.test(path);
}

function getLineNumber(content: string, index: number): number {
  return content.substring(0, index).split('\n').length;
}

function checkAuditLogging(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let hasAuthEvents = false;
  let hasAuthLogging = false;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;

    if (/(?:login|logout|signin|signout|authenticate)/i.test(content)) {
      hasAuthEvents = true;
      if (
        /(?:log|logger|audit|winston|pino|bunyan).*(?:login|logout|auth|sign)/i.test(content) ||
        /(?:login|logout|auth|sign).*(?:log|logger|audit)/i.test(content)
      ) {
        hasAuthLogging = true;
      }
    }
  }

  if (hasAuthEvents && !hasAuthLogging) {
    findings.push({
      id: 'SEC-LOG-001',
      severity: 'medium',
      layer: LAYER,
      layerName: NAME,
      owasp: 'A09:2025',
      cwe: 'CWE-778',
      title: 'Authentication events not logged',
      description: 'Login/logout events are not captured in audit logs',
      impact: 'Security incidents cannot be detected or investigated',
      evidence: { file: 'authentication handlers' },
      fix: {
        description: 'Add audit logging for all authentication events (login, logout, failures)',
        effort: 'sprint',
        automated: false,
      },
      references: ['https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html'],
    });
    return { passed: 0, total: 1 };
  }

  return { passed: 1, total: 1 };
}

function checkLogInjection(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;

    // User input directly in log statements
    const logInjection =
      /(?:console\.(?:log|info|warn|error)|logger\.(?:log|info|warn|error))\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.)[^)]*\)/gi;
    const match = logInjection.exec(content);

    if (match) {
      total++;
      // Check for sanitization
      if (
        !/(?:sanitize|escape|encode|strip|replace\()/i.test(
          content.substring(Math.max(0, match.index - 200), match.index + match[0].length),
        )
      ) {
        issues++;
        findings.push({
          id: 'SEC-LOG-002',
          severity: 'medium',
          layer: LAYER,
          layerName: NAME,
          owasp: 'A09:2025',
          cwe: 'CWE-117',
          title: 'Log injection — unsanitized user input in logs',
          description: `${filePath} logs user-supplied data without sanitization`,
          impact: 'Attackers can inject fake log entries or corrupt log files',
          evidence: {
            file: filePath,
            line: getLineNumber(content, match.index),
            snippet: match[0].substring(0, 80),
          },
          fix: {
            description:
              'Sanitize user input before logging — strip newlines and control characters',
            effort: 'immediate',
            automated: false,
          },
          references: ['https://cwe.mitre.org/data/definitions/117.html'],
        });
      }
    }
  }

  return { passed: Math.max(1, total) - issues, total: Math.max(total, 1) };
}

function checkSensitiveDataInLogs(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath) || isNonCodeFile(filePath)) continue;

    const sensitiveLogPatterns = [
      {
        pattern: /(?:console|logger)\.(?:log|info|debug)\s*\([^)]*(?:password|passwd|pwd)[^)]*\)/gi,
        name: 'password',
      },
      {
        pattern:
          /(?:console|logger)\.(?:log|info|debug)\s*\([^)]*(?:(?<!\w)(?:api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token|bearer|credentials)\b)[^)]*\)/gi,
        name: 'secret/credential',
      },
      {
        pattern:
          /(?:console|logger)\.(?:log|info|debug)\s*\([^)]*(?:ssn|social.?security|credit.?card)[^)]*\)/gi,
        name: 'PII',
      },
    ];

    for (const { pattern, name } of sensitiveLogPatterns) {
      const match = pattern.exec(content);
      if (match) {
        total++;
        issues++;
        findings.push({
          id: 'SEC-LOG-003',
          severity: 'high',
          layer: LAYER,
          layerName: NAME,
          owasp: 'A09:2025',
          cwe: 'CWE-532',
          title: `Sensitive data in logs: ${name}`,
          description: `${filePath} may log ${name} data`,
          impact: 'Sensitive data exposed in log files, accessible to operations staff',
          evidence: {
            file: filePath,
            line: getLineNumber(content, match.index),
            snippet: match[0].substring(0, 80),
          },
          fix: {
            description: `Mask or redact ${name} data before logging`,
            effort: 'immediate',
            automated: false,
          },
          references: ['https://cwe.mitre.org/data/definitions/532.html'],
        });
        break;
      }
    }
  }

  return { passed: Math.max(1, total) - issues, total: Math.max(total, 1) };
}

function checkStructuredLogging(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  const allContent = [...files.values()].join('\n');

  const hasStructuredLogger =
    /(?:winston|pino|bunyan|serilog|log4j|structured.?log|createLogger)/i.test(allContent);
  const hasConsoleLog = /console\.(log|info|warn|error)\s*\(/i.test(allContent);

  if (hasConsoleLog && !hasStructuredLogger) {
    findings.push({
      id: 'SEC-LOG-004',
      severity: 'low',
      layer: LAYER,
      layerName: NAME,
      owasp: 'A09:2025',
      cwe: 'CWE-778',
      title: 'No structured logging library detected',
      description: 'Application uses console.log instead of a structured logging library',
      impact: 'Logs are hard to parse, search, and monitor for security events',
      evidence: { file: 'project-wide' },
      fix: {
        description: 'Use a structured logging library like pino or winston with JSON output',
        effort: 'sprint',
        automated: false,
      },
      references: ['https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html'],
    });
    return { passed: 0, total: 1 };
  }

  return { passed: 1, total: 1 };
}

function checkErrorLogging(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  const allContent = [...files.values()].join('\n');

  const hasUncaughtHandler =
    /(?:uncaughtException|unhandledRejection|process\.on\s*\(\s*['"](?:uncaughtException|unhandledRejection)['"])/i.test(
      allContent,
    );

  if (!hasUncaughtHandler) {
    findings.push({
      id: 'SEC-LOG-005',
      severity: 'low',
      layer: LAYER,
      layerName: NAME,
      owasp: 'A09:2025',
      cwe: 'CWE-755',
      title: 'No uncaught exception handler',
      description: 'No process.on("uncaughtException") or process.on("unhandledRejection") handler',
      impact: 'Unhandled errors may crash the process without proper logging',
      evidence: { file: 'process-level error handling' },
      fix: {
        description: 'Add process-level handlers for uncaughtException and unhandledRejection',
        effort: 'immediate',
        automated: false,
      },
      references: ['https://nodejs.org/api/process.html#event-uncaughtexception'],
    });
    return { passed: 0, total: 1 };
  }

  return { passed: 1, total: 1 };
}

export async function runLoggingLayer(
  files: Map<string, string>,
  _stackTags: Set<string>,
  _projectRoot: string,
): Promise<LayerResult> {
  const findings: SecureFinding[] = [];

  const checks = [
    checkAuditLogging(files, findings),
    checkLogInjection(files, findings),
    checkSensitiveDataInLogs(files, findings),
    checkStructuredLogging(files, findings),
    checkErrorLogging(files, findings),
  ];

  const totalPassed = checks.reduce((s, c) => s + c.passed, 0);
  const totalChecks = checks.reduce((s, c) => s + c.total, 0);

  const ratio = totalChecks > 0 ? totalPassed / totalChecks : 1;
  const score = Math.round(ratio * WEIGHT * 100) / 100;

  return {
    layer: LAYER,
    name: NAME,
    weight: WEIGHT,
    checksPassed: totalPassed,
    checksTotal: totalChecks,
    score,
    findings,
  };
}
