/**
 * Layer 10 — Error Handling & Resilience (5%)
 * OWASP — Improper Error Handling
 */

import type { LayerResult, SecureFinding } from '../types.js';
import { getLayerName, getLayerWeight } from '../types.js';

const LAYER = 10;
const WEIGHT = getLayerWeight(LAYER);
const NAME = getLayerName(LAYER);

function isTestFile(path: string): boolean {
  return /\.(test|spec)\.|__tests__|\/tests\/|\/fixtures\/|benchmarks\/|\.bench\./i.test(path);
}

function isSecureFile(path: string): boolean {
  return /secure\/|layers\//.test(path) && path.endsWith('.ts');
}

function getLineNumber(content: string, index: number): number {
  return content.substring(0, index).split('\n').length;
}

function checkGlobalErrorHandler(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  const allContent = [...files.values()].join('\n');

  // Express error middleware (4 params) or global error handler
  const hasGlobalHandler =
    /(?:app\.use\s*\(\s*(?:function\s*)?\([^)]*err[^)]*,[^)]*req[^)]*,[^)]*res[^)]*,[^)]*next|errorHandler|globalExceptionFilter|UseExceptionHandler)/i.test(
      allContent,
    );

  if (!hasGlobalHandler) {
    findings.push({
      id: 'SEC-EX-001',
      severity: 'medium',
      layer: LAYER,
      layerName: NAME,
      owasp: 'A05:2025',
      cwe: 'CWE-755',
      title: 'No global error handler middleware',
      description: 'No Express 4-param error handler or global exception filter detected',
      impact: 'Unhandled errors may leak stack traces or crash the server',
      evidence: { file: 'server configuration' },
      fix: {
        description: 'Add a global error handling middleware as the last app.use()',
        codeAfter:
          'app.use((err, req, res, next) => {\n  logger.error(err);\n  res.status(500).json({ error: "Internal Server Error" });\n});',
        effort: 'immediate',
        automated: false,
      },
      references: ['https://expressjs.com/en/guide/error-handling.html'],
    });
    return { passed: 0, total: 1 };
  }

  return { passed: 1, total: 1 };
}

function checkStackTraceLeaks(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;

    // Stack traces sent to client
    const patterns = [
      /res\.(?:json|send)\s*\([^)]*err(?:or)?\.stack/gi,
      /res\.(?:json|send)\s*\([^)]*\.stack/gi,
      /res\.status\s*\([^)]*\)\.(?:json|send)\s*\([^)]*stack/gi,
    ];

    for (const pattern of patterns) {
      const match = pattern.exec(content);
      if (match) {
        total++;
        issues++;
        findings.push({
          id: 'SEC-EX-002',
          severity: 'medium',
          layer: LAYER,
          layerName: NAME,
          owasp: 'A05:2025',
          cwe: 'CWE-209',
          title: 'Stack trace leaked to client',
          description: `${filePath} sends error stack trace in HTTP response`,
          impact: 'Internal code structure and file paths exposed to attackers',
          evidence: {
            file: filePath,
            line: getLineNumber(content, match.index),
            snippet: match[0].substring(0, 60),
          },
          fix: {
            description: 'Return generic error messages to clients, log stack traces server-side',
            effort: 'immediate',
            automated: false,
          },
          references: ['https://cwe.mitre.org/data/definitions/209.html'],
        });
        break;
      }
    }
  }

  return { passed: Math.max(1, total) - issues, total: Math.max(total, 1) };
}

function checkTimeouts(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  const allContent = [...files.values()].join('\n');

  const hasServer = /(?:createServer|app\.listen|express\(\))/i.test(allContent);
  if (!hasServer) return { passed: 1, total: 1 };

  const hasTimeout =
    /(?:timeout|keepAliveTimeout|headersTimeout|requestTimeout|server\.timeout)/i.test(allContent);

  if (!hasTimeout) {
    findings.push({
      id: 'SEC-EX-003',
      severity: 'low',
      layer: LAYER,
      layerName: NAME,
      owasp: 'A05:2025',
      cwe: 'CWE-400',
      title: 'No HTTP/DB timeout configuration detected',
      description: 'Server does not configure request timeouts explicitly',
      impact: 'Slow requests can consume resources indefinitely (Slowloris attack)',
      evidence: { file: 'server configuration' },
      fix: {
        description: 'Set server.timeout, keepAliveTimeout, and headersTimeout',
        effort: 'immediate',
        automated: false,
      },
      references: ['https://nodejs.org/api/http.html#servertimeout'],
    });
    return { passed: 0, total: 1 };
  }

  return { passed: 1, total: 1 };
}

function checkResourceLimits(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  const allContent = [...files.values()].join('\n');

  const hasServer = /(?:app\.listen|express\(\)|createServer)/i.test(allContent);
  if (!hasServer) return { passed: 1, total: 1 };

  const checks: string[] = [];

  // File upload limits
  if (/(?:multer|upload|multipart|formidable)/i.test(allContent)) {
    if (!/(?:limits|maxFileSize|fileSizeLimit|maxSize)/i.test(allContent)) {
      checks.push('file upload size limit');
    }
  }

  // Request body size limits
  if (/(?:express\.json|bodyParser|body-parser)/i.test(allContent)) {
    if (!/limit\s*:/i.test(allContent)) {
      checks.push('request body size limit');
    }
  }

  if (checks.length > 0) {
    findings.push({
      id: 'SEC-EX-004',
      severity: 'medium',
      layer: LAYER,
      layerName: NAME,
      owasp: 'A05:2025',
      cwe: 'CWE-770',
      title: `Missing resource limits: ${checks.join(', ')}`,
      description: `Server does not configure ${checks.join(', ')}`,
      impact: 'Large payloads can exhaust server memory and cause denial of service',
      evidence: { file: 'server configuration' },
      fix: {
        description: 'Configure limits for file uploads and request body size',
        codeAfter: "app.use(express.json({ limit: '1mb' }));",
        effort: 'immediate',
        automated: true,
      },
      references: ['https://expressjs.com/en/api.html#express.json'],
    });
    return { passed: 0, total: 1 };
  }

  return { passed: 1, total: 1 };
}

function checkUnhandledPromise(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  const allContent = [...files.values()].join('\n');

  const hasUnhandledRejection = /process\.on\s*\(\s*['"]unhandledRejection['"]/i.test(allContent);

  if (!hasUnhandledRejection) {
    findings.push({
      id: 'SEC-EX-005',
      severity: 'low',
      layer: LAYER,
      layerName: NAME,
      owasp: 'A05:2025',
      cwe: 'CWE-755',
      title: 'No unhandledRejection handler',
      description:
        'Missing process.on("unhandledRejection") — unhandled promises may crash Node 15+',
      impact: 'Unhandled promise rejections crash the process in modern Node.js',
      evidence: { file: 'process-level error handling' },
      fix: {
        description:
          'Add process.on("unhandledRejection") handler to log and gracefully handle rejections',
        effort: 'immediate',
        automated: false,
      },
      references: ['https://nodejs.org/api/process.html#event-unhandledrejection'],
    });
    return { passed: 0, total: 1 };
  }

  return { passed: 1, total: 1 };
}

export async function runExceptionsLayer(
  files: Map<string, string>,
  _stackTags: Set<string>,
  _projectRoot: string,
): Promise<LayerResult> {
  const findings: SecureFinding[] = [];

  const checks = [
    checkGlobalErrorHandler(files, findings),
    checkStackTraceLeaks(files, findings),
    checkTimeouts(files, findings),
    checkResourceLimits(files, findings),
    checkUnhandledPromise(files, findings),
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
