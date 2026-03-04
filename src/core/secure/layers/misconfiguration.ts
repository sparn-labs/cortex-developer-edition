/**
 * Layer 2 — Security Misconfiguration (12%)
 * OWASP A05:2025 — Security Misconfiguration
 */

import type { LayerResult, SecureFinding } from '../types.js';
import { getLayerName, getLayerWeight } from '../types.js';

const LAYER = 2;
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

function checkSecurityHeaders(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  const requiredHeaders = [
    { name: 'Strict-Transport-Security', pattern: /strict-transport-security|hsts/i },
    { name: 'Content-Security-Policy', pattern: /content-security-policy|csp/i },
    { name: 'X-Content-Type-Options', pattern: /x-content-type-options|nosniff/i },
    { name: 'X-Frame-Options', pattern: /x-frame-options|frameguard|frame-options/i },
    { name: 'Referrer-Policy', pattern: /referrer-policy/i },
    { name: 'Permissions-Policy', pattern: /permissions-policy|feature-policy/i },
  ];

  // Check if helmet or similar security middleware is used
  const allContent = [...files.values()].join('\n');
  const hasHelmet = /helmet\(|app\.use\s*\(\s*helmet/i.test(allContent);

  if (hasHelmet) return { passed: requiredHeaders.length, total: requiredHeaders.length };

  let passed = 0;
  const missing: string[] = [];

  for (const header of requiredHeaders) {
    if (header.pattern.test(allContent)) {
      passed++;
    } else {
      missing.push(header.name);
    }
  }

  if (missing.length > 0) {
    findings.push({
      id: 'SEC-MC-001',
      severity: 'medium',
      layer: LAYER,
      layerName: NAME,
      owasp: 'A05:2025',
      cwe: 'CWE-693',
      title: `Missing security headers: ${missing.join(', ')}`,
      description: `Project does not set ${missing.length} required security headers`,
      impact: 'Browser security features are not enabled, increasing attack surface',
      evidence: { file: 'server configuration' },
      fix: {
        description: 'Use helmet middleware or manually set all required security headers',
        codeAfter: "import helmet from 'helmet';\napp.use(helmet());",
        effort: 'immediate',
        automated: true,
      },
      references: ['https://owasp.org/www-project-secure-headers/'],
    });
  }

  return { passed, total: requiredHeaders.length };
}

function checkDebugMode(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;

    const debugPatterns = [
      { pattern: /DEBUG\s*[:=]\s*(?:true|1|['"]true['"])/gi, name: 'DEBUG flag enabled' },
      { pattern: /NODE_ENV\s*[:=]\s*['"]development['"]/g, name: 'NODE_ENV set to development' },
      {
        pattern: /ASPNETCORE_ENVIRONMENT\s*[:=]\s*['"]Development['"]/g,
        name: '.NET Development mode',
      },
    ];

    // Only check config-like files
    if (!/config|env|setting|\.yaml|\.yml|\.json|\.toml/i.test(filePath)) continue;

    for (const { pattern, name } of debugPatterns) {
      const match = pattern.exec(content);
      if (match) {
        total++;
        issues++;
        findings.push({
          id: 'SEC-MC-002',
          severity: 'high',
          layer: LAYER,
          layerName: NAME,
          owasp: 'A05:2025',
          cwe: 'CWE-489',
          title: `Debug mode in production config: ${name}`,
          description: `${filePath} has debug/development mode enabled`,
          impact: 'Verbose errors, stack traces, and debug endpoints exposed in production',
          evidence: {
            file: filePath,
            line: getLineNumber(content, match.index),
            snippet: match[0],
          },
          fix: {
            description: 'Set DEBUG=false and NODE_ENV=production in production configs',
            effort: 'immediate',
            automated: true,
          },
          references: ['https://cwe.mitre.org/data/definitions/489.html'],
        });
      }
    }
  }

  return { passed: Math.max(1, total) - issues, total: Math.max(total, 1) };
}

function checkVerboseErrors(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath) || isNonCodeFile(filePath)) continue;

    // Sending stack traces to client — require res.json/send context
    const stackTracePattern =
      /res\.(?:json|send|status)\s*\([^)]*(?:err\.stack|error\.stack|\.stack|err\.message|error\.message)/g;
    const match = stackTracePattern.exec(content);

    if (match) {
      total++;
      issues++;
      findings.push({
        id: 'SEC-MC-003',
        severity: 'medium',
        layer: LAYER,
        layerName: NAME,
        owasp: 'A05:2025',
        cwe: 'CWE-209',
        title: 'Stack trace or error details sent to client',
        description: `${filePath} may expose error details to clients`,
        impact: 'Internal implementation details leaked to attackers',
        evidence: { file: filePath, line: getLineNumber(content, match.index), snippet: match[0] },
        fix: {
          description: 'Return generic error messages to clients, log details server-side',
          effort: 'sprint',
          automated: false,
        },
        references: ['https://cwe.mitre.org/data/definitions/209.html'],
      });
    }
  }

  return { passed: Math.max(1, total) - issues, total: Math.max(total, 1) };
}

function checkDirectoryListing(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;

    const dirListingPattern = /express\.static\s*\(|serveStatic\s*\(/g;
    const match = dirListingPattern.exec(content);

    if (match) {
      total++;
      // Check if directory listing is explicitly disabled
      if (!/dotfiles\s*:\s*['"]deny['"]|index\s*:\s*false/i.test(content)) {
        issues++;
        findings.push({
          id: 'SEC-MC-004',
          severity: 'low',
          layer: LAYER,
          layerName: NAME,
          owasp: 'A05:2025',
          cwe: 'CWE-548',
          title: 'Static file serving without directory listing protection',
          description: `${filePath} uses static file serving — verify directory listing is disabled`,
          impact: 'Directory contents may be browsable by attackers',
          evidence: { file: filePath, line: getLineNumber(content, match.index) },
          fix: {
            description: 'Set { dotfiles: "deny", index: false } in static middleware options',
            effort: 'immediate',
            automated: true,
          },
          references: ['https://cwe.mitre.org/data/definitions/548.html'],
        });
      }
    }
  }

  return { passed: Math.max(1, total) - issues, total: Math.max(total, 1) };
}

function checkSourceMaps(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;
    if (!/webpack|vite|next\.config|tsconfig|rollup/i.test(filePath)) continue;

    total++;
    const sourceMapEnabled =
      /(?:sourceMap|devtool)\s*[:=]\s*(?:true|['"]source-map['"]|['"]eval['"])/i;
    const match = sourceMapEnabled.exec(content);

    if (match) {
      // Check if it's production-only config
      if (!/production|prod\b/i.test(filePath)) {
        issues++;
        findings.push({
          id: 'SEC-MC-005',
          severity: 'low',
          layer: LAYER,
          layerName: NAME,
          owasp: 'A05:2025',
          cwe: 'CWE-540',
          title: 'Source maps may be enabled in production',
          description: `${filePath} has source maps enabled — may expose source code in production`,
          impact: 'Original source code visible to users via browser devtools',
          evidence: {
            file: filePath,
            line: getLineNumber(content, match.index),
            snippet: match[0],
          },
          fix: {
            description: 'Disable source maps in production builds or use hidden-source-map',
            effort: 'immediate',
            automated: true,
          },
          references: ['https://cwe.mitre.org/data/definitions/540.html'],
        });
      }
    }
  }

  return { passed: Math.max(1, total) - issues, total: Math.max(total, 1) };
}

function checkTLSConfig(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;

    const tlsPattern = /(?:minVersion|secureProtocol|ssl_protocols)/gi;
    if (!tlsPattern.test(content)) continue;

    total++;
    const weakTLS = /(?:TLSv1(?![\d.])|TLSv1\.0|SSLv3|TLSv1_method)/i;
    const match = weakTLS.exec(content);

    if (match) {
      issues++;
      findings.push({
        id: 'SEC-MC-006',
        severity: 'high',
        layer: LAYER,
        layerName: NAME,
        owasp: 'A05:2025',
        cwe: 'CWE-326',
        title: 'Weak TLS version configured',
        description: `${filePath} allows deprecated TLS versions`,
        impact: 'Connection may be vulnerable to protocol downgrade attacks',
        evidence: { file: filePath, line: getLineNumber(content, match.index), snippet: match[0] },
        fix: {
          description: 'Set minimum TLS version to TLSv1.2 or TLSv1.3',
          effort: 'immediate',
          automated: true,
        },
        references: ['https://cwe.mitre.org/data/definitions/326.html'],
      });
    }
  }

  return { passed: Math.max(1, total) - issues, total: Math.max(total, 1) };
}

function checkHTTPSRedirect(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  const allContent = [...files.values()].join('\n');

  const hasHTTPSRedirect = /(?:https|ssl|redirect.*https|forceSSL|require.*https|hsts)/i.test(
    allContent,
  );
  const hasHttpServer = /(?:createServer|http\.listen|app\.listen|express\(\))/i.test(allContent);

  if (!hasHttpServer) return { passed: 1, total: 1 };

  if (!hasHTTPSRedirect) {
    findings.push({
      id: 'SEC-MC-007',
      severity: 'high',
      layer: LAYER,
      layerName: NAME,
      owasp: 'A05:2025',
      cwe: 'CWE-319',
      title: 'No HTTPS redirect or enforcement detected',
      description: 'Server does not appear to enforce HTTPS connections',
      impact: 'Traffic may be sent over unencrypted HTTP, vulnerable to eavesdropping',
      evidence: { file: 'server configuration' },
      fix: {
        description: 'Add HTTPS redirect middleware and HSTS header',
        effort: 'sprint',
        automated: false,
      },
      references: ['https://cwe.mitre.org/data/definitions/319.html'],
    });
    return { passed: 0, total: 1 };
  }

  return { passed: 1, total: 1 };
}

export async function runMisconfigurationLayer(
  files: Map<string, string>,
  _stackTags: Set<string>,
  _projectRoot: string,
): Promise<LayerResult> {
  const findings: SecureFinding[] = [];

  const checks = [
    checkSecurityHeaders(files, findings),
    checkDebugMode(files, findings),
    checkVerboseErrors(files, findings),
    checkDirectoryListing(files, findings),
    checkSourceMaps(files, findings),
    checkTLSConfig(files, findings),
    checkHTTPSRedirect(files, findings),
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
