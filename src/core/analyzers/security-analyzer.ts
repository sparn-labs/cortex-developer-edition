/**
 * Security Analyzer (15 pts)
 *
 * Checks for hardcoded secrets, sensitive files, weak crypto,
 * CORS issues, missing auth, eval/innerHTML, SQL injection, insecure deps.
 */

import type { AnalysisContext, Analyzer, AnalyzerFinding, CategoryResult } from './types.js';

export function createSecurityAnalyzer(): Analyzer {
  return {
    category: 'security',
    name: 'Security',
    maxPoints: 15,

    async analyze(context: AnalysisContext): Promise<CategoryResult> {
      const findings: AnalyzerFinding[] = [];
      let deductions = 0;

      for (const [filePath, content] of context.files) {
        if (isIgnoredFile(filePath, context)) continue;

        deductions += checkHardcodedSecrets(filePath, content, findings);
        deductions += checkSensitiveFiles(filePath, findings);
        deductions += checkWeakCrypto(filePath, content, findings);
        deductions += checkCORSWildcard(filePath, content, findings);
        deductions += checkMissingAuth(filePath, content, findings);
        deductions += checkDangerousAPIs(filePath, content, findings);
        deductions += checkSQLInjection(filePath, content, findings);
      }

      deductions += checkInsecureDeps(context, findings);

      const score = Math.max(0, 15 - deductions);

      return {
        category: 'security',
        name: 'Security',
        maxPoints: 15,
        score,
        isNA: false,
        findings,
      };
    },
  };
}

function isIgnoredFile(filePath: string, context: AnalysisContext): boolean {
  if (context.config.secretsIgnorePatterns.some((p) => filePath.includes(p))) return true;
  // Skip analyzer source files to avoid self-detection (regex patterns referencing secrets/SQL)
  if (isAnalyzerFile(filePath)) return true;
  return false;
}

function isAnalyzerFile(path: string): boolean {
  return (
    path.includes('analyzers/') && (path.endsWith('-analyzer.ts') || path.endsWith('-analyzer.js'))
  );
}

function isTestFile(path: string): boolean {
  return (
    path.includes('.test.') ||
    path.includes('.spec.') ||
    path.includes('__tests__') ||
    path.includes('/tests/') ||
    path.includes('/fixtures/')
  );
}

const SECRET_PATTERNS: Array<{ pattern: RegExp; name: string }> = [
  // API keys
  { pattern: /['"](?:sk|pk)[-_](?:live|test)[-_][a-zA-Z0-9]{20,}['"]/g, name: 'Stripe API key' },
  { pattern: /['"]AIza[0-9A-Za-z_-]{35}['"]/g, name: 'Google API key' },
  { pattern: /['"]gh[ps]_[A-Za-z0-9]{36,}['"]/g, name: 'GitHub token' },
  // AWS
  { pattern: /['"]AKIA[0-9A-Z]{16}['"]/g, name: 'AWS Access Key' },
  // Generic secrets
  {
    pattern: /(?:password|secret|token|api_key|apikey|auth_token)\s*[:=]\s*['"][^'"]{8,}['"]/gi,
    name: 'Hardcoded credential',
  },
  // Private keys
  { pattern: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g, name: 'Private key' },
  // JWT
  {
    pattern: /['"]eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}['"]/g,
    name: 'JWT token',
  },
];

function checkHardcodedSecrets(
  filePath: string,
  content: string,
  findings: AnalyzerFinding[],
): number {
  if (isTestFile(filePath) || filePath.endsWith('.md') || filePath.endsWith('.json')) return 0;

  let total = 0;

  for (const { pattern, name } of SECRET_PATTERNS) {
    const regex = new RegExp(pattern.source, pattern.flags);
    const matches = [...content.matchAll(regex)];
    if (matches.length > 0) {
      total += 1;
      findings.push({
        ruleId: 'SEC-001',
        title: `Hardcoded secret: ${name}`,
        description: `${filePath}: ${matches.length} potential ${name}(s) found`,
        severity: 'critical',
        filePath,
        suggestion: `Move secrets to environment variables or a vault. Never commit secrets to source control.`,
        deduction: 1,
        fixable: true,
        fixType: 'config-change',
      });
    }
  }

  return Math.min(total, 5);
}

const SENSITIVE_FILE_PATTERNS = [
  /^\.env$/,
  /^\.env\./,
  /\.pem$/,
  /\.key$/,
  /\.p12$/,
  /\.pfx$/,
  /credentials\.json$/,
  /service-account.*\.json$/,
  /\.keystore$/,
];

function checkSensitiveFiles(filePath: string, findings: AnalyzerFinding[]): number {
  const fileName = filePath.split('/').pop() || '';

  for (const pattern of SENSITIVE_FILE_PATTERNS) {
    if (pattern.test(fileName) || pattern.test(filePath)) {
      findings.push({
        ruleId: 'SEC-002',
        title: 'Sensitive file committed',
        description: `${filePath} should not be in source control`,
        severity: 'critical',
        filePath,
        suggestion: `Add to .gitignore and remove from repository history.`,
        deduction: 1,
        fixable: true,
        fixType: 'config-change',
      });
      return 1;
    }
  }

  return 0;
}

function checkWeakCrypto(filePath: string, content: string, findings: AnalyzerFinding[]): number {
  if (isTestFile(filePath)) return 0;

  const weakPatterns = [
    { pattern: /createHash\s*\(\s*['"]md5['"]\s*\)/g, name: 'MD5' },
    { pattern: /createHash\s*\(\s*['"]sha1['"]\s*\)/g, name: 'SHA1' },
    { pattern: /\bMD5\s*\(/g, name: 'MD5' },
    { pattern: /\bSHA1\s*\(/g, name: 'SHA1' },
  ];

  let total = 0;

  for (const { pattern, name } of weakPatterns) {
    if (pattern.test(content)) {
      total += 0.5;
      findings.push({
        ruleId: 'SEC-003',
        title: `Weak cryptography: ${name}`,
        description: `${filePath}: ${name} is cryptographically weak for security purposes`,
        severity: 'minor',
        filePath,
        suggestion: `Use SHA-256 or stronger for security-sensitive hashing.`,
        deduction: 0.5,
        fixable: true,
        fixType: 'replace-pattern',
      });
    }
  }

  return Math.min(total, 1);
}

function checkCORSWildcard(filePath: string, content: string, findings: AnalyzerFinding[]): number {
  if (isTestFile(filePath)) return 0;

  const corsWildcard =
    /(?:Access-Control-Allow-Origin|cors\s*\(\s*\{[^}]*origin\s*:\s*)['"]?\*['"]?/gi;

  if (corsWildcard.test(content)) {
    findings.push({
      ruleId: 'SEC-004',
      title: 'CORS wildcard origin',
      description: `${filePath}: Allow-Origin set to * — allows any domain`,
      severity: 'minor',
      filePath,
      suggestion: `Restrict CORS to specific trusted domains.`,
      deduction: 0.5,
      fixable: true,
      fixType: 'config-change',
    });
    return 0.5;
  }

  return 0;
}

function checkMissingAuth(filePath: string, content: string, findings: AnalyzerFinding[]): number {
  if (isTestFile(filePath)) return 0;

  // Check for route definitions without auth middleware
  const routePattern =
    /(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*['"][^'"]+['"]\s*,\s*(?:async\s+)?(?:\(|function)/g;
  const authPattern =
    /(?:auth|authenticate|authorize|isAuthenticated|requireAuth|protect|guard|middleware)/i;

  const routes = [...content.matchAll(routePattern)];
  if (routes.length === 0) return 0;

  // Check if file has any auth middleware import/usage
  if (!authPattern.test(content)) {
    const deduction = Math.min(routes.length * 0.25, 1);
    findings.push({
      ruleId: 'SEC-005',
      title: 'Routes without auth middleware',
      description: `${filePath}: ${routes.length} route(s) with no auth middleware detected`,
      severity: 'major',
      filePath,
      suggestion: `Add authentication middleware to protect API endpoints.`,
      deduction,
      fixable: true,
      fixType: 'replace-pattern',
    });
    return deduction;
  }

  return 0;
}

function checkDangerousAPIs(
  filePath: string,
  content: string,
  findings: AnalyzerFinding[],
): number {
  if (isTestFile(filePath)) return 0;

  let total = 0;

  const patterns: Array<{ pattern: RegExp; title: string; deduction: number }> = [
    { pattern: /\beval\s*\(/g, title: 'eval() usage', deduction: 1 },
    {
      pattern: /dangerouslySetInnerHTML/g,
      title: 'dangerouslySetInnerHTML',
      deduction: 0.5,
    },
    { pattern: /\.innerHTML\s*=/g, title: 'innerHTML assignment', deduction: 0.5 },
    { pattern: /new\s+Function\s*\(/g, title: 'new Function() (eval equivalent)', deduction: 0.5 },
  ];

  for (const { pattern, title, deduction } of patterns) {
    const matches = content.match(pattern);
    if (matches) {
      total += deduction;
      findings.push({
        ruleId: 'SEC-006',
        title: `Dangerous API: ${title}`,
        description: `${filePath}: ${matches.length} usage(s) of ${title}`,
        severity: 'critical',
        filePath,
        suggestion: `Avoid dynamic code execution. Use safe alternatives.`,
        deduction,
        fixable: true,
        fixType: 'replace-pattern',
      });
    }
  }

  return Math.min(total, 2);
}

function checkSQLInjection(filePath: string, content: string, findings: AnalyzerFinding[]): number {
  if (isTestFile(filePath)) return 0;
  // Skip files using prepared statements or ORM patterns
  if (/\.prepare\s*\(/.test(content)) return 0;
  if (/\bprisma\b|\btypeorm\b|\bsequelize\b|\bdrizzle\b|\bknex\b/i.test(content)) return 0;

  const injectionPatterns = [
    /`.*\$\{.*\}.*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)\b/gi,
    /(?:SELECT|INSERT|UPDATE|DELETE|WHERE)\b.*`\$\{/gi,
    /(?:SELECT|INSERT|UPDATE|DELETE|WHERE).*['"]\s*\+/gi,
  ];

  for (const pattern of injectionPatterns) {
    if (pattern.test(content)) {
      findings.push({
        ruleId: 'SEC-007',
        title: 'SQL injection risk',
        description: `${filePath}: SQL query built with string interpolation/concatenation`,
        severity: 'critical',
        filePath,
        suggestion: `Use parameterized queries or an ORM.`,
        deduction: 0.5,
        fixable: true,
        fixType: 'replace-pattern',
      });
      return 0.5;
    }
  }

  return 0;
}

function checkInsecureDeps(context: AnalysisContext, findings: AnalyzerFinding[]): number {
  // Check lock files for known vulnerable package patterns
  const lockFiles = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'];
  let total = 0;

  for (const lockFile of lockFiles) {
    const content = context.files.get(lockFile);
    if (!content) continue;

    // Check for known vulnerable package patterns
    const vulnerablePatterns = [
      { pattern: /"event-stream"/, name: 'event-stream (supply chain attack)' },
      { pattern: /"ua-parser-js":\s*"[01]\./, name: 'ua-parser-js (compromised versions)' },
      { pattern: /"node-ipc":\s*"[91][0-2]\./, name: 'node-ipc (protestware)' },
    ];

    for (const { pattern, name } of vulnerablePatterns) {
      if (pattern.test(content)) {
        total += 0.5;
        findings.push({
          ruleId: 'SEC-008',
          title: `Potentially vulnerable dependency: ${name}`,
          description: `${lockFile}: contains potentially vulnerable package`,
          severity: 'major',
          filePath: lockFile,
          suggestion: `Run npm audit and update vulnerable dependencies.`,
          deduction: 0.5,
          fixable: true,
          fixType: 'config-change',
        });
      }
    }
  }

  return Math.min(total, 1);
}
