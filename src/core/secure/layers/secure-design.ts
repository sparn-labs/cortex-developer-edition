/**
 * Layer 6 — Secure Design (8%)
 * OWASP A04:2025 — Insecure Design
 */

import type { LayerResult, SecureFinding } from '../types.js';
import { getLayerName, getLayerWeight } from '../types.js';

const LAYER = 6;
const WEIGHT = getLayerWeight(LAYER);
const NAME = getLayerName(LAYER);

function isTestFile(path: string): boolean {
  return /\.(test|spec)\.|__tests__|\/tests\/|\/fixtures\/|benchmarks\/|\.bench\./i.test(path);
}

function isSecureFile(path: string): boolean {
  return /secure\/|layers\//.test(path) && path.endsWith('.ts');
}

function checkRateLimiting(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  const allContent = [...files.values()].join('\n');
  const hasApiRoutes = /(?:app|router)\.(get|post|put|patch|delete)\s*\(/i.test(allContent);

  if (!hasApiRoutes) return { passed: 1, total: 1 };

  const hasRateLimit =
    /(?:rate.?limit|rateLimit|throttle|express-rate-limit|@nestjs\/throttler|slowDown)/i.test(
      allContent,
    );

  if (!hasRateLimit) {
    findings.push({
      id: 'SEC-SD-001',
      severity: 'medium',
      layer: LAYER,
      layerName: NAME,
      owasp: 'A04:2025',
      cwe: 'CWE-770',
      title: 'No rate limiting detected on API routes',
      description: 'API endpoints have no rate limiting middleware',
      impact: 'API is vulnerable to brute force, credential stuffing, and abuse',
      evidence: { file: 'server configuration' },
      fix: {
        description: 'Add rate limiting middleware (e.g., express-rate-limit)',
        codeAfter:
          "import rateLimit from 'express-rate-limit';\napp.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));",
        effort: 'sprint',
        automated: false,
      },
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html',
      ],
    });
    return { passed: 0, total: 1 };
  }

  return { passed: 1, total: 1 };
}

function checkInputValidation(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  const allContent = [...files.values()].join('\n');
  const hasApiRoutes = /(?:app|router)\.(get|post|put|patch|delete)\s*\(/i.test(allContent);

  if (!hasApiRoutes) return { passed: 1, total: 1 };

  const hasValidation =
    /(?:zod|joi|yup|class-validator|ajv|FluentValidation|express-validator|superstruct|valibot|\.parse\(|\.safeParse\(|\.validate\()/i.test(
      allContent,
    );

  if (!hasValidation) {
    findings.push({
      id: 'SEC-SD-002',
      severity: 'medium',
      layer: LAYER,
      layerName: NAME,
      owasp: 'A04:2025',
      cwe: 'CWE-20',
      title: 'No input validation library detected',
      description: 'No schema validation (Zod, Joi, Yup, etc.) found for API inputs',
      impact: 'Invalid or malicious data may reach application logic',
      evidence: { file: 'project-wide' },
      fix: {
        description: 'Add input validation using Zod, Joi, or similar schema library',
        effort: 'sprint',
        automated: false,
      },
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html',
      ],
    });
    return { passed: 0, total: 1 };
  }

  return { passed: 1, total: 1 };
}

function checkErrorBoundaries(
  files: Map<string, string>,
  stackTags: Set<string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  if (!stackTags.has('react')) return { passed: 1, total: 1 };

  const allContent = [...files.values()].join('\n');
  const hasErrorBoundary =
    /(?:ErrorBoundary|componentDidCatch|getDerivedStateFromError|error-boundary)/i.test(allContent);

  if (!hasErrorBoundary) {
    findings.push({
      id: 'SEC-SD-003',
      severity: 'low',
      layer: LAYER,
      layerName: NAME,
      owasp: 'A04:2025',
      cwe: 'CWE-755',
      title: 'No React Error Boundaries detected',
      description: 'React app lacks Error Boundary components for graceful error handling',
      impact: 'Unhandled errors may crash the UI and expose error details',
      evidence: { file: 'React components' },
      fix: {
        description: 'Add Error Boundary components around critical UI sections',
        effort: 'sprint',
        automated: false,
      },
      references: [
        'https://react.dev/reference/react/Component#catching-rendering-errors-with-an-error-boundary',
      ],
    });
    return { passed: 0, total: 1 };
  }

  return { passed: 1, total: 1 };
}

function checkMassAssignment(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;

    // Direct assignment of req.body to model/DB
    const massAssignPattern =
      /(?:create|update|insert|save)\s*\(\s*(?:req\.body|request\.body|body)\s*\)/gi;
    const match = massAssignPattern.exec(content);

    if (match) {
      total++;
      issues++;
      findings.push({
        id: 'SEC-SD-004',
        severity: 'medium',
        layer: LAYER,
        layerName: NAME,
        owasp: 'A04:2025',
        cwe: 'CWE-915',
        title: 'Mass assignment — req.body passed directly to model',
        description: `${filePath} passes request body directly to create/update without field filtering`,
        impact: 'Attackers can set unintended fields (e.g., role, isAdmin)',
        evidence: { file: filePath, snippet: match[0] },
        fix: {
          description: 'Destructure only expected fields from req.body before passing to model',
          effort: 'immediate',
          automated: false,
        },
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html',
        ],
      });
    }
  }

  return { passed: Math.max(1, total) - issues, total: Math.max(total, 1) };
}

function checkFailSecure(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;

    // Empty catch blocks that silently continue
    const emptyCatch = /catch\s*\([^)]*\)\s*\{\s*(?:\/\/[^\n]*\n\s*)?\}/g;

    let match: RegExpExecArray | null = emptyCatch.exec(content);
    while (match !== null) {
      // Check if catch block is truly empty (not just commented)
      const catchContent = match[0];
      if (!/(?:log|throw|return|console|reject)/.test(catchContent)) {
        total++;
        issues++;
        findings.push({
          id: 'SEC-SD-005',
          severity: 'low',
          layer: LAYER,
          layerName: NAME,
          owasp: 'A04:2025',
          cwe: 'CWE-390',
          title: 'Empty catch block — fail-open pattern',
          description: `${filePath} has a catch block that silently swallows errors`,
          impact: 'Errors are silently ignored, potentially masking security issues',
          evidence: { file: filePath, line: content.substring(0, match.index).split('\n').length },
          fix: {
            description: 'Log errors or handle them appropriately in catch blocks',
            effort: 'immediate',
            automated: false,
          },
          references: ['https://cwe.mitre.org/data/definitions/390.html'],
        });
        if (issues >= 3) break;
      }
      match = emptyCatch.exec(content);
    }
  }

  return { passed: Math.max(1, total) - issues, total: Math.max(total, 1) };
}

function checkSeparationOfConcerns(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;
    // Only check source code files
    if (/\.md$|\.txt$|\.ya?ml$|\.json$|\/docs?\//i.test(filePath)) continue;

    // Security logic mixed with business logic
    const hasSecurityLogic = /(?:bcrypt|jwt|authorize|authenticate|encrypt|decrypt)/i.test(content);
    const hasBusinessLogic =
      /(?:calculate|process|transform|generate|validate.*order|validate.*payment)/i.test(content);
    const isSecurityModule = /(?:auth|security|middleware|guard|policy)/i.test(filePath);

    if (hasSecurityLogic && hasBusinessLogic && !isSecurityModule) {
      total++;
      issues++;
      findings.push({
        id: 'SEC-SD-006',
        severity: 'info',
        layer: LAYER,
        layerName: NAME,
        owasp: 'A04:2025',
        cwe: 'CWE-653',
        title: 'Security logic mixed with business logic',
        description: `${filePath} contains both security and business logic — separation of concerns`,
        impact: 'Security logic is harder to audit and maintain when mixed with business code',
        evidence: { file: filePath },
        fix: {
          description: 'Extract security logic into dedicated middleware or service modules',
          effort: 'quarter',
          automated: false,
        },
        references: ['https://cwe.mitre.org/data/definitions/653.html'],
      });
    }
  }

  return { passed: Math.max(1, total) - issues, total: Math.max(total, 1) };
}

export async function runSecureDesignLayer(
  files: Map<string, string>,
  stackTags: Set<string>,
  _projectRoot: string,
): Promise<LayerResult> {
  const findings: SecureFinding[] = [];

  const checks = [
    checkRateLimiting(files, findings),
    checkInputValidation(files, findings),
    checkErrorBoundaries(files, stackTags, findings),
    checkMassAssignment(files, findings),
    checkFailSecure(files, findings),
    checkSeparationOfConcerns(files, findings),
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
