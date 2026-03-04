/**
 * Layer 8 — Data Integrity (6%)
 * OWASP A08:2025 — Software and Data Integrity Failures
 */

import type { LayerResult, SecureFinding } from '../types.js';
import { getLayerName, getLayerWeight } from '../types.js';

const LAYER = 8;
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

function checkCICDSecrets(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  const ciFiles = [
    '.github/workflows',
    '.gitlab-ci.yml',
    'Jenkinsfile',
    '.circleci/config.yml',
    'azure-pipelines.yml',
    '.travis.yml',
  ];

  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    const isCIFile = ciFiles.some((ci) => filePath.includes(ci));
    if (!isCIFile) continue;

    total++;

    // Plaintext secrets in CI config
    const secretPatterns = [
      /(?:password|token|secret|api_key|apikey)\s*[:=]\s*['"][^$][^'"]{8,}['"]/gi,
      /(?:--password|--token)\s+['"][^$][^'"]{8,}['"]/gi,
    ];

    for (const pattern of secretPatterns) {
      const match = pattern.exec(content);
      if (match) {
        issues++;
        findings.push({
          id: 'SEC-DI-001',
          severity: 'critical',
          layer: LAYER,
          layerName: NAME,
          owasp: 'A08:2025',
          cwe: 'CWE-798',
          cvss: 9.8,
          title: 'Plaintext secret in CI/CD configuration',
          description: `${filePath} contains hardcoded secrets — use CI secrets/variables instead`,
          impact: 'CI/CD secrets visible to anyone with repository access',
          evidence: { file: filePath, line: getLineNumber(content, match.index) },
          fix: {
            description:
              'Use CI/CD secret variables (e.g., secrets.TOKEN) instead of hardcoded values',
            effort: 'immediate',
            automated: false,
          },
          references: [
            'https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions',
          ],
        });
        break;
      }
    }
  }

  return { passed: Math.max(1, total) - issues, total: Math.max(total, 1) };
}

function checkDeserialization(
  files: Map<string, string>,
  stackTags: Set<string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;

    // .NET BinaryFormatter
    if (
      stackTags.has('dotnet') &&
      /BinaryFormatter|SoapFormatter|ObjectStateFormatter/i.test(content)
    ) {
      total++;
      issues++;
      findings.push({
        id: 'SEC-DI-002',
        severity: 'critical',
        layer: LAYER,
        layerName: NAME,
        owasp: 'A08:2025',
        cwe: 'CWE-502',
        cvss: 9.8,
        title: 'Insecure deserialization — BinaryFormatter',
        description: `${filePath} uses BinaryFormatter which is vulnerable to deserialization attacks`,
        impact: 'Remote code execution through crafted serialized data',
        evidence: { file: filePath },
        fix: {
          description: 'Replace BinaryFormatter with System.Text.Json or JsonSerializer',
          effort: 'sprint',
          automated: false,
        },
        references: [
          'https://learn.microsoft.com/dotnet/standard/serialization/binaryformatter-security-guide',
        ],
      });
    }

    // JSON.parse of untrusted input without try-catch
    const jsonParsePattern = /JSON\.parse\s*\(\s*(?:req\.|request\.|body\.|query\.)/g;
    const match = jsonParsePattern.exec(content);
    if (match) {
      total++;
      // Check if wrapped in try-catch
      const contextBefore = content.substring(Math.max(0, match.index - 100), match.index);
      if (!/try\s*\{/.test(contextBefore)) {
        issues++;
        findings.push({
          id: 'SEC-DI-002',
          severity: 'medium',
          layer: LAYER,
          layerName: NAME,
          owasp: 'A08:2025',
          cwe: 'CWE-502',
          title: 'JSON.parse of untrusted input without error handling',
          description: `${filePath} parses untrusted JSON without try-catch`,
          impact: 'Malformed JSON can crash the application',
          evidence: {
            file: filePath,
            line: getLineNumber(content, match.index),
            snippet: match[0],
          },
          fix: {
            description: 'Wrap JSON.parse in try-catch and validate the parsed structure',
            effort: 'immediate',
            automated: false,
          },
          references: ['https://cwe.mitre.org/data/definitions/502.html'],
        });
      }
    }
  }

  return { passed: Math.max(1, total) - issues, total: Math.max(total, 1) };
}

function checkSRI(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;
    if (!filePath.endsWith('.html') && !filePath.endsWith('.tsx') && !filePath.endsWith('.jsx'))
      continue;

    // CDN scripts without integrity
    const cdnPattern =
      /<script[^>]+src\s*=\s*['"]https?:\/\/(?:cdn|unpkg|cdnjs|jsdelivr)[^'"]+['"]/gi;
    const matches = [...content.matchAll(cdnPattern)];

    for (const match of matches) {
      total++;
      if (!/integrity\s*=/.test(match[0])) {
        issues++;
        findings.push({
          id: 'SEC-DI-003',
          severity: 'medium',
          layer: LAYER,
          layerName: NAME,
          owasp: 'A08:2025',
          cwe: 'CWE-353',
          title: 'CDN script without Subresource Integrity (SRI)',
          description: `${filePath} loads external scripts without integrity verification`,
          impact: 'Compromised CDN could inject malicious code',
          evidence: {
            file: filePath,
            line: getLineNumber(content, match.index),
            snippet: match[0].substring(0, 80),
          },
          fix: {
            description: 'Add integrity and crossorigin attributes to external script tags',
            effort: 'immediate',
            automated: true,
          },
          references: [
            'https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity',
          ],
        });
      }
    }
  }

  return { passed: Math.max(1, total) - issues, total: Math.max(total, 1) };
}

function checkCSP(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  const allContent = [...files.values()].join('\n');
  const hasCSP = /content-security-policy/i.test(allContent);

  if (!hasCSP) {
    // CSP check already covered in misconfiguration layer — just a basic check here
    findings.push({
      id: 'SEC-DI-004',
      severity: 'medium',
      layer: LAYER,
      layerName: NAME,
      owasp: 'A08:2025',
      cwe: 'CWE-693',
      title: 'No Content Security Policy configured',
      description: 'CSP header not found — helps prevent XSS and data injection',
      impact: 'Browser cannot enforce content origin restrictions',
      evidence: { file: 'server configuration' },
      fix: {
        description: 'Configure Content-Security-Policy header with restrictive directives',
        effort: 'sprint',
        automated: false,
      },
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'],
    });
    return { passed: 0, total: 1 };
  }

  // Check for unsafe directives
  if (/unsafe-inline|unsafe-eval/i.test(allContent)) {
    findings.push({
      id: 'SEC-DI-004',
      severity: 'low',
      layer: LAYER,
      layerName: NAME,
      owasp: 'A08:2025',
      cwe: 'CWE-693',
      title: 'CSP contains unsafe-inline or unsafe-eval',
      description: 'Content Security Policy uses unsafe directives that weaken protection',
      impact: 'CSP effectiveness is significantly reduced',
      evidence: { file: 'CSP configuration' },
      fix: {
        description: 'Replace unsafe-inline with nonces/hashes and remove unsafe-eval',
        effort: 'sprint',
        automated: false,
      },
      references: ['https://csp-evaluator.withgoogle.com/'],
    });
    return { passed: 0, total: 1 };
  }

  return { passed: 1, total: 1 };
}

function checkPackageIntegrity(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  const hasPackageLock = files.has('package-lock.json');
  if (!hasPackageLock) return { passed: 1, total: 1 };

  const lockContent = files.get('package-lock.json') ?? '';

  // Check if lockfile version >= 2 (has integrity hashes)
  try {
    const lock = JSON.parse(lockContent);
    if (lock.lockfileVersion < 2) {
      findings.push({
        id: 'SEC-DI-005',
        severity: 'low',
        layer: LAYER,
        layerName: NAME,
        owasp: 'A08:2025',
        cwe: 'CWE-353',
        title: 'Old lockfile format without integrity hashes',
        description: 'package-lock.json uses lockfileVersion < 2, missing integrity verification',
        impact: 'Package integrity cannot be verified during install',
        evidence: { file: 'package-lock.json' },
        fix: {
          description: 'Regenerate package-lock.json with npm 7+ for lockfileVersion >= 2',
          effort: 'immediate',
          automated: true,
        },
        references: ['https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json'],
      });
      return { passed: 0, total: 1 };
    }
  } catch {
    // Can't parse — skip
  }

  return { passed: 1, total: 1 };
}

export async function runDataIntegrityLayer(
  files: Map<string, string>,
  stackTags: Set<string>,
  _projectRoot: string,
): Promise<LayerResult> {
  const findings: SecureFinding[] = [];

  const checks = [
    checkCICDSecrets(files, findings),
    checkDeserialization(files, stackTags, findings),
    checkSRI(files, findings),
    checkCSP(files, findings),
    checkPackageIntegrity(files, findings),
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
