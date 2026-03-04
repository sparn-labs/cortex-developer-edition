/**
 * Layer 6 — Data Protection & Encryption (10%)
 * Checks encryption at rest, in transit, anonymization, PII in logs, TLS validation.
 */

import type { ComplianceFramework, ComplyFinding, ComplyLayerResult } from '../types.js';
import { getComplyLayerName, getComplyLayerWeight } from '../types.js';

const LAYER = 6;
const WEIGHT = getComplyLayerWeight(LAYER);
const NAME = getComplyLayerName(LAYER);

function isTestFile(path: string): boolean {
  return /\.(test|spec)\.|__tests__|\/tests\/|\/fixtures\/|benchmarks\/|\.bench\./i.test(path);
}

function isNonCodeFile(path: string): boolean {
  return /\.(md|txt|json|ya?ml|lock|svg|png|jpg|ico|woff|eot|ttf)$/i.test(path);
}

function getLineNumber(content: string, index: number): number {
  return content.substring(0, index).split('\n').length;
}

function checkEncryptionAtRest(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  const allContent = [...files.values()].join('\n');

  // Check if app stores PII
  const storesPII = /(?:email|phone|name|address|ssn|dateOfBirth)\s*[:=]/i.test(allContent);
  const usesDB =
    /(?:database|mongodb|postgres|mysql|sqlite|redis|dynamo|firestore|prisma|sequelize|typeorm|drizzle)\b/i.test(
      allContent,
    );

  if (!storesPII || !usesDB) return { passed: 1, total: 1 };

  const hasEncryption =
    /(?:encrypt|aes|cipher|kms|vault|sealed|at.?rest|column.?encrypt|field.?encrypt|pgcrypto)\b/i.test(
      allContent,
    );

  if (hasEncryption) return { passed: 1, total: 1 };

  findings.push({
    id: 'CMP-DP-001',
    severity: 'high',
    layer: LAYER,
    layerName: NAME,
    regulation: [
      { framework: 'gdpr', article: 'Art. 32', title: 'Security of Processing' },
      { framework: 'hipaa', article: '§164.312(a)(2)(iv)', title: 'Encryption and Decryption' },
      { framework: 'soc2', article: 'CC6.1', title: 'Logical and Physical Access Controls' },
    ],
    title: 'No encryption at rest for PII data stores',
    description: 'Application stores PII in a database without visible encryption at rest',
    impact:
      'Unencrypted PII at rest increases breach impact. GDPR Art. 32 requires appropriate technical measures',
    evidence: { file: 'project root' },
    fix: {
      description: 'Enable database-level or column-level encryption for PII fields',
      effort: 'sprint',
      automated: false,
    },
    references: ['https://gdpr-info.eu/art-32-gdpr/'],
  });

  return { passed: 0, total: 1 };
}

function checkEncryptionInTransit(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isNonCodeFile(filePath)) continue;

    // Check for HTTP (non-HTTPS) API calls
    const httpPattern = /['"]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/gi;
    const match = httpPattern.exec(content);
    if (!match) continue;

    total++;
    issues++;
    findings.push({
      id: 'CMP-DP-002',
      severity: 'high',
      layer: LAYER,
      layerName: NAME,
      regulation: [
        { framework: 'gdpr', article: 'Art. 32', title: 'Security of Processing' },
        { framework: 'hipaa', article: '§164.312(e)(1)', title: 'Transmission Security' },
      ],
      title: 'Non-HTTPS connection detected',
      description: `${filePath} uses plain HTTP for external communication`,
      impact: 'Data in transit without TLS encryption can be intercepted (man-in-the-middle)',
      evidence: { file: filePath, line: getLineNumber(content, match.index), snippet: match[0] },
      fix: {
        description: 'Use HTTPS for all external communications',
        effort: 'immediate',
        automated: true,
      },
      references: ['https://gdpr-info.eu/art-32-gdpr/'],
    });
  }

  return { passed: total === 0 ? 1 : total - issues, total: Math.max(total, 1) };
}

function checkAnonymization(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  const allContent = [...files.values()].join('\n');

  // Only relevant if app processes analytics/reporting on PII
  const hasAnalytics = /(?:analytics|report|aggregate|statistic|dashboard|metrics)\b/i.test(
    allContent,
  );
  const hasPII = /(?:email|phone|name|userId|user_id)\b/i.test(allContent);

  if (!hasAnalytics || !hasPII) return { passed: 1, total: 1 };

  const hasAnonymization =
    /(?:anonymiz|pseudonymiz|hash.*(?:email|name|user)|mask|redact|k-anonymity|differential.?privacy|tokenize)\b/i.test(
      allContent,
    );

  if (hasAnonymization) return { passed: 1, total: 1 };

  findings.push({
    id: 'CMP-DP-003',
    severity: 'medium',
    layer: LAYER,
    layerName: NAME,
    regulation: [
      { framework: 'gdpr', article: 'Art. 25', title: 'Data Protection by Design' },
      { framework: 'gdpr', article: 'Recital 26', title: 'Anonymisation' },
    ],
    title: 'No anonymization/pseudonymization for analytics',
    description: 'Application has analytics features that use PII without visible anonymization',
    impact: 'GDPR encourages pseudonymization as a safeguard. Anonymous data is outside GDPR scope',
    evidence: { file: 'project root' },
    fix: {
      description:
        'Implement data anonymization or pseudonymization for analytics and reporting pipelines',
      effort: 'quarter',
      automated: false,
    },
    references: ['https://gdpr-info.eu/art-25-gdpr/'],
  });

  return { passed: 0, total: 1 };
}

function checkPIIInLogs(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isNonCodeFile(filePath)) continue;

    const logPattern =
      /(?:console\.log|logger\.\w+|log\.\w+)\s*\([^)]*(?:userData|userInfo|userProfile|email|password|(?:access|auth|session|refresh|bearer)Token|secret|apiKey|api_key|phone)\b/gi;
    const match = logPattern.exec(content);
    if (!match) continue;

    total++;
    issues++;
    findings.push({
      id: 'CMP-DP-004',
      severity: 'high',
      layer: LAYER,
      layerName: NAME,
      regulation: [
        { framework: 'gdpr', article: 'Art. 5(1)(f)', title: 'Integrity and Confidentiality' },
        { framework: 'soc2', article: 'CC6.1', title: 'Access Controls' },
      ],
      title: 'PII potentially logged',
      description: `${filePath} may log sensitive personal data in application logs`,
      impact:
        'PII in logs is accessible to operations staff and complicates data subject access/erasure requests',
      evidence: {
        file: filePath,
        line: getLineNumber(content, match.index),
        snippet: match[0].substring(0, 80),
      },
      fix: {
        description:
          'Redact or mask PII in log statements. Use structured logging with PII filters',
        effort: 'immediate',
        automated: true,
      },
      references: ['https://gdpr-info.eu/art-5-gdpr/'],
    });
  }

  return { passed: total === 0 ? 1 : total - issues, total: Math.max(total, 1) };
}

function checkColumnEncryption(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  const allContent = [...files.values()].join('\n');

  const hasDB = /(?:database|prisma|sequelize|typeorm|drizzle|knex|mongoose)\b/i.test(allContent);
  if (!hasDB) return { passed: 1, total: 1 };

  const hasColumnEncryption =
    /(?:column.?encrypt|field.?encrypt|pgcrypto|encrypt.*column|@encrypted|EncryptedColumn)\b/i.test(
      allContent,
    );

  if (hasColumnEncryption) return { passed: 1, total: 1 };

  findings.push({
    id: 'CMP-DP-005',
    severity: 'info',
    layer: LAYER,
    layerName: NAME,
    regulation: [{ framework: 'gdpr', article: 'Art. 32', title: 'Security of Processing' }],
    title: 'No column-level encryption detected',
    description: 'No column-level encryption patterns found for sensitive database fields',
    impact: 'Column-level encryption provides defense-in-depth for the most sensitive PII fields',
    evidence: { file: 'project root' },
    fix: {
      description:
        'Consider encrypting high-sensitivity columns (SSN, health data) at the application level',
      effort: 'quarter',
      automated: false,
    },
    references: ['https://gdpr-info.eu/art-32-gdpr/'],
  });

  return { passed: 0, total: 1 };
}

function checkTLSValidation(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isNonCodeFile(filePath)) continue;

    const tlsDisablePattern =
      /(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|ssl_verify\s*[:=]\s*false)/gi;
    const match = tlsDisablePattern.exec(content);
    if (!match) continue;

    total++;
    issues++;
    findings.push({
      id: 'CMP-DP-006',
      severity: 'critical',
      layer: LAYER,
      layerName: NAME,
      regulation: [
        { framework: 'gdpr', article: 'Art. 32', title: 'Security of Processing' },
        { framework: 'hipaa', article: '§164.312(e)(1)', title: 'Transmission Security' },
      ],
      title: 'TLS certificate validation disabled',
      description: `${filePath} disables TLS certificate validation, enabling man-in-the-middle attacks`,
      impact: 'Disabling TLS validation makes all encrypted connections vulnerable to interception',
      evidence: { file: filePath, line: getLineNumber(content, match.index), snippet: match[0] },
      fix: {
        description: 'Remove TLS validation bypass. Use proper certificate management instead',
        effort: 'immediate',
        automated: true,
      },
      references: ['https://gdpr-info.eu/art-32-gdpr/'],
    });
  }

  return { passed: total === 0 ? 1 : total - issues, total: Math.max(total, 1) };
}

export async function runDataProtectionLayer(
  files: Map<string, string>,
  _stackTags: Set<string>,
  _projectRoot: string,
  _frameworks: Set<ComplianceFramework>,
): Promise<ComplyLayerResult> {
  const findings: ComplyFinding[] = [];

  const checks = [
    checkEncryptionAtRest(files, findings),
    checkEncryptionInTransit(files, findings),
    checkAnonymization(files, findings),
    checkPIIInLogs(files, findings),
    checkColumnEncryption(files, findings),
    checkTLSValidation(files, findings),
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
