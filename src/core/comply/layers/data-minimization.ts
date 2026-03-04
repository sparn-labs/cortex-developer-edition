/**
 * Layer 4 — Data Minimization & Retention (12%)
 * Checks for over-collection, retention policies, TTL, PII in logs.
 */

import type { ComplianceFramework, ComplyFinding, ComplyLayerResult } from '../types.js';
import { getComplyLayerName, getComplyLayerWeight } from '../types.js';

const LAYER = 4;
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

/** Heuristic: check if match at index is inside a regex literal or pattern definition. */
function isPatternContext(content: string, index: number): boolean {
  const ls = content.lastIndexOf('\n', index - 1) + 1;
  const le = content.indexOf('\n', index);
  const line = content.substring(ls, le === -1 ? content.length : le);
  const col = index - ls;
  const before = line.substring(0, col);
  const slashes = before.match(/(?<!\\)\//g);
  if (slashes && slashes.length % 2 === 1) return true;
  if (/(?:new\s+RegExp\s*\(|(?:pattern|regex)\s*[:=]\s*\/)/i.test(line)) return true;
  return false;
}

function checkOverCollection(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  const piiFields =
    /(?:email|phone|firstName|first_name|lastName|last_name|address|dateOfBirth|date_of_birth|ssn|passport|nationalId|creditCard|bankAccount|gender|ethnicity|religion|salary|income)\b/gi;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isNonCodeFile(filePath)) continue;

    // Look for schemas/models with many PII fields
    const schemaPattern = /(?:schema|model|interface|type|class|table|entity)\s+\w+/gi;
    const schemas = [...content.matchAll(schemaPattern)];
    if (schemas.length === 0) continue;

    const fieldMatches = [...content.matchAll(piiFields)].filter(
      (m) => m.index !== undefined && !isPatternContext(content, m.index),
    );
    const uniqueFields = new Set(fieldMatches.map((m) => m[0].toLowerCase()));

    if (uniqueFields.size > 10) {
      total++;
      issues++;
      findings.push({
        id: 'CMP-DM-001',
        severity: 'medium',
        layer: LAYER,
        layerName: NAME,
        regulation: [{ framework: 'gdpr', article: 'Art. 5(1)(c)', title: 'Data Minimisation' }],
        title: 'Potential over-collection of PII fields',
        description: `${filePath} contains ${uniqueFields.size} PII field types — review for data minimization`,
        impact:
          'GDPR Art. 5(1)(c) requires that personal data be adequate, relevant, and limited to what is necessary',
        evidence: { file: filePath, snippet: `${uniqueFields.size} PII fields detected` },
        fix: {
          description:
            'Review each PII field for necessity. Remove fields not required for the stated purpose',
          effort: 'sprint',
          automated: false,
        },
        references: ['https://gdpr-info.eu/art-5-gdpr/'],
      });
    } else if (uniqueFields.size > 0) {
      total++;
    }
  }

  return { passed: total === 0 ? 1 : total - issues, total: Math.max(total, 1) };
}

function checkRetentionPolicy(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  const allContent = [...files.values()].join('\n');

  const hasRetention =
    /(?:retention|retentionPolicy|retention_policy|data.?retention|expir|purge.?old|cleanup|archive.?old|ttl|time.?to.?live)\b/i.test(
      allContent,
    );

  if (hasRetention) return { passed: 1, total: 1 };

  // Check if the app stores data at all
  const storesData =
    /(?:database|mongodb|postgres|mysql|sqlite|redis|dynamo|firestore|prisma|sequelize|typeorm|drizzle|knex)\b/i.test(
      allContent,
    );
  if (!storesData) return { passed: 1, total: 1 };

  findings.push({
    id: 'CMP-DM-002',
    severity: 'medium',
    layer: LAYER,
    layerName: NAME,
    regulation: [
      { framework: 'gdpr', article: 'Art. 5(1)(e)', title: 'Storage Limitation' },
      { framework: 'soc2', article: 'CC6.5', title: 'Data Disposal' },
    ],
    title: 'No data retention policy indicators',
    description:
      'Application uses a database but no retention policy, TTL, or cleanup patterns were found',
    impact: 'GDPR requires data to be kept no longer than necessary for its stated purpose',
    evidence: { file: 'project root' },
    fix: {
      description:
        'Define and implement data retention policies with automated cleanup for each data category',
      effort: 'quarter',
      automated: false,
    },
    references: ['https://gdpr-info.eu/art-5-gdpr/'],
  });

  return { passed: 0, total: 1 };
}

function checkSoftDeleteOnly(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isNonCodeFile(filePath)) continue;

    const hasSoftDelete =
      /(?:softDelete|soft_delete|isDeleted|is_deleted|deletedAt|deleted_at|paranoid)\b/i.test(
        content,
      );
    if (!hasSoftDelete) continue;

    total++;
    const hasHardDelete =
      /(?:hardDelete|hard_delete|forceDelete|force_delete|permanentDelete|permanent_delete|destroy|\.remove|\.delete\b(?!.*soft))/i.test(
        content,
      );

    if (!hasHardDelete) {
      issues++;
      findings.push({
        id: 'CMP-DM-003',
        severity: 'low',
        layer: LAYER,
        layerName: NAME,
        regulation: [{ framework: 'gdpr', article: 'Art. 17', title: 'Right to Erasure' }],
        title: 'Soft delete only — no hard delete capability',
        description: `${filePath} uses soft delete but has no hard/permanent delete mechanism`,
        impact:
          'Soft-deleted data still exists. GDPR erasure requests require actual deletion within reasonable timeframe',
        evidence: { file: filePath },
        fix: {
          description:
            'Implement a hard delete mechanism that permanently removes data after retention period',
          effort: 'sprint',
          automated: false,
        },
        references: ['https://gdpr-info.eu/art-17-gdpr/'],
      });
    }
  }

  return { passed: total === 0 ? 1 : total - issues, total: Math.max(total, 1) };
}

function checkNoTTL(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isNonCodeFile(filePath)) continue;

    // Check for session/token/cache storage without TTL
    const storagePattern =
      /(?:session|token|cache|temp|temporary)\s*(?:store|storage|save|set)\b/gi;
    const match = storagePattern.exec(content);
    if (!match) continue;

    total++;
    const hasTTL = /(?:ttl|expire|expiresIn|expires_in|maxAge|max_age|timeout)\b/i.test(content);

    if (!hasTTL) {
      issues++;
      findings.push({
        id: 'CMP-DM-004',
        severity: 'medium',
        layer: LAYER,
        layerName: NAME,
        regulation: [{ framework: 'gdpr', article: 'Art. 5(1)(e)', title: 'Storage Limitation' }],
        title: 'No TTL/expiry on stored data',
        description: `${filePath} stores session/token/cache data without visible TTL or expiration`,
        impact:
          'Data stored without expiry may persist indefinitely, violating storage limitation principle',
        evidence: { file: filePath, line: getLineNumber(content, match.index), snippet: match[0] },
        fix: {
          description:
            'Add TTL or expiration to all temporary data stores (sessions, tokens, caches)',
          effort: 'immediate',
          automated: false,
        },
        references: ['https://gdpr-info.eu/art-5-gdpr/'],
      });
    }
  }

  return { passed: total === 0 ? 1 : total - issues, total: Math.max(total, 1) };
}

function checkPurposeLimitation(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  const allContent = [...files.values()].join('\n');

  // Check if there's any purpose documentation
  const hasPurpose =
    /(?:purpose|dataUse|data_use|processingPurpose|processing_purpose|lawfulBasis|lawful_basis)\b/i.test(
      allContent,
    );

  // Only flag if app collects PII but has no purpose documentation
  const collectsPII = /(?:email|phone|name|address|dateOfBirth)\s*[:=]/i.test(allContent);
  if (!collectsPII) return { passed: 1, total: 1 };

  if (hasPurpose) return { passed: 1, total: 1 };

  findings.push({
    id: 'CMP-DM-005',
    severity: 'low',
    layer: LAYER,
    layerName: NAME,
    regulation: [{ framework: 'gdpr', article: 'Art. 5(1)(b)', title: 'Purpose Limitation' }],
    title: 'No purpose limitation documentation in code',
    description:
      'Application collects PII but has no visible purpose documentation or data use annotations',
    impact:
      'GDPR requires personal data to be collected for specified, explicit, and legitimate purposes',
    evidence: { file: 'project root' },
    fix: {
      description:
        'Document the purpose for each data collection point. Consider code comments or a data catalog',
      effort: 'quarter',
      automated: false,
    },
    references: ['https://gdpr-info.eu/art-5-gdpr/'],
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

    // Detect logging of PII fields
    const logPattern =
      /(?:console\.log|logger\.\w+|log\.\w+|winston\.\w+|pino\.\w+)\s*\([^)]*(?:email|password|ssn|creditCard|(?:access|auth|session|refresh|bearer)Token|secret|apiKey|api_key|phoneNumber|phone_number)\b/gi;
    const match = logPattern.exec(content);
    if (!match) continue;

    total++;
    issues++;
    findings.push({
      id: 'CMP-DM-006',
      severity: 'high',
      layer: LAYER,
      layerName: NAME,
      regulation: [
        { framework: 'gdpr', article: 'Art. 5(1)(f)', title: 'Integrity and Confidentiality' },
        { framework: 'hipaa', article: '§164.312(a)', title: 'Access Control' },
      ],
      title: 'PII detected in log statements',
      description: `${filePath} logs potentially sensitive personal data`,
      impact:
        'PII in logs can be accessed by unauthorized personnel and complicates erasure requests',
      evidence: {
        file: filePath,
        line: getLineNumber(content, match.index),
        snippet: match[0].substring(0, 80),
      },
      fix: {
        description: 'Remove PII from log statements or implement log redaction/masking',
        effort: 'immediate',
        automated: true,
      },
      references: ['https://gdpr-info.eu/art-5-gdpr/'],
    });
  }

  return { passed: total === 0 ? 1 : total - issues, total: Math.max(total, 1) };
}

export async function runDataMinimizationLayer(
  files: Map<string, string>,
  _stackTags: Set<string>,
  _projectRoot: string,
  _frameworks: Set<ComplianceFramework>,
): Promise<ComplyLayerResult> {
  const findings: ComplyFinding[] = [];

  const checks = [
    checkOverCollection(files, findings),
    checkRetentionPolicy(files, findings),
    checkSoftDeleteOnly(files, findings),
    checkNoTTL(files, findings),
    checkPurposeLimitation(files, findings),
    checkPIIInLogs(files, findings),
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
