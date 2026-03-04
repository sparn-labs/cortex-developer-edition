/**
 * Layer 5 — Cross-Border Data Transfers (10%)
 * Checks cloud regions, CDN configs, API calls to non-EU services, data residency.
 */

import type { ComplianceFramework, ComplyFinding, ComplyLayerResult } from '../types.js';
import { getComplyLayerName, getComplyLayerWeight } from '../types.js';

const LAYER = 5;
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

function checkCloudRegion(
  files: Map<string, string>,
  findings: ComplyFinding[],
  frameworks: Set<ComplianceFramework>,
): { passed: number; total: number } {
  if (!frameworks.has('gdpr') && !frameworks.has('all')) return { passed: 1, total: 1 };

  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isNonCodeFile(filePath)) continue;

    const regionPattern =
      /(?:region|AWS_REGION|REGION|cloud.?region)\s*[:=]\s*['"]?(us-|ap-|sa-|af-|me-)/gi;
    const match = regionPattern.exec(content);
    if (!match) continue;

    total++;
    issues++;
    findings.push({
      id: 'CMP-CB-001',
      severity: 'medium',
      layer: LAYER,
      layerName: NAME,
      regulation: [{ framework: 'gdpr', article: 'Art. 44', title: 'Transfer to Third Countries' }],
      title: 'Cloud region configured outside EU',
      description: `${filePath} configures a non-EU cloud region which may involve cross-border data transfers`,
      impact:
        'Transferring personal data outside the EU requires adequate safeguards (SCCs, adequacy decision)',
      evidence: { file: filePath, line: getLineNumber(content, match.index), snippet: match[0] },
      fix: {
        description:
          'Use EU regions for EU user data, or implement Standard Contractual Clauses (SCCs)',
        effort: 'quarter',
        automated: false,
      },
      references: ['https://gdpr-info.eu/art-44-gdpr/'],
    });
  }

  return { passed: total === 0 ? 1 : total - issues, total: Math.max(total, 1) };
}

function checkCDN(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isNonCodeFile(filePath)) continue;

    const cdnPattern = /(?:cloudfront|cloudflare|akamai|fastly|bunny\.net|cdn\.\w+)\b/gi;
    const match = cdnPattern.exec(content);
    if (!match) continue;
    if (isPatternContext(content, match.index)) continue;

    total++;
    const hasRegionRestriction =
      /(?:geo.?restrict|country|region.?restrict|allowlist.?countr|geo.?block)/i.test(content);

    if (!hasRegionRestriction) {
      issues++;
      findings.push({
        id: 'CMP-CB-002',
        severity: 'low',
        layer: LAYER,
        layerName: NAME,
        regulation: [
          { framework: 'gdpr', article: 'Art. 44', title: 'Transfer to Third Countries' },
        ],
        title: 'CDN without regional restrictions',
        description: `${filePath} uses a CDN without visible geo-restriction configuration`,
        impact: 'CDN edge caches may replicate data to servers in non-adequate countries',
        evidence: { file: filePath, line: getLineNumber(content, match.index), snippet: match[0] },
        fix: {
          description:
            'Configure CDN geo-restrictions to limit data replication to adequate jurisdictions',
          effort: 'sprint',
          automated: false,
        },
        references: ['https://gdpr-info.eu/art-44-gdpr/'],
      });
    }
  }

  return { passed: total === 0 ? 1 : total - issues, total: Math.max(total, 1) };
}

function checkNonEUAPIs(
  files: Map<string, string>,
  findings: ComplyFinding[],
  frameworks: Set<ComplianceFramework>,
): { passed: number; total: number } {
  if (!frameworks.has('gdpr') && !frameworks.has('all')) return { passed: 1, total: 1 };

  let total = 0;
  let issues = 0;

  const nonEUServices =
    /(?:amazonaws\.com|googleapis\.com|azure\.com|firebaseio\.com|api\.openai\.com|api\.anthropic\.com|api\.stripe\.com)\b/gi;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isNonCodeFile(filePath)) continue;

    const match = nonEUServices.exec(content);
    if (!match) continue;

    total++;
    const hasDPA = /(?:dpa|data.?processing.?agreement|scc|standard.?contractual|adequacy)/i.test(
      content,
    );

    if (!hasDPA) {
      issues++;
      findings.push({
        id: 'CMP-CB-003',
        severity: 'medium',
        layer: LAYER,
        layerName: NAME,
        regulation: [{ framework: 'gdpr', article: 'Art. 46', title: 'Appropriate Safeguards' }],
        title: 'API calls to services with potential non-EU processing',
        description: `${filePath} calls external services that may process data outside the EU`,
        impact:
          'API calls transmitting personal data to non-EU services require appropriate safeguards',
        evidence: { file: filePath, line: getLineNumber(content, match.index), snippet: match[0] },
        fix: {
          description:
            'Ensure Data Processing Agreements (DPAs) are in place with all third-party service providers',
          effort: 'sprint',
          automated: false,
        },
        references: ['https://gdpr-info.eu/art-46-gdpr/'],
      });
    }
  }

  return { passed: total === 0 ? 1 : total - issues, total: Math.max(total, 1) };
}

function checkDataResidency(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  const allContent = [...files.values()].join('\n');

  const hasResidency =
    /(?:data.?residen|data.?localiz|data.?sovereign|region.?config|multi.?region)\b/i.test(
      allContent,
    );

  if (hasResidency) {
    return { passed: 1, total: 1 };
  }

  // Only flag if the app uses cloud services
  const usesCloud = /(?:aws|gcp|azure|cloud|s3|dynamodb|rds|firestore)\b/i.test(allContent);
  if (!usesCloud) return { passed: 1, total: 1 };

  findings.push({
    id: 'CMP-CB-004',
    severity: 'info',
    layer: LAYER,
    layerName: NAME,
    regulation: [{ framework: 'gdpr', article: 'Art. 44', title: 'Transfer to Third Countries' }],
    title: 'No data residency configuration detected',
    description:
      'Application uses cloud services but has no visible data residency or localization configuration',
    impact:
      'Consider implementing data residency controls to ensure compliance with local data protection laws',
    evidence: { file: 'project root' },
    fix: {
      description:
        'Document data storage locations and implement region-aware deployment configuration',
      effort: 'quarter',
      automated: false,
    },
    references: ['https://gdpr-info.eu/art-44-gdpr/'],
  });

  return { passed: 0, total: 1 };
}

function checkTransferImpactAssessment(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  const allContent = [...files.values()].join('\n');

  const hasTransfers = /(?:amazonaws\.com|googleapis\.com|azure\.com|api\.\w+\.com)\b/i.test(
    allContent,
  );
  if (!hasTransfers) return { passed: 1, total: 1 };

  const hasTIA = /(?:transfer.?impact|tia|data.?transfer.?assessment|schrems)\b/i.test(allContent);

  if (hasTIA) return { passed: 1, total: 1 };

  findings.push({
    id: 'CMP-CB-005',
    severity: 'info',
    layer: LAYER,
    layerName: NAME,
    regulation: [{ framework: 'gdpr', article: 'Art. 46', title: 'Appropriate Safeguards' }],
    title: 'No transfer impact assessment reference',
    description:
      'Application transfers data to third-party services but no Transfer Impact Assessment (TIA) documentation found',
    impact: 'Post-Schrems II, TIAs are recommended for international data transfers',
    evidence: { file: 'project root' },
    fix: {
      description: 'Conduct a Transfer Impact Assessment for each international data transfer',
      effort: 'quarter',
      automated: false,
    },
    references: ['https://gdpr-info.eu/art-46-gdpr/'],
  });

  return { passed: 0, total: 1 };
}

export async function runCrossBorderLayer(
  files: Map<string, string>,
  _stackTags: Set<string>,
  _projectRoot: string,
  frameworks: Set<ComplianceFramework>,
): Promise<ComplyLayerResult> {
  const findings: ComplyFinding[] = [];

  const checks = [
    checkCloudRegion(files, findings, frameworks),
    checkCDN(files, findings),
    checkNonEUAPIs(files, findings, frameworks),
    checkDataResidency(files, findings),
    checkTransferImpactAssessment(files, findings),
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
