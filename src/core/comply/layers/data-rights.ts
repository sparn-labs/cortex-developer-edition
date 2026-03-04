/**
 * Layer 3 — Data Subject Rights (15%)
 * Checks for data export, deletion, access, rectification endpoints.
 * These are "absence checks" — only triggered when user auth patterns exist.
 */

import type { ComplianceFramework, ComplyFinding, ComplyLayerResult } from '../types.js';
import { getComplyLayerName, getComplyLayerWeight } from '../types.js';

const LAYER = 3;
const WEIGHT = getComplyLayerWeight(LAYER);
const NAME = getComplyLayerName(LAYER);

function hasUserAuth(files: Map<string, string>): boolean {
  const allContent = [...files.values()].join('\n');
  return /(?:signup|sign.?up|register|login|log.?in|createUser|create.?user|authentication)\b/i.test(
    allContent,
  );
}

function checkDataExport(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  if (!hasUserAuth(files)) return { passed: 1, total: 1 };

  const allContent = [...files.values()].join('\n');
  const hasExport =
    /(?:export.?data|data.?export|download.?data|data.?download|portability|data.?dump|exportUser|getUserData|takeout)\b/i.test(
      allContent,
    );

  if (hasExport) return { passed: 1, total: 1 };

  findings.push({
    id: 'CMP-DR-001',
    severity: 'critical',
    layer: LAYER,
    layerName: NAME,
    regulation: [
      { framework: 'gdpr', article: 'Art. 20', title: 'Right to Data Portability' },
      { framework: 'ccpa', article: '§1798.100', title: 'Right to Know / Access' },
    ],
    title: 'No data export/portability capability',
    description: 'Application has user authentication but no data export or portability endpoint',
    impact:
      'GDPR Art. 20 requires providing personal data in a portable, machine-readable format upon request',
    evidence: { file: 'project root' },
    fix: {
      description:
        'Implement a data export endpoint that allows users to download all their personal data in JSON/CSV format',
      effort: 'sprint',
      automated: false,
    },
    references: ['https://gdpr-info.eu/art-20-gdpr/'],
  });

  return { passed: 0, total: 1 };
}

function checkDataDeletion(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  if (!hasUserAuth(files)) return { passed: 1, total: 1 };

  const allContent = [...files.values()].join('\n');
  const hasDeletion =
    /(?:delete.?account|account.?delet|erase.?data|data.?eras|right.?to.?be.?forgotten|removeUser|deleteUser|purge.?user|gdpr.?delet)\b/i.test(
      allContent,
    );

  if (hasDeletion) return { passed: 1, total: 1 };

  findings.push({
    id: 'CMP-DR-002',
    severity: 'critical',
    layer: LAYER,
    layerName: NAME,
    regulation: [
      { framework: 'gdpr', article: 'Art. 17', title: 'Right to Erasure' },
      { framework: 'ccpa', article: '§1798.105', title: 'Right to Delete' },
    ],
    title: 'No data deletion/erasure capability',
    description:
      'Application has user authentication but no account deletion or data erasure endpoint',
    impact:
      'GDPR Art. 17 and CCPA §1798.105 require the ability to delete personal data upon request',
    evidence: { file: 'project root' },
    fix: {
      description:
        'Implement account deletion endpoint that removes all personal data, including backups within 30 days',
      effort: 'sprint',
      automated: false,
    },
    references: ['https://gdpr-info.eu/art-17-gdpr/'],
  });

  return { passed: 0, total: 1 };
}

function checkDataAccess(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  if (!hasUserAuth(files)) return { passed: 1, total: 1 };

  const allContent = [...files.values()].join('\n');
  const hasAccess =
    /(?:\/me|\/profile|\/account|getUser|getUserProfile|viewData|accessData|subject.?access|data.?access)\b/i.test(
      allContent,
    );

  if (hasAccess) return { passed: 1, total: 1 };

  findings.push({
    id: 'CMP-DR-003',
    severity: 'high',
    layer: LAYER,
    layerName: NAME,
    regulation: [
      { framework: 'gdpr', article: 'Art. 15', title: 'Right of Access' },
      { framework: 'ccpa', article: '§1798.110', title: 'Right to Know Categories' },
    ],
    title: 'No data access/view capability',
    description:
      'Application has user authentication but no endpoint for users to view their personal data',
    impact: 'GDPR Art. 15 grants data subjects the right to access their personal data',
    evidence: { file: 'project root' },
    fix: {
      description:
        'Implement a profile/account page where users can view all their stored personal data',
      effort: 'sprint',
      automated: false,
    },
    references: ['https://gdpr-info.eu/art-15-gdpr/'],
  });

  return { passed: 0, total: 1 };
}

function checkDataRectification(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  if (!hasUserAuth(files)) return { passed: 1, total: 1 };

  const allContent = [...files.values()].join('\n');
  const hasRectification =
    /(?:update.?profile|edit.?profile|modify.?data|rectif|correct.?data|change.?info|updateUser)\b/i.test(
      allContent,
    );

  if (hasRectification) return { passed: 1, total: 1 };

  findings.push({
    id: 'CMP-DR-004',
    severity: 'medium',
    layer: LAYER,
    layerName: NAME,
    regulation: [{ framework: 'gdpr', article: 'Art. 16', title: 'Right to Rectification' }],
    title: 'No data rectification capability',
    description:
      'Application has user authentication but no endpoint for users to correct their data',
    impact:
      'GDPR Art. 16 requires allowing users to rectify inaccurate personal data without undue delay',
    evidence: { file: 'project root' },
    fix: {
      description:
        'Add profile editing functionality so users can update their personal information',
      effort: 'sprint',
      automated: false,
    },
    references: ['https://gdpr-info.eu/art-16-gdpr/'],
  });

  return { passed: 0, total: 1 };
}

function checkPreferences(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  if (!hasUserAuth(files)) return { passed: 1, total: 1 };

  const allContent = [...files.values()].join('\n');
  const hasPreferences =
    /(?:settings|preferences|notification.?settings|email.?preferences|marketing.?opt|communication.?preferences)\b/i.test(
      allContent,
    );

  if (hasPreferences) return { passed: 1, total: 1 };

  findings.push({
    id: 'CMP-DR-005',
    severity: 'low',
    layer: LAYER,
    layerName: NAME,
    regulation: [{ framework: 'gdpr', article: 'Art. 21', title: 'Right to Object' }],
    title: 'No user preference/settings endpoint',
    description: 'Application has user authentication but no settings or preference management',
    impact:
      'Users should be able to manage communication preferences and object to certain processing',
    evidence: { file: 'project root' },
    fix: {
      description: 'Add a settings page for notification and communication preferences',
      effort: 'sprint',
      automated: false,
    },
    references: ['https://gdpr-info.eu/art-21-gdpr/'],
  });

  return { passed: 0, total: 1 };
}

function checkOptOutOfSale(
  files: Map<string, string>,
  findings: ComplyFinding[],
  frameworks: Set<ComplianceFramework>,
): { passed: number; total: number } {
  if (!frameworks.has('ccpa') && !frameworks.has('all')) return { passed: 1, total: 1 };
  if (!hasUserAuth(files)) return { passed: 1, total: 1 };

  const allContent = [...files.values()].join('\n');

  // Check if app shares data with third parties
  const sharesData = /(?:analytics|tracking|advertis|third.?party|share.*data|data.*shar)/i.test(
    allContent,
  );
  if (!sharesData) return { passed: 1, total: 1 };

  const hasOptOut = /(?:do.?not.?sell|opt.?out|ccpa.?opt|sale.?opt|sharing.?opt|dns)\b/i.test(
    allContent,
  );

  if (hasOptOut) return { passed: 1, total: 1 };

  findings.push({
    id: 'CMP-DR-006',
    severity: 'critical',
    layer: LAYER,
    layerName: NAME,
    regulation: [{ framework: 'ccpa', article: '§1798.120', title: 'Right to Opt-Out of Sale' }],
    title: 'No opt-out of sale/sharing endpoint (CCPA)',
    description:
      'Application shares data with third parties but lacks a "Do Not Sell My Personal Information" mechanism',
    impact:
      'CCPA requires a clear opt-out mechanism for the sale or sharing of personal information',
    evidence: { file: 'project root' },
    fix: {
      description:
        'Add a "Do Not Sell or Share My Personal Information" link and opt-out functionality',
      effort: 'sprint',
      automated: false,
    },
    references: ['https://oag.ca.gov/privacy/ccpa'],
  });

  return { passed: 0, total: 1 };
}

export async function runDataRightsLayer(
  files: Map<string, string>,
  _stackTags: Set<string>,
  _projectRoot: string,
  frameworks: Set<ComplianceFramework>,
): Promise<ComplyLayerResult> {
  const findings: ComplyFinding[] = [];

  const checks = [
    checkDataExport(files, findings),
    checkDataDeletion(files, findings),
    checkDataAccess(files, findings),
    checkDataRectification(files, findings),
    checkPreferences(files, findings),
    checkOptOutOfSale(files, findings, frameworks),
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
