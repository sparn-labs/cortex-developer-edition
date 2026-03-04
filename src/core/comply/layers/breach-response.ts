/**
 * Layer 8 — Breach & Incident Response (7%)
 * Checks incident response plan, breach notification, monitoring, audit trails, DPO contact.
 */

import type { ComplianceFramework, ComplyFinding, ComplyLayerResult } from '../types.js';
import { getComplyLayerName, getComplyLayerWeight } from '../types.js';

const LAYER = 8;
const WEIGHT = getComplyLayerWeight(LAYER);
const NAME = getComplyLayerName(LAYER);

function isTestFile(path: string): boolean {
  return /\.(test|spec)\.|__tests__|\/tests\/|\/fixtures\/|benchmarks\/|\.bench\./i.test(path);
}

function checkIncidentResponsePlan(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  const hasIRPFile = [...files.keys()].some((f) =>
    /(?:incident|breach|response|disaster|contingency|runbook|playbook)/i.test(f),
  );

  const hasIRPContent = [...files.values()].some((content) =>
    /(?:incident.?response.?plan|breach.?notification|disaster.?recovery|business.?continuity|security.?incident)\b/i.test(
      content,
    ),
  );

  if (hasIRPFile || hasIRPContent) return { passed: 1, total: 1 };

  findings.push({
    id: 'CMP-BR-001',
    severity: 'medium',
    layer: LAYER,
    layerName: NAME,
    regulation: [
      { framework: 'gdpr', article: 'Art. 33', title: 'Notification of a Personal Data Breach' },
      { framework: 'hipaa', article: '§164.308(a)(6)', title: 'Security Incident Procedures' },
      { framework: 'soc2', article: 'CC7.3', title: 'Detection of Changes' },
    ],
    title: 'No incident response plan file detected',
    description: 'No incident response plan, runbook, or breach procedure documentation found',
    impact:
      'GDPR Art. 33 requires breach notification within 72 hours. An IRP ensures timely response',
    evidence: { file: 'project root' },
    fix: {
      description:
        'Create an incident response plan covering detection, containment, notification, and recovery',
      effort: 'quarter',
      automated: false,
    },
    references: ['https://gdpr-info.eu/art-33-gdpr/'],
  });

  return { passed: 0, total: 1 };
}

function checkBreachNotification(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  const allContent = [...files.values()].join('\n');

  const hasNotification =
    /(?:breach.?notif|notif.*breach|alert.*breach|incident.?alert|72.?hour|report.*breach|notify.*authority|supervisory.?authority)\b/i.test(
      allContent,
    );

  if (hasNotification) return { passed: 1, total: 1 };

  // Only flag if the app handles personal data
  const handlesPII = /(?:email|user|password|login|register|signup)\b/i.test(allContent);
  if (!handlesPII) return { passed: 1, total: 1 };

  findings.push({
    id: 'CMP-BR-002',
    severity: 'medium',
    layer: LAYER,
    layerName: NAME,
    regulation: [
      { framework: 'gdpr', article: 'Art. 33', title: 'Notification to Supervisory Authority' },
      { framework: 'gdpr', article: 'Art. 34', title: 'Communication to Data Subject' },
      { framework: 'ccpa', article: '§1798.82', title: 'Breach Notification' },
    ],
    title: 'No breach notification capability',
    description: 'No breach notification mechanism or procedure found in the application',
    impact:
      'GDPR requires notifying the supervisory authority within 72 hours and affected individuals without undue delay',
    evidence: { file: 'project root' },
    fix: {
      description:
        'Implement breach notification workflow: detect, assess, notify authority (72h), notify users if high risk',
      effort: 'quarter',
      automated: false,
    },
    references: ['https://gdpr-info.eu/art-33-gdpr/', 'https://gdpr-info.eu/art-34-gdpr/'],
  });

  return { passed: 0, total: 1 };
}

function checkMonitoringAlerting(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  const allContent = [...files.values()].join('\n');

  const hasMonitoring =
    /(?:monitoring|sentry|datadog|newrelic|prometheus|grafana|cloudwatch|alert|pagerduty|opsgenie|incident.?manage)\b/i.test(
      allContent,
    );

  if (hasMonitoring) return { passed: 1, total: 1 };

  // Only flag if there's a running service
  const isService =
    /(?:express|fastify|koa|nest|next|nuxt|flask|django|rails|spring|aspnet|server\.listen|createServer)\b/i.test(
      allContent,
    );
  if (!isService) return { passed: 1, total: 1 };

  findings.push({
    id: 'CMP-BR-003',
    severity: 'medium',
    layer: LAYER,
    layerName: NAME,
    regulation: [
      { framework: 'gdpr', article: 'Art. 32', title: 'Security of Processing' },
      { framework: 'soc2', article: 'CC7.2', title: 'Monitoring of System Components' },
    ],
    title: 'No monitoring/alerting for data access detected',
    description: 'No application monitoring or alerting system integration found',
    impact:
      'Without monitoring, breaches may go undetected for extended periods, increasing impact',
    evidence: { file: 'project root' },
    fix: {
      description:
        'Implement application monitoring with alerting for suspicious data access patterns',
      effort: 'sprint',
      automated: false,
    },
    references: ['https://gdpr-info.eu/art-32-gdpr/'],
  });

  return { passed: 0, total: 1 };
}

function checkAuditTrail(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  const allContent = [...files.values()].join('\n');

  const hasAuditTrail =
    /(?:audit.?log|audit.?trail|activity.?log|access.?log|event.?log|changelog|history.?table|createdBy|created_by|modifiedBy|modified_by|action.?log)\b/i.test(
      allContent,
    );

  if (hasAuditTrail) return { passed: 1, total: 1 };

  // Only flag if app has authentication
  const hasAuth = /(?:login|signup|register|authenticate)\b/i.test(allContent);
  if (!hasAuth) return { passed: 1, total: 1 };

  findings.push({
    id: 'CMP-BR-004',
    severity: 'medium',
    layer: LAYER,
    layerName: NAME,
    regulation: [
      { framework: 'soc2', article: 'CC7.1', title: 'Detection and Monitoring' },
      { framework: 'hipaa', article: '§164.312(b)', title: 'Audit Controls' },
    ],
    title: 'No audit trail implementation',
    description: 'No audit logging or activity trail found for user actions and data access',
    impact:
      'Audit trails are essential for investigating breaches, demonstrating compliance, and supporting forensics',
    evidence: { file: 'project root' },
    fix: {
      description:
        'Implement audit logging for authentication events, data access, and administrative actions',
      effort: 'sprint',
      automated: false,
    },
    references: [],
  });

  return { passed: 0, total: 1 };
}

function checkDPOContact(
  files: Map<string, string>,
  findings: ComplyFinding[],
  frameworks: Set<ComplianceFramework>,
): { passed: number; total: number } {
  if (!frameworks.has('gdpr') && !frameworks.has('all')) return { passed: 1, total: 1 };

  const allContent = [...files.entries()]
    .filter(([f]) => !isTestFile(f))
    .map(([, c]) => c)
    .join('\n');

  const hasDPO =
    /(?:dpo|data.?protection.?officer|datenschutzbeauftragter|privacy.?officer|privacy@|dpo@)\b/i.test(
      allContent,
    );

  if (hasDPO) return { passed: 1, total: 1 };

  findings.push({
    id: 'CMP-BR-005',
    severity: 'low',
    layer: LAYER,
    layerName: NAME,
    regulation: [{ framework: 'gdpr', article: 'Art. 37', title: 'Designation of DPO' }],
    title: 'No DPO contact information',
    description: 'No Data Protection Officer contact information found in the project',
    impact:
      'GDPR Art. 37-39 may require a DPO. Contact info should be published and communicated to the supervisory authority',
    evidence: { file: 'project root' },
    fix: {
      description: 'Add DPO or privacy contact information to privacy policy and contact pages',
      effort: 'immediate',
      automated: false,
    },
    references: ['https://gdpr-info.eu/art-37-gdpr/'],
  });

  return { passed: 0, total: 1 };
}

export async function runBreachResponseLayer(
  files: Map<string, string>,
  _stackTags: Set<string>,
  _projectRoot: string,
  frameworks: Set<ComplianceFramework>,
): Promise<ComplyLayerResult> {
  const findings: ComplyFinding[] = [];

  const checks = [
    checkIncidentResponsePlan(files, findings),
    checkBreachNotification(files, findings),
    checkMonitoringAlerting(files, findings),
    checkAuditTrail(files, findings),
    checkDPOContact(files, findings, frameworks),
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
