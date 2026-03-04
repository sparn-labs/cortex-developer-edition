/**
 * Comply audit engine — orchestrates all 8 layers, computes score, builds report.
 */

import { resolve } from 'node:path';
import { buildAnalysisContext, getProjectName } from '../analyzers/context-builder.js';
import { runBreachResponseLayer } from './layers/breach-response.js';
import { runConsentNoticeLayer } from './layers/consent-notice.js';
import { runCrossBorderLayer } from './layers/cross-border.js';
import { runDataMinimizationLayer } from './layers/data-minimization.js';
import { runDataProtectionLayer } from './layers/data-protection.js';
import { runDataRightsLayer } from './layers/data-rights.js';
import { runPersonalDataLayer } from './layers/personal-data.js';
import { runThirdPartyLayer } from './layers/third-party.js';
import { computeComplyScore } from './scorer.js';
import type {
  ComplianceFramework,
  ComplyAuditOptions,
  ComplyFinding,
  ComplyLayerResult,
  ComplyRemediationItem,
  ComplyRemediationRoadmap,
  ComplyReport,
  DataFlowItem,
  DataFlowSummary,
  FrameworkComplianceItem,
  FrameworkComplianceMatrix,
} from './types.js';

type ComplyLayerRunner = (
  files: Map<string, string>,
  stackTags: Set<string>,
  projectRoot: string,
  frameworks: Set<ComplianceFramework>,
) => Promise<ComplyLayerResult>;

const ALL_LAYERS: Array<{ layer: number; run: ComplyLayerRunner }> = [
  { layer: 1, run: runPersonalDataLayer },
  { layer: 2, run: runConsentNoticeLayer },
  { layer: 3, run: runDataRightsLayer },
  { layer: 4, run: runDataMinimizationLayer },
  { layer: 5, run: runCrossBorderLayer },
  { layer: 6, run: runDataProtectionLayer },
  { layer: 7, run: runThirdPartyLayer },
  { layer: 8, run: runBreachResponseLayer },
];

function parseLayerFilter(filter?: string): Set<number> | null {
  if (!filter) return null;
  const nums = filter
    .split(',')
    .map((s) => Number.parseInt(s.trim(), 10))
    .filter((n) => !Number.isNaN(n));
  return nums.length > 0 ? new Set(nums) : null;
}

function parseFrameworks(framework?: string): Set<ComplianceFramework> {
  if (!framework || framework === 'all') return new Set(['all'] as ComplianceFramework[]);
  const valid = new Set<ComplianceFramework>();
  for (const f of framework.split(',')) {
    const trimmed = f.trim().toLowerCase() as ComplianceFramework;
    if (['gdpr', 'ccpa', 'hipaa', 'soc2'].includes(trimmed)) {
      valid.add(trimmed);
    }
  }
  return valid.size > 0 ? valid : new Set(['all'] as ComplianceFramework[]);
}

// --- GDPR Articles ---
const GDPR_ARTICLES: Array<{ article: string; title: string }> = [
  { article: 'Art. 5', title: 'Principles (lawfulness, minimisation, storage limitation)' },
  { article: 'Art. 6', title: 'Lawfulness of Processing' },
  { article: 'Art. 7', title: 'Conditions for Consent' },
  { article: 'Art. 8', title: "Child's Consent" },
  { article: 'Art. 9', title: 'Special Categories of Data' },
  { article: 'Art. 13', title: 'Information to be Provided (collection from data subject)' },
  { article: 'Art. 15', title: 'Right of Access' },
  { article: 'Art. 16', title: 'Right to Rectification' },
  { article: 'Art. 17', title: 'Right to Erasure' },
  { article: 'Art. 20', title: 'Right to Data Portability' },
  { article: 'Art. 21', title: 'Right to Object' },
  { article: 'Art. 25', title: 'Data Protection by Design and Default' },
  { article: 'Art. 28', title: 'Processor' },
  { article: 'Art. 32', title: 'Security of Processing' },
  { article: 'Art. 33', title: 'Notification of Breach to Authority' },
  { article: 'Art. 34', title: 'Communication of Breach to Data Subject' },
  { article: 'Art. 37', title: 'Designation of DPO' },
  { article: 'Art. 44', title: 'Transfer to Third Countries' },
];

// --- CCPA Sections ---
const CCPA_SECTIONS: Array<{ article: string; title: string }> = [
  { article: '§1798.100', title: 'Right to Know / Access' },
  { article: '§1798.105', title: 'Right to Delete' },
  { article: '§1798.110', title: 'Right to Know Categories' },
  { article: '§1798.120', title: 'Right to Opt-Out of Sale' },
  { article: '§1798.130', title: 'Notice Requirements' },
  { article: '§1798.140', title: 'Definitions (Personal Information)' },
  { article: '§1798.82', title: 'Breach Notification' },
];

// --- HIPAA Rules ---
const HIPAA_RULES: Array<{ article: string; title: string }> = [
  { article: '§164.308', title: 'Administrative Safeguards' },
  { article: '§164.310', title: 'Physical Safeguards' },
  { article: '§164.312', title: 'Technical Safeguards' },
  { article: '§164.502', title: 'Uses and Disclosures of PHI' },
  { article: '§164.514', title: 'De-identification Standard' },
];

// --- SOC2 Criteria ---
const SOC2_CRITERIA: Array<{ article: string; title: string }> = [
  { article: 'CC2.2', title: 'Communication of Policies' },
  { article: 'CC6.1', title: 'Logical and Physical Access Controls' },
  { article: 'CC6.5', title: 'Data Disposal' },
  { article: 'CC7.1', title: 'Detection and Monitoring' },
  { article: 'CC7.2', title: 'Monitoring of System Components' },
  { article: 'CC7.3', title: 'Detection of Changes' },
];

function buildFrameworkMatrices(
  findings: ComplyFinding[],
  frameworks: Set<ComplianceFramework>,
): FrameworkComplianceMatrix[] {
  const matrices: FrameworkComplianceMatrix[] = [];

  const buildMatrix = (
    framework: ComplianceFramework,
    articles: Array<{ article: string; title: string }>,
  ): FrameworkComplianceMatrix => {
    const items: FrameworkComplianceItem[] = articles.map((art) => {
      const related = findings.filter((f) =>
        f.regulation.some((r) => r.framework === framework && r.article === art.article),
      );
      const criticalOrHigh = related.filter(
        (f) => f.severity === 'critical' || f.severity === 'high',
      );

      let status: 'compliant' | 'non-compliant' | 'partial' | 'n/a';
      if (related.length === 0) {
        status = 'compliant';
      } else if (criticalOrHigh.length > 0) {
        status = 'non-compliant';
      } else {
        status = 'partial';
      }

      return {
        article: art.article,
        title: art.title,
        status,
        findings: related.map((f) => f.id),
      };
    });

    const compliantCount = items.filter((i) => i.status === 'compliant').length;
    const complianceRate = Math.round((compliantCount / items.length) * 100);

    return { framework, items, complianceRate };
  };

  if (frameworks.has('all') || frameworks.has('gdpr')) {
    matrices.push(buildMatrix('gdpr', GDPR_ARTICLES));
  }
  if (frameworks.has('all') || frameworks.has('ccpa')) {
    matrices.push(buildMatrix('ccpa', CCPA_SECTIONS));
  }
  if (frameworks.has('all') || frameworks.has('hipaa')) {
    matrices.push(buildMatrix('hipaa', HIPAA_RULES));
  }
  if (frameworks.has('all') || frameworks.has('soc2')) {
    matrices.push(buildMatrix('soc2', SOC2_CRITERIA));
  }

  return matrices;
}

function buildDataFlowSummary(findings: ComplyFinding[]): DataFlowSummary {
  const items: DataFlowItem[] = [];

  // Extract data types from Layer 1 and Layer 7 findings
  const piiFindings = findings.filter((f) => f.layer === 1 || f.layer === 7);

  const dataTypeMap: Record<string, { category: DataFlowItem['category']; id: string }> = {
    'CMP-PD-001': { category: 'pii', id: 'email' },
    'CMP-PD-002': { category: 'pii', id: 'name' },
    'CMP-PD-003': { category: 'pii', id: 'phone' },
    'CMP-PD-004': { category: 'pii', id: 'address' },
    'CMP-PD-005': { category: 'sensitive', id: 'national-id' },
    'CMP-PD-006': { category: 'pii', id: 'date-of-birth' },
    'CMP-PD-007': { category: 'behavioral', id: 'ip-address' },
    'CMP-PD-008': { category: 'behavioral', id: 'geolocation' },
    'CMP-PD-009': { category: 'biometric', id: 'biometric' },
    'CMP-PD-010': { category: 'health', id: 'sensitive-category' },
    'CMP-PD-011': { category: 'financial', id: 'financial' },
  };

  const seen = new Set<string>();

  for (const f of piiFindings) {
    const mapping = dataTypeMap[f.id];
    if (!mapping || seen.has(mapping.id)) continue;
    seen.add(mapping.id);

    items.push({
      dataType: mapping.id,
      category: mapping.category,
      collectionPoints: [f.evidence.file],
      hasConsent: false, // Finding exists = no consent found
      hasEncryption: !findings.some((ef) => ef.id === 'CMP-DP-001'),
      hasRetentionPolicy: !findings.some((ef) => ef.id === 'CMP-DM-002'),
    });
  }

  const totalDataTypes = items.length;
  const consentCoverage =
    totalDataTypes > 0
      ? Math.round((items.filter((i) => i.hasConsent).length / totalDataTypes) * 100)
      : 100;
  const encryptionCoverage =
    totalDataTypes > 0
      ? Math.round((items.filter((i) => i.hasEncryption).length / totalDataTypes) * 100)
      : 100;

  return { items, totalDataTypes, consentCoverage, encryptionCoverage };
}

function buildRemediationRoadmap(findings: ComplyFinding[]): ComplyRemediationRoadmap {
  const immediate: ComplyFinding[] = [];
  const sprint: ComplyFinding[] = [];
  const quarter: ComplyFinding[] = [];

  const severityOrder: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };
  const sorted = [...findings].sort(
    (a, b) => (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4),
  );

  for (const f of sorted) {
    if (f.fix.effort === 'immediate') immediate.push(f);
    else if (f.fix.effort === 'sprint') sprint.push(f);
    else quarter.push(f);
  }

  const toItem = (f: ComplyFinding): ComplyRemediationItem => ({
    findingId: f.id,
    title: f.title,
    severity: f.severity,
    effort: f.fix.effort,
    automated: f.fix.automated,
    description: f.fix.description,
  });

  return {
    immediate: immediate.map(toItem),
    sprint: sprint.map(toItem),
    quarter: quarter.map(toItem),
    totalFindings: findings.length,
    automatable: findings.filter((f) => f.fix.automated).length,
  };
}

export async function runComplyAudit(options: ComplyAuditOptions): Promise<ComplyReport> {
  const projectRoot = resolve(options.path);

  // 1. Build AnalysisContext (reuse existing context-builder)
  const context = await buildAnalysisContext(projectRoot);

  // 2. Parse frameworks
  const frameworks = parseFrameworks(options.framework);

  // 3. Filter layers
  const layerFilter = parseLayerFilter(options.layer);
  let layers = ALL_LAYERS;
  if (layerFilter) {
    layers = layers.filter((l) => layerFilter.has(l.layer));
  }

  // 4. Quick mode — layers 1, 2, 3 only
  if (options.quick) {
    layers = layers.filter((l) => [1, 2, 3].includes(l.layer));
  }

  // 5. Run layers
  const layerResults: ComplyLayerResult[] = [];
  for (const { run } of layers) {
    const result = await run(context.files, context.stackTags, projectRoot, frameworks);
    layerResults.push(result);
  }

  // 6. Collect all findings
  const allFindings = layerResults.flatMap((r) => r.findings);

  // 7. Compute score
  const scoring = computeComplyScore(layerResults, allFindings);

  // 8. Build per-framework compliance matrices
  const frameworkMatrices = buildFrameworkMatrices(allFindings, frameworks);

  // 9. Build data flow summary
  const dataFlow = buildDataFlowSummary(allFindings);

  // 10. Build remediation roadmap
  const remediationRoadmap = buildRemediationRoadmap(allFindings);

  // 11. Build report
  const projectName = getProjectName(projectRoot);
  const frameworkList = frameworks.has('all')
    ? (['gdpr', 'ccpa', 'hipaa', 'soc2'] as ComplianceFramework[])
    : ([...frameworks] as ComplianceFramework[]);

  return {
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    project: {
      name: projectName,
      path: projectRoot,
      stack: [...context.stackTags],
    },
    frameworks: frameworkList,
    score: {
      global: scoring.global,
      grade: scoring.grade,
      layers: scoring.layers,
    },
    findings: allFindings,
    frameworkMatrices,
    dataFlow,
    remediationRoadmap,
  };
}
