/**
 * Types for the legal & regulatory compliance analyzer (`cortex comply`).
 * GDPR, CCPA, HIPAA, SOC2 — 8 compliance layers, 100-point weighted scoring.
 */

export type ComplySeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ComplianceFramework = 'gdpr' | 'ccpa' | 'hipaa' | 'soc2' | 'all';

export interface RegulatoryReference {
  framework: ComplianceFramework;
  article: string;
  title: string;
}

export interface ComplyFinding {
  id: string;
  severity: ComplySeverity;
  layer: number;
  layerName: string;
  regulation: RegulatoryReference[];
  title: string;
  description: string;
  impact: string;
  evidence: { file: string; line?: number; snippet?: string };
  fix: {
    description: string;
    effort: 'immediate' | 'sprint' | 'quarter';
    automated: boolean;
  };
  references: string[];
}

export interface ComplyLayerResult {
  layer: number;
  name: string;
  weight: number;
  checksPassed: number;
  checksTotal: number;
  score: number;
  findings: ComplyFinding[];
}

export type ComplyGrade =
  | 'S'
  | 'A+++'
  | 'A++'
  | 'A+'
  | 'A'
  | 'A-'
  | 'B+'
  | 'B'
  | 'B-'
  | 'C'
  | 'D'
  | 'Zero';

export interface ComplyLayerScore {
  layer: number;
  name: string;
  weight: number;
  score: number;
  passed: number;
  total: number;
  grade: ComplyGrade;
}

export interface FrameworkComplianceItem {
  article: string;
  title: string;
  status: 'compliant' | 'non-compliant' | 'partial' | 'n/a';
  findings: string[];
}

export interface FrameworkComplianceMatrix {
  framework: ComplianceFramework;
  items: FrameworkComplianceItem[];
  complianceRate: number;
}

export interface DataFlowItem {
  dataType: string;
  category: 'pii' | 'sensitive' | 'financial' | 'health' | 'biometric' | 'behavioral';
  collectionPoints: string[];
  hasConsent: boolean;
  hasEncryption: boolean;
  hasRetentionPolicy: boolean;
}

export interface DataFlowSummary {
  items: DataFlowItem[];
  totalDataTypes: number;
  consentCoverage: number;
  encryptionCoverage: number;
}

export interface ComplyRemediationItem {
  findingId: string;
  title: string;
  severity: ComplySeverity;
  effort: 'immediate' | 'sprint' | 'quarter';
  automated: boolean;
  description: string;
}

export interface ComplyRemediationRoadmap {
  immediate: ComplyRemediationItem[];
  sprint: ComplyRemediationItem[];
  quarter: ComplyRemediationItem[];
  totalFindings: number;
  automatable: number;
}

export interface ComplyReport {
  version: string;
  timestamp: string;
  project: { name: string; path: string; stack: string[] };
  frameworks: ComplianceFramework[];
  score: {
    global: number;
    grade: ComplyGrade;
    layers: Record<string, ComplyLayerScore>;
  };
  findings: ComplyFinding[];
  frameworkMatrices: FrameworkComplianceMatrix[];
  dataFlow: DataFlowSummary;
  remediationRoadmap: ComplyRemediationRoadmap;
}

export interface ComplyAuditOptions {
  path: string;
  ci?: boolean;
  minGrade?: string;
  failOn?: string;
  framework?: string;
  layer?: string;
  output?: string;
  outputFile?: string;
  quick?: boolean;
  verbose?: boolean;
}

const _COMPLY_LAYER_WEIGHTS: Record<number, number> = {
  1: 20,
  2: 18,
  3: 15,
  4: 12,
  5: 10,
  6: 10,
  7: 8,
  8: 7,
};

const _COMPLY_LAYER_NAMES: Record<number, string> = {
  1: 'Personal Data Handling',
  2: 'Consent & Notice',
  3: 'Data Subject Rights',
  4: 'Data Minimization & Retention',
  5: 'Cross-Border Data Transfers',
  6: 'Data Protection & Encryption',
  7: 'Third-Party & Vendor Compliance',
  8: 'Breach & Incident Response',
};

export function getComplyLayerWeight(layer: number): number {
  const w = _COMPLY_LAYER_WEIGHTS[layer];
  if (w === undefined) throw new Error(`Unknown comply layer: ${layer}`);
  return w;
}

export function getComplyLayerName(layer: number): string {
  const n = _COMPLY_LAYER_NAMES[layer];
  if (n === undefined) throw new Error(`Unknown comply layer: ${layer}`);
  return n;
}

export const COMPLY_LAYER_WEIGHTS = _COMPLY_LAYER_WEIGHTS;
export const COMPLY_LAYER_NAMES = _COMPLY_LAYER_NAMES;
