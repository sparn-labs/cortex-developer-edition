/**
 * Types for the enterprise security analyzer (`cortex secure`).
 * OWASP 2025-aligned, 10 defense layers, 100-point weighted scoring.
 */

export type SecureSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface SecureFinding {
  id: string;
  severity: SecureSeverity;
  layer: number;
  layerName: string;
  owasp: string;
  cwe?: string;
  cvss?: number;
  title: string;
  description: string;
  impact: string;
  evidence: { file: string; line?: number; snippet?: string };
  fix: {
    description: string;
    codeBefore?: string;
    codeAfter?: string;
    effort: 'immediate' | 'sprint' | 'quarter';
    automated: boolean;
  };
  references: string[];
}

export interface LayerResult {
  layer: number;
  name: string;
  weight: number;
  checksPassed: number;
  checksTotal: number;
  score: number;
  findings: SecureFinding[];
}

export type SecureGrade =
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

export interface LayerScore {
  layer: number;
  name: string;
  weight: number;
  score: number;
  passed: number;
  total: number;
  grade: SecureGrade;
}

export interface ComplianceItem {
  control: string;
  description: string;
  status: 'pass' | 'fail' | 'partial' | 'n/a';
  findings: string[];
}

export interface ComplianceMatrix {
  framework: string;
  items: ComplianceItem[];
  passRate: number;
}

export interface AttackSurface {
  totalEndpoints: number;
  authenticatedEndpoints: number;
  unauthenticatedEndpoints: number;
  rateLimitedEndpoints: number;
  publicFiles: number;
  externalDependencies: number;
  cryptoUsages: number;
  inputPoints: number;
}

export interface RemediationItem {
  findingId: string;
  title: string;
  severity: SecureSeverity;
  effort: 'immediate' | 'sprint' | 'quarter';
  automated: boolean;
  description: string;
}

export interface RemediationRoadmap {
  immediate: RemediationItem[];
  sprint: RemediationItem[];
  quarter: RemediationItem[];
  totalFindings: number;
  automatable: number;
}

export interface SecureReport {
  version: string;
  timestamp: string;
  project: { name: string; path: string; stack: string[] };
  score: {
    global: number;
    grade: SecureGrade;
    layers: Record<string, LayerScore>;
  };
  findings: SecureFinding[];
  compliance: ComplianceMatrix;
  attackSurface: AttackSurface;
  remediationRoadmap: RemediationRoadmap;
}

export interface SecureAuditOptions {
  path: string;
  fix?: boolean;
  ci?: boolean;
  minGrade?: string;
  failOn?: string;
  layer?: string;
  compare?: string;
  output?: string;
  outputFile?: string;
  quick?: boolean;
  compliance?: string;
  verbose?: boolean;
}

export interface SecureLayerCheck {
  layer: number;
  name: string;
  weight: number;
  run(
    files: Map<string, string>,
    stackTags: Set<string>,
    projectRoot: string,
  ): Promise<LayerResult>;
}

const _LAYER_WEIGHTS: Record<number, number> = {
  1: 15,
  2: 12,
  3: 12,
  4: 10,
  5: 12,
  6: 8,
  7: 10,
  8: 6,
  9: 8,
  10: 5,
  11: 2,
};

const _LAYER_NAMES: Record<number, string> = {
  1: 'Access Control & Identity',
  2: 'Security Misconfiguration',
  3: 'Supply Chain Security',
  4: 'Cryptographic Failures',
  5: 'Injection Prevention',
  6: 'Secure Design',
  7: 'Auth & Session Management',
  8: 'Data Integrity',
  9: 'Logging & Monitoring',
  10: 'Error Handling & Resilience',
  11: 'Zero Trust & PQC Readiness',
};

export function getLayerWeight(layer: number): number {
  const w = _LAYER_WEIGHTS[layer];
  if (w === undefined) throw new Error(`Unknown layer: ${layer}`);
  return w;
}

export function getLayerName(layer: number): string {
  const n = _LAYER_NAMES[layer];
  if (n === undefined) throw new Error(`Unknown layer: ${layer}`);
  return n;
}

export const LAYER_WEIGHTS = _LAYER_WEIGHTS;
export const LAYER_NAMES = _LAYER_NAMES;
