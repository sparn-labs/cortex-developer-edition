/**
 * Weighted scoring engine for cortex comply.
 * 100-point scale with auto-downgrade rules for compliance violations.
 */

import type { ComplyFinding, ComplyGrade, ComplyLayerResult, ComplyLayerScore } from './types.js';
import { COMPLY_LAYER_WEIGHTS } from './types.js';

const GRADE_THRESHOLDS: Array<{ min: number; grade: ComplyGrade }> = [
  { min: 96, grade: 'S' },
  { min: 92, grade: 'A+++' },
  { min: 88, grade: 'A++' },
  { min: 84, grade: 'A+' },
  { min: 80, grade: 'A' },
  { min: 75, grade: 'A-' },
  { min: 70, grade: 'B+' },
  { min: 60, grade: 'B' },
  { min: 50, grade: 'B-' },
  { min: 35, grade: 'C' },
  { min: 15, grade: 'D' },
  { min: 0, grade: 'Zero' },
];

export function mapComplyGrade(score: number): ComplyGrade {
  for (const { min, grade } of GRADE_THRESHOLDS) {
    if (score >= min) return grade;
  }
  return 'Zero';
}

export function mapComplyLayerGrade(score: number, weight: number): ComplyGrade {
  if (weight === 0) return 'S';
  const pct = (score / weight) * 100;
  return mapComplyGrade(pct);
}

export interface ComplyScoringResult {
  global: number;
  grade: ComplyGrade;
  layers: Record<string, ComplyLayerScore>;
  cappedBy?: string;
}

/**
 * Auto-downgrade rules: enforce maximum score based on compliance violations.
 */
function applyDowngradeRules(
  score: number,
  findings: ComplyFinding[],
): { score: number; cappedBy?: string } {
  let cap = 100;
  let cappedBy: string | undefined;

  // PII collected with zero consent mechanism → max Zero (14)
  const hasPiiNoConsent =
    findings.some((f) => f.layer === 1 && (f.severity === 'critical' || f.severity === 'high')) &&
    findings.some((f) => f.id === 'CMP-CN-004' && f.severity === 'high');
  if (hasPiiNoConsent) {
    cap = Math.min(cap, 14);
    cappedBy = 'PII collected with zero consent mechanism';
  }

  // No privacy policy file detected → max D (34)
  const noPrivacyPolicy = findings.some((f) => f.id === 'CMP-CN-001');
  if (noPrivacyPolicy) {
    cap = Math.min(cap, 34);
    cappedBy = cappedBy || 'No privacy policy file detected';
  }

  // No data deletion capability → max C (49)
  const noDeletion = findings.some((f) => f.id === 'CMP-DR-002');
  if (noDeletion) {
    cap = Math.min(cap, 49);
    cappedBy = cappedBy || 'No data deletion capability';
  }

  // Health data without encryption → max C (49)
  const healthNoEncryption =
    findings.some((f) => f.id === 'CMP-PD-010') && findings.some((f) => f.id === 'CMP-DP-001');
  if (healthNoEncryption) {
    cap = Math.min(cap, 49);
    cappedBy = cappedBy || 'Health data without encryption';
  }

  // Third-party tracking without consent gate → max B (69)
  const trackingNoConsent = findings.some((f) => f.id === 'CMP-CN-005');
  if (trackingNoConsent) {
    cap = Math.min(cap, 69);
    cappedBy = cappedBy || 'Third-party tracking without consent gate';
  }

  // Any critical finding → max B+ (74)
  const hasCritical = findings.some((f) => f.severity === 'critical');
  if (hasCritical && cap > 74) {
    cap = Math.min(cap, 74);
    cappedBy = cappedBy || 'Critical compliance finding(s) present';
  }

  return { score: Math.min(score, cap), cappedBy };
}

export function computeComplyScore(
  layerResults: ComplyLayerResult[],
  allFindings: ComplyFinding[],
): ComplyScoringResult {
  const layers: Record<string, ComplyLayerScore> = {};
  let totalScore = 0;

  for (const result of layerResults) {
    const weight = COMPLY_LAYER_WEIGHTS[result.layer] ?? 0;
    const layerScore = Math.max(0, Math.min(weight, result.score));
    totalScore += layerScore;

    layers[String(result.layer)] = {
      layer: result.layer,
      name: result.name,
      weight,
      score: layerScore,
      passed: result.checksPassed,
      total: result.checksTotal,
      grade: mapComplyLayerGrade(layerScore, weight),
    };
  }

  totalScore = Math.round(totalScore * 100) / 100;

  const { score: finalScore, cappedBy } = applyDowngradeRules(totalScore, allFindings);
  const grade = mapComplyGrade(finalScore);

  return { global: finalScore, grade, layers, cappedBy };
}
