/**
 * Weighted scoring engine for cortex secure.
 * 100-point scale with auto-downgrade rules for critical findings.
 */

import type { LayerResult, LayerScore, SecureFinding, SecureGrade } from './types.js';
import { LAYER_WEIGHTS } from './types.js';

const GRADE_THRESHOLDS: Array<{ min: number; grade: SecureGrade }> = [
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

export function mapSecureGrade(score: number): SecureGrade {
  for (const { min, grade } of GRADE_THRESHOLDS) {
    if (score >= min) return grade;
  }
  return 'Zero';
}

export function mapLayerGrade(score: number, weight: number): SecureGrade {
  if (weight === 0) return 'S';
  const pct = (score / weight) * 100;
  return mapSecureGrade(pct);
}

export interface ScoringResult {
  global: number;
  grade: SecureGrade;
  layers: Record<string, LayerScore>;
  cappedBy?: string;
}

/**
 * Auto-downgrade rules: enforce maximum grade based on critical findings.
 */
function applyDowngradeRules(
  score: number,
  findings: SecureFinding[],
): { score: number; cappedBy?: string } {
  let cap = 100;
  let cappedBy: string | undefined;

  // Default credentials → max Zero (14)
  const hasDefaultCreds = findings.some(
    (f) =>
      f.id.includes('SEC-CR-002') &&
      f.severity === 'critical' &&
      f.title.toLowerCase().includes('default'),
  );
  if (hasDefaultCreds) {
    cap = Math.min(cap, 14);
    cappedBy = 'Default credentials detected';
  }

  // No HTTPS → max D (34)
  const noHttps = findings.some((f) => f.id === 'SEC-MC-007' && f.severity === 'high');
  if (noHttps) {
    cap = Math.min(cap, 34);
    cappedBy = 'No HTTPS enforcement';
  }

  // SQL injection → max C (49)
  const hasSQLi = findings.some(
    (f) => f.id === 'SEC-INJ-001' && (f.severity === 'critical' || f.severity === 'high'),
  );
  if (hasSQLi) {
    cap = Math.min(cap, 49);
    cappedBy = 'SQL injection possible';
  }

  // Secrets in code → max B (69)
  const hasSecrets = findings.some((f) => f.id === 'SEC-CR-002' && f.severity === 'critical');
  if (hasSecrets) {
    cap = Math.min(cap, 69);
    cappedBy = cappedBy || 'Hardcoded secrets in code';
  }

  // Any critical finding → max B+ (74)
  const hasCritical = findings.some((f) => f.severity === 'critical');
  if (hasCritical && cap > 74) {
    cap = Math.min(cap, 74);
    cappedBy = cappedBy || 'Critical finding(s) present';
  }

  return { score: Math.min(score, cap), cappedBy };
}

export function computeSecureScore(
  layerResults: LayerResult[],
  allFindings: SecureFinding[],
): ScoringResult {
  const layers: Record<string, LayerScore> = {};
  let totalScore = 0;

  for (const result of layerResults) {
    const weight = LAYER_WEIGHTS[result.layer] ?? 0;
    const layerScore = Math.max(0, Math.min(weight, result.score));
    totalScore += layerScore;

    layers[String(result.layer)] = {
      layer: result.layer,
      name: result.name,
      weight,
      score: layerScore,
      passed: result.checksPassed,
      total: result.checksTotal,
      grade: mapLayerGrade(layerScore, weight),
    };
  }

  totalScore = Math.round(totalScore * 100) / 100;

  const { score: finalScore, cappedBy } = applyDowngradeRules(totalScore, allFindings);
  const grade = mapSecureGrade(finalScore);

  return { global: finalScore, grade, layers, cappedBy };
}
