/**
 * Score computation with N/A weight redistribution and grade mapping.
 */

import type { CategoryResult, Grade, ScoreResult } from './types.js';

const GRADE_THRESHOLDS: Array<{ min: number; grade: Grade }> = [
  { min: 95, grade: 'S' },
  { min: 90, grade: 'A+++' },
  { min: 85, grade: 'A++' },
  { min: 80, grade: 'A+' },
  { min: 75, grade: 'A' },
  { min: 65, grade: 'B' },
  { min: 55, grade: 'B-' },
  { min: 40, grade: 'C' },
  { min: 20, grade: 'D' },
  { min: 0, grade: 'Zero' },
];

export function mapGrade(score: number): Grade {
  for (const { min, grade } of GRADE_THRESHOLDS) {
    if (score >= min) return grade;
  }
  return 'Zero';
}

export function computeScore(results: CategoryResult[]): ScoreResult {
  const activeResults = results.filter((r) => !r.isNA);
  const naResults = results.filter((r) => r.isNA);

  // If all categories are N/A, return a neutral score
  if (activeResults.length === 0) {
    const categories: ScoreResult['categories'] = {};
    for (const r of results) {
      categories[r.category] = {
        score: r.score,
        maxPoints: r.maxPoints,
        scaledScore: 0,
        scaledMax: 0,
        isNA: true,
      };
    }
    return { totalScore: 0, grade: 'Zero', categories };
  }

  const activeMaxTotal = activeResults.reduce((sum, r) => sum + r.maxPoints, 0);
  const scaleFactor = activeMaxTotal > 0 ? 100 / activeMaxTotal : 1;

  const categories: ScoreResult['categories'] = {};
  let totalScaled = 0;

  for (const r of activeResults) {
    const scaledMax = r.maxPoints * scaleFactor;
    const ratio = r.maxPoints > 0 ? r.score / r.maxPoints : 0;
    const scaledScore = scaledMax * ratio;
    totalScaled += scaledScore;
    categories[r.category] = {
      score: r.score,
      maxPoints: r.maxPoints,
      scaledScore: Math.round(scaledScore * 100) / 100,
      scaledMax: Math.round(scaledMax * 100) / 100,
      isNA: false,
    };
  }

  for (const r of naResults) {
    categories[r.category] = {
      score: 0,
      maxPoints: r.maxPoints,
      scaledScore: 0,
      scaledMax: 0,
      isNA: true,
    };
  }

  const totalScore = Math.round(Math.min(100, Math.max(0, totalScaled)) * 100) / 100;

  return {
    totalScore,
    grade: mapGrade(totalScore),
    categories,
  };
}
