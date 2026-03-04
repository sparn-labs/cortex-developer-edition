import { describe, expect, it } from 'vitest';
import { computeSecureScore, mapSecureGrade } from '../../../src/core/secure/scorer.js';
import type { LayerResult, SecureFinding } from '../../../src/core/secure/types.js';
import { LAYER_NAMES, LAYER_WEIGHTS } from '../../../src/core/secure/types.js';

function makeLayerResult(layer: number, ratio: number): LayerResult {
  const weight = LAYER_WEIGHTS[layer] ?? 0;
  return {
    layer,
    name: LAYER_NAMES[layer] ?? `Layer ${layer}`,
    weight,
    checksPassed: Math.round(ratio * 10),
    checksTotal: 10,
    score: weight * ratio,
    findings: [],
  };
}

function makeFinding(overrides: Partial<SecureFinding>): SecureFinding {
  return {
    id: 'SEC-TEST-001',
    severity: 'medium',
    layer: 1,
    layerName: 'Test',
    owasp: 'A01:2025',
    title: 'Test finding',
    description: 'Test',
    impact: 'Test',
    evidence: { file: 'test.ts' },
    fix: { description: 'Fix', effort: 'immediate', automated: false },
    references: [],
    ...overrides,
  };
}

describe('Secure Scorer', () => {
  describe('mapSecureGrade', () => {
    it('should return S for score >= 96', () => {
      expect(mapSecureGrade(96)).toBe('S');
      expect(mapSecureGrade(100)).toBe('S');
    });

    it('should return A+++ for score 92-95', () => {
      expect(mapSecureGrade(92)).toBe('A+++');
      expect(mapSecureGrade(95)).toBe('A+++');
    });

    it('should return A++ for score 88-91', () => {
      expect(mapSecureGrade(88)).toBe('A++');
      expect(mapSecureGrade(91)).toBe('A++');
    });

    it('should return A+ for score 84-87', () => {
      expect(mapSecureGrade(84)).toBe('A+');
    });

    it('should return A for score 80-83', () => {
      expect(mapSecureGrade(80)).toBe('A');
    });

    it('should return A- for score 75-79', () => {
      expect(mapSecureGrade(75)).toBe('A-');
    });

    it('should return B+ for score 70-74', () => {
      expect(mapSecureGrade(70)).toBe('B+');
    });

    it('should return B for score 60-69', () => {
      expect(mapSecureGrade(60)).toBe('B');
    });

    it('should return B- for score 50-59', () => {
      expect(mapSecureGrade(50)).toBe('B-');
    });

    it('should return C for score 35-49', () => {
      expect(mapSecureGrade(35)).toBe('C');
    });

    it('should return D for score 15-34', () => {
      expect(mapSecureGrade(15)).toBe('D');
    });

    it('should return Zero for score 0-14', () => {
      expect(mapSecureGrade(0)).toBe('Zero');
      expect(mapSecureGrade(14)).toBe('Zero');
    });
  });

  describe('computeSecureScore', () => {
    it('should compute perfect score when all layers pass', () => {
      const results = Array.from({ length: 11 }, (_, i) => makeLayerResult(i + 1, 1));
      const score = computeSecureScore(results, []);

      expect(score.global).toBe(100);
      expect(score.grade).toBe('S');
    });

    it('should compute zero score when all layers fail', () => {
      const results = Array.from({ length: 11 }, (_, i) => makeLayerResult(i + 1, 0));
      const score = computeSecureScore(results, []);

      expect(score.global).toBe(0);
      expect(score.grade).toBe('Zero');
    });

    it('should compute partial score correctly', () => {
      const results = Array.from({ length: 11 }, (_, i) => makeLayerResult(i + 1, 0.5));
      const score = computeSecureScore(results, []);

      // Sum of all weights * 0.5 = 100 * 0.5 = 50
      expect(score.global).toBe(50);
      expect(score.grade).toBe('B-');
    });

    it('should produce correct layer scores', () => {
      const results = [makeLayerResult(1, 0.8), makeLayerResult(5, 1)];
      const score = computeSecureScore(results, []);

      expect(score.layers['1'].score).toBe(12); // 15 * 0.8
      expect(score.layers['1'].weight).toBe(15);
      expect(score.layers['5'].score).toBe(12); // 12 * 1
    });

    it('should cap score with critical finding → max B+ (74)', () => {
      const results = Array.from({ length: 11 }, (_, i) => makeLayerResult(i + 1, 1));
      const findings = [makeFinding({ severity: 'critical' })];
      const score = computeSecureScore(results, findings);

      expect(score.global).toBeLessThanOrEqual(74);
      expect(score.grade).toBe('B+');
    });

    it('should cap score with hardcoded secrets → max B (69)', () => {
      const results = Array.from({ length: 11 }, (_, i) => makeLayerResult(i + 1, 1));
      const findings = [makeFinding({ id: 'SEC-CR-002', severity: 'critical' })];
      const score = computeSecureScore(results, findings);

      expect(score.global).toBeLessThanOrEqual(69);
    });

    it('should cap score with SQL injection → max C (49)', () => {
      const results = Array.from({ length: 11 }, (_, i) => makeLayerResult(i + 1, 1));
      const findings = [makeFinding({ id: 'SEC-INJ-001', severity: 'critical' })];
      const score = computeSecureScore(results, findings);

      expect(score.global).toBeLessThanOrEqual(49);
    });

    it('should cap score with no HTTPS → max D (34)', () => {
      const results = Array.from({ length: 11 }, (_, i) => makeLayerResult(i + 1, 1));
      const findings = [makeFinding({ id: 'SEC-MC-007', severity: 'high' })];
      const score = computeSecureScore(results, findings);

      expect(score.global).toBeLessThanOrEqual(34);
    });
  });
});
