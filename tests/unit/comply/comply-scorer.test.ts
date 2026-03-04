/**
 * Comply Scorer Tests
 */

import { describe, expect, it } from 'vitest';
import {
  computeComplyScore,
  mapComplyGrade,
  mapComplyLayerGrade,
} from '../../../src/core/comply/scorer.js';
import type { ComplyFinding, ComplyLayerResult } from '../../../src/core/comply/types.js';

function makeFinding(overrides: Partial<ComplyFinding> = {}): ComplyFinding {
  return {
    id: 'CMP-TEST-001',
    severity: 'medium',
    layer: 1,
    layerName: 'Personal Data Handling',
    regulation: [{ framework: 'gdpr', article: 'Art. 6', title: 'Lawfulness' }],
    title: 'Test finding',
    description: 'Test',
    impact: 'Test',
    evidence: { file: 'test.ts' },
    fix: { description: 'Fix it', effort: 'sprint', automated: false },
    references: [],
    ...overrides,
  };
}

function makeLayerResult(overrides: Partial<ComplyLayerResult> = {}): ComplyLayerResult {
  return {
    layer: 1,
    name: 'Personal Data Handling',
    weight: 20,
    checksPassed: 10,
    checksTotal: 10,
    score: 20,
    findings: [],
    ...overrides,
  };
}

describe('Comply Scorer', () => {
  describe('mapComplyGrade', () => {
    it('should return S for 96+', () => {
      expect(mapComplyGrade(96)).toBe('S');
      expect(mapComplyGrade(100)).toBe('S');
    });

    it('should return A+++ for 92-95', () => {
      expect(mapComplyGrade(92)).toBe('A+++');
      expect(mapComplyGrade(95)).toBe('A+++');
    });

    it('should return A for 80-83', () => {
      expect(mapComplyGrade(80)).toBe('A');
      expect(mapComplyGrade(83)).toBe('A');
    });

    it('should return Zero for 0-14', () => {
      expect(mapComplyGrade(0)).toBe('Zero');
      expect(mapComplyGrade(14)).toBe('Zero');
    });

    it('should return D for 15-34', () => {
      expect(mapComplyGrade(15)).toBe('D');
      expect(mapComplyGrade(34)).toBe('D');
    });

    it('should return C for 35-49', () => {
      expect(mapComplyGrade(35)).toBe('C');
      expect(mapComplyGrade(49)).toBe('C');
    });
  });

  describe('mapComplyLayerGrade', () => {
    it('should grade layer based on percentage of weight', () => {
      expect(mapComplyLayerGrade(20, 20)).toBe('S'); // 100%
      expect(mapComplyLayerGrade(16, 20)).toBe('A'); // 80%
      expect(mapComplyLayerGrade(0, 20)).toBe('Zero'); // 0%
    });

    it('should return S for zero weight', () => {
      expect(mapComplyLayerGrade(0, 0)).toBe('S');
    });
  });

  describe('computeComplyScore', () => {
    it('should compute perfect score when all layers pass', () => {
      const layers: ComplyLayerResult[] = [
        makeLayerResult({ layer: 1, weight: 20, score: 20 }),
        makeLayerResult({ layer: 2, weight: 18, score: 18, name: 'Consent & Notice' }),
        makeLayerResult({ layer: 3, weight: 15, score: 15, name: 'Data Subject Rights' }),
        makeLayerResult({ layer: 4, weight: 12, score: 12, name: 'Data Minimization & Retention' }),
        makeLayerResult({ layer: 5, weight: 10, score: 10, name: 'Cross-Border Data Transfers' }),
        makeLayerResult({ layer: 6, weight: 10, score: 10, name: 'Data Protection & Encryption' }),
        makeLayerResult({ layer: 7, weight: 8, score: 8, name: 'Third-Party & Vendor Compliance' }),
        makeLayerResult({ layer: 8, weight: 7, score: 7, name: 'Breach & Incident Response' }),
      ];

      const result = computeComplyScore(layers, []);
      expect(result.global).toBe(100);
      expect(result.grade).toBe('S');
      expect(result.cappedBy).toBeUndefined();
    });

    it('should cap score to layer weight', () => {
      const layers: ComplyLayerResult[] = [
        makeLayerResult({ layer: 1, weight: 20, score: 25 }), // Over weight
      ];

      const result = computeComplyScore(layers, []);
      expect(result.layers['1'].score).toBe(20);
    });

    it('should not go below 0', () => {
      const layers: ComplyLayerResult[] = [makeLayerResult({ layer: 1, weight: 20, score: -5 })];

      const result = computeComplyScore(layers, []);
      expect(result.layers['1'].score).toBe(0);
    });
  });

  describe('auto-downgrade rules', () => {
    it('should cap at D (34) when no privacy policy detected', () => {
      const layers = [makeLayerResult({ layer: 2, score: 18, weight: 18 })];
      const findings = [makeFinding({ id: 'CMP-CN-001', severity: 'high', layer: 2 })];

      const result = computeComplyScore(layers, findings);
      expect(result.global).toBeLessThanOrEqual(34);
      expect(result.cappedBy).toBe('No privacy policy file detected');
    });

    it('should cap at C (49) when no data deletion capability', () => {
      const layers = [makeLayerResult({ layer: 3, score: 15, weight: 15 })];
      const findings = [makeFinding({ id: 'CMP-DR-002', severity: 'critical', layer: 3 })];

      const result = computeComplyScore(layers, findings);
      expect(result.global).toBeLessThanOrEqual(49);
    });

    it('should cap at B (69) when third-party tracking without consent', () => {
      const layers = [
        makeLayerResult({ layer: 1, score: 20, weight: 20 }),
        makeLayerResult({ layer: 2, score: 18, weight: 18 }),
      ];
      const findings = [makeFinding({ id: 'CMP-CN-005', severity: 'critical', layer: 2 })];

      const result = computeComplyScore(layers, findings);
      expect(result.global).toBeLessThanOrEqual(69);
    });

    it('should cap at B+ (74) for any critical finding', () => {
      const layers = [
        makeLayerResult({ layer: 1, score: 20, weight: 20 }),
        makeLayerResult({ layer: 2, score: 18, weight: 18 }),
        makeLayerResult({ layer: 3, score: 15, weight: 15 }),
        makeLayerResult({ layer: 4, score: 12, weight: 12 }),
        makeLayerResult({ layer: 5, score: 10, weight: 10 }),
        makeLayerResult({ layer: 6, score: 10, weight: 10 }),
        makeLayerResult({ layer: 7, score: 8, weight: 8 }),
        makeLayerResult({ layer: 8, score: 7, weight: 7 }),
      ];
      const findings = [makeFinding({ id: 'CMP-PD-009', severity: 'critical', layer: 1 })];

      const result = computeComplyScore(layers, findings);
      expect(result.global).toBeLessThanOrEqual(74);
    });
  });
});
