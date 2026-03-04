import { describe, expect, it } from 'vitest';
import { computeScore, mapGrade } from '../../../src/core/analyzers/scoring.js';
import type { CategoryResult } from '../../../src/core/analyzers/types.js';

describe('Scoring', () => {
  describe('mapGrade', () => {
    it('should map 95-100 to S', () => {
      expect(mapGrade(100)).toBe('S');
      expect(mapGrade(95)).toBe('S');
    });

    it('should map 90-94 to A+++', () => {
      expect(mapGrade(94)).toBe('A+++');
      expect(mapGrade(90)).toBe('A+++');
    });

    it('should map 85-89 to A++', () => {
      expect(mapGrade(89)).toBe('A++');
      expect(mapGrade(85)).toBe('A++');
    });

    it('should map 80-84 to A+', () => {
      expect(mapGrade(84)).toBe('A+');
      expect(mapGrade(80)).toBe('A+');
    });

    it('should map 75-79 to A', () => {
      expect(mapGrade(79)).toBe('A');
      expect(mapGrade(75)).toBe('A');
    });

    it('should map 65-74 to B', () => {
      expect(mapGrade(74)).toBe('B');
      expect(mapGrade(65)).toBe('B');
    });

    it('should map 55-64 to B-', () => {
      expect(mapGrade(64)).toBe('B-');
      expect(mapGrade(55)).toBe('B-');
    });

    it('should map 40-54 to C', () => {
      expect(mapGrade(54)).toBe('C');
      expect(mapGrade(40)).toBe('C');
    });

    it('should map 20-39 to D', () => {
      expect(mapGrade(39)).toBe('D');
      expect(mapGrade(20)).toBe('D');
    });

    it('should map 0-19 to Zero', () => {
      expect(mapGrade(19)).toBe('Zero');
      expect(mapGrade(0)).toBe('Zero');
    });
  });

  describe('computeScore', () => {
    it('should compute perfect score when all categories are maxed', () => {
      const results: CategoryResult[] = [
        {
          category: 'architecture',
          name: 'Architecture',
          maxPoints: 25,
          score: 25,
          isNA: false,
          findings: [],
        },
        {
          category: 'quality',
          name: 'Code Quality',
          maxPoints: 20,
          score: 20,
          isNA: false,
          findings: [],
        },
        {
          category: 'database',
          name: 'Database',
          maxPoints: 20,
          score: 20,
          isNA: false,
          findings: [],
        },
        {
          category: 'security',
          name: 'Security',
          maxPoints: 15,
          score: 15,
          isNA: false,
          findings: [],
        },
        {
          category: 'tokens',
          name: 'Token Efficiency',
          maxPoints: 10,
          score: 10,
          isNA: false,
          findings: [],
        },
        {
          category: 'tests',
          name: 'Tests & Docs',
          maxPoints: 10,
          score: 10,
          isNA: false,
          findings: [],
        },
      ];

      const result = computeScore(results);
      expect(result.totalScore).toBe(100);
      expect(result.grade).toBe('S');
    });

    it('should compute zero score when all categories are at 0', () => {
      const results: CategoryResult[] = [
        {
          category: 'architecture',
          name: 'Architecture',
          maxPoints: 25,
          score: 0,
          isNA: false,
          findings: [],
        },
        {
          category: 'quality',
          name: 'Code Quality',
          maxPoints: 20,
          score: 0,
          isNA: false,
          findings: [],
        },
        {
          category: 'database',
          name: 'Database',
          maxPoints: 20,
          score: 0,
          isNA: false,
          findings: [],
        },
        {
          category: 'security',
          name: 'Security',
          maxPoints: 15,
          score: 0,
          isNA: false,
          findings: [],
        },
        {
          category: 'tokens',
          name: 'Token Efficiency',
          maxPoints: 10,
          score: 0,
          isNA: false,
          findings: [],
        },
        {
          category: 'tests',
          name: 'Tests & Docs',
          maxPoints: 10,
          score: 0,
          isNA: false,
          findings: [],
        },
      ];

      const result = computeScore(results);
      expect(result.totalScore).toBe(0);
      expect(result.grade).toBe('Zero');
    });

    it('should redistribute weight when a category is N/A', () => {
      const results: CategoryResult[] = [
        {
          category: 'architecture',
          name: 'Architecture',
          maxPoints: 25,
          score: 25,
          isNA: false,
          findings: [],
        },
        {
          category: 'quality',
          name: 'Code Quality',
          maxPoints: 20,
          score: 20,
          isNA: false,
          findings: [],
        },
        {
          category: 'database',
          name: 'Database',
          maxPoints: 20,
          score: 0,
          isNA: true,
          findings: [],
        },
        {
          category: 'security',
          name: 'Security',
          maxPoints: 15,
          score: 15,
          isNA: false,
          findings: [],
        },
        {
          category: 'tokens',
          name: 'Token Efficiency',
          maxPoints: 10,
          score: 10,
          isNA: false,
          findings: [],
        },
        {
          category: 'tests',
          name: 'Tests & Docs',
          maxPoints: 10,
          score: 10,
          isNA: false,
          findings: [],
        },
      ];

      const result = computeScore(results);
      // With database (20pts) N/A, remaining 80 points scaled to 100
      // All remaining categories at max = 100
      expect(result.totalScore).toBe(100);
      expect(result.grade).toBe('S');
      expect(result.categories['database']?.isNA).toBe(true);
    });

    it('should scale partial scores with N/A redistribution', () => {
      const results: CategoryResult[] = [
        {
          category: 'architecture',
          name: 'Architecture',
          maxPoints: 25,
          score: 12.5,
          isNA: false,
          findings: [],
        },
        {
          category: 'quality',
          name: 'Code Quality',
          maxPoints: 20,
          score: 10,
          isNA: false,
          findings: [],
        },
        {
          category: 'database',
          name: 'Database',
          maxPoints: 20,
          score: 0,
          isNA: true,
          findings: [],
        },
        {
          category: 'security',
          name: 'Security',
          maxPoints: 15,
          score: 7.5,
          isNA: false,
          findings: [],
        },
        {
          category: 'tokens',
          name: 'Token Efficiency',
          maxPoints: 10,
          score: 5,
          isNA: false,
          findings: [],
        },
        {
          category: 'tests',
          name: 'Tests & Docs',
          maxPoints: 10,
          score: 5,
          isNA: false,
          findings: [],
        },
      ];

      const result = computeScore(results);
      // 50% of each category = 50 total
      expect(result.totalScore).toBe(50);
      expect(result.grade).toBe('C');
    });

    it('should handle all categories as N/A', () => {
      const results: CategoryResult[] = [
        {
          category: 'architecture',
          name: 'Architecture',
          maxPoints: 25,
          score: 0,
          isNA: true,
          findings: [],
        },
        {
          category: 'quality',
          name: 'Code Quality',
          maxPoints: 20,
          score: 0,
          isNA: true,
          findings: [],
        },
      ];

      const result = computeScore(results);
      expect(result.totalScore).toBe(0);
      expect(result.grade).toBe('Zero');
    });
  });
});
