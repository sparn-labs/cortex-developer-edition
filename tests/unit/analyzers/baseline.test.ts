import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  diffFindings,
  fingerprint,
  loadBaseline,
  saveBaseline,
} from '../../../src/core/analyzers/baseline.js';
import type { AnalysisReport, AnalyzerFinding } from '../../../src/core/analyzers/types.js';

describe('Baseline', () => {
  const tmpDir = join(process.cwd(), '.test-baseline-tmp');

  beforeEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    mkdirSync(join(tmpDir, '.cortex'), { recursive: true });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('fingerprint', () => {
    it('should produce stable fingerprints', () => {
      const fp1 = fingerprint({
        ruleId: 'QUAL-001',
        filePath: 'src/a.ts',
        title: 'High complexity',
      });
      const fp2 = fingerprint({
        ruleId: 'QUAL-001',
        filePath: 'src/a.ts',
        title: 'High complexity',
      });
      expect(fp1).toBe(fp2);
    });

    it('should produce different fingerprints for different findings', () => {
      const fp1 = fingerprint({
        ruleId: 'QUAL-001',
        filePath: 'src/a.ts',
        title: 'High complexity',
      });
      const fp2 = fingerprint({ ruleId: 'QUAL-002', filePath: 'src/a.ts', title: 'Long function' });
      expect(fp1).not.toBe(fp2);
    });

    it('should handle undefined filePath', () => {
      const fp = fingerprint({ ruleId: 'DOC-001', title: 'Low test coverage' });
      expect(fp).toBeTruthy();
      expect(fp.length).toBe(16);
    });
  });

  describe('saveBaseline / loadBaseline', () => {
    it('should save and load baseline', () => {
      const report = makeReport([
        makeFinding('QUAL-001', 'src/a.ts', 'High complexity'),
        makeFinding('ARCH-004', 'src/b.ts', 'Dependency cycle'),
      ]);

      saveBaseline(tmpDir, report);

      const loaded = loadBaseline(tmpDir);
      expect(loaded).not.toBeNull();
      expect(loaded?.findings).toHaveLength(2);
      expect(loaded?.score).toBe(85);
      expect(loaded?.grade).toBe('A+');
    });

    it('should return null for corrupted JSON', () => {
      writeFileSync(join(tmpDir, '.cortex', 'analyze-baseline.json'), '{invalid json!!!', 'utf-8');
      const loaded = loadBaseline(tmpDir);
      expect(loaded).toBeNull();
    });

    it('should return null when no baseline exists', () => {
      const loaded = loadBaseline(tmpDir);
      expect(loaded).toBeNull();
    });

    it('should create .cortex directory if needed', () => {
      rmSync(join(tmpDir, '.cortex'), { recursive: true, force: true });
      const report = makeReport([makeFinding('QUAL-001', 'src/a.ts', 'Test')]);
      saveBaseline(tmpDir, report);

      const loaded = loadBaseline(tmpDir);
      expect(loaded).not.toBeNull();
    });
  });

  describe('diffFindings', () => {
    it('should detect new findings', () => {
      const baseline = [
        {
          ruleId: 'QUAL-001',
          filePath: 'src/a.ts',
          severity: 'major',
          title: 'Old',
          fingerprint: fingerprint({ ruleId: 'QUAL-001', filePath: 'src/a.ts', title: 'Old' }),
        },
      ];
      const current: AnalyzerFinding[] = [
        makeFinding('QUAL-001', 'src/a.ts', 'Old'),
        makeFinding('QUAL-002', 'src/b.ts', 'New'),
      ];

      const diff = diffFindings(current, baseline);
      expect(diff.newFindings).toHaveLength(1);
      expect(diff.newFindings[0]?.ruleId).toBe('QUAL-002');
      expect(diff.unchanged).toHaveLength(1);
      expect(diff.fixedFindings).toHaveLength(0);
    });

    it('should detect fixed findings', () => {
      const baseline = [
        {
          ruleId: 'QUAL-001',
          filePath: 'src/a.ts',
          severity: 'major',
          title: 'Fixed',
          fingerprint: fingerprint({ ruleId: 'QUAL-001', filePath: 'src/a.ts', title: 'Fixed' }),
        },
        {
          ruleId: 'QUAL-002',
          filePath: 'src/b.ts',
          severity: 'minor',
          title: 'Still here',
          fingerprint: fingerprint({
            ruleId: 'QUAL-002',
            filePath: 'src/b.ts',
            title: 'Still here',
          }),
        },
      ];
      const current: AnalyzerFinding[] = [makeFinding('QUAL-002', 'src/b.ts', 'Still here')];

      const diff = diffFindings(current, baseline);
      expect(diff.fixedFindings).toHaveLength(1);
      expect(diff.fixedFindings[0]?.ruleId).toBe('QUAL-001');
      expect(diff.unchanged).toHaveLength(1);
      expect(diff.newFindings).toHaveLength(0);
    });

    it('should handle empty baseline', () => {
      const current: AnalyzerFinding[] = [makeFinding('QUAL-001', 'src/a.ts', 'New')];

      const diff = diffFindings(current, []);
      expect(diff.newFindings).toHaveLength(1);
      expect(diff.fixedFindings).toHaveLength(0);
    });

    it('should handle empty current findings', () => {
      const baseline = [
        {
          ruleId: 'QUAL-001',
          filePath: 'src/a.ts',
          severity: 'major',
          title: 'Gone',
          fingerprint: fingerprint({ ruleId: 'QUAL-001', filePath: 'src/a.ts', title: 'Gone' }),
        },
      ];

      const diff = diffFindings([], baseline);
      expect(diff.fixedFindings).toHaveLength(1);
      expect(diff.newFindings).toHaveLength(0);
    });
  });
});

function makeFinding(ruleId: string, filePath: string, title: string): AnalyzerFinding {
  return {
    ruleId,
    title,
    description: `Test finding: ${title}`,
    severity: 'major',
    filePath,
    deduction: 1,
    suggestion: 'Fix it',
  };
}

function makeReport(findings: AnalyzerFinding[]): AnalysisReport {
  return {
    version: '2.0',
    timestamp: new Date().toISOString(),
    project: { name: 'test', path: '/test', stack: ['typescript'] },
    score: { totalScore: 85, grade: 'A+', categories: {} },
    categoryResults: [
      {
        category: 'quality',
        name: 'Quality',
        maxPoints: 20,
        score: 17,
        isNA: false,
        findings,
      },
    ],
    metrics: {
      totalFiles: 10,
      totalTokens: 5000,
      entryPoints: 1,
      hotPaths: 2,
      orphanedFiles: 0,
    },
    actionPlan: { quickWins: [], structural: findings, backlog: [] },
  };
}
