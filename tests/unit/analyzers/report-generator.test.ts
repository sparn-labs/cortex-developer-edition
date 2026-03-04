import { describe, expect, it } from 'vitest';
import {
  buildActionPlanItems,
  buildReport,
  generateJSONReport,
  generateMarkdownReport,
} from '../../../src/core/analyzers/report-generator.js';
import type {
  AnalysisReport,
  CategoryResult,
  ScoreResult,
} from '../../../src/core/analyzers/types.js';

function createTestReport(): AnalysisReport {
  const categoryResults: CategoryResult[] = [
    {
      category: 'architecture',
      name: 'Architecture',
      maxPoints: 25,
      score: 20,
      isNA: false,
      findings: [
        {
          ruleId: 'ARCH-001',
          title: 'High coupling',
          description: 'File has too many callers',
          severity: 'major',
          filePath: 'src/core/utils.ts',
          deduction: 1,
          suggestion: 'Split the module',
        },
      ],
    },
    {
      category: 'quality',
      name: 'Code Quality',
      maxPoints: 20,
      score: 18,
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
  ];

  const score: ScoreResult = {
    totalScore: 85,
    grade: 'A++',
    categories: {
      architecture: { score: 20, maxPoints: 25, scaledScore: 30, scaledMax: 37.5, isNA: false },
      quality: { score: 18, maxPoints: 20, scaledScore: 27, scaledMax: 30, isNA: false },
      database: { score: 0, maxPoints: 20, scaledScore: 0, scaledMax: 0, isNA: true },
    },
  };

  return buildReport(
    score,
    categoryResults,
    'test-project',
    '/home/test/project',
    ['typescript'],
    50,
    10000,
    3,
    5,
    2,
    '2.0',
  );
}

describe('Report Generator', () => {
  describe('generateMarkdownReport', () => {
    it('should generate valid Markdown with all sections', () => {
      const report = createTestReport();
      const md = generateMarkdownReport(report);

      expect(md).toContain('# Cortex Analysis Report');
      expect(md).toContain('**Project**: test-project');
      expect(md).toContain('**Stack**: typescript');
      expect(md).toContain('## Score');
      expect(md).toContain('85/100');
      expect(md).toContain('A++');
      expect(md).toContain('## Findings');
      expect(md).toContain('ARCH-001');
      expect(md).toContain('## Metrics');
      expect(md).toContain('## Action Plan');
      expect(md).toContain('N/A');
    });

    it('should show all findings in verbose mode', () => {
      const report = createTestReport();
      const md = generateMarkdownReport(report, true);
      expect(md).toContain('ARCH-001');
    });

    it('should include category breakdown table', () => {
      const report = createTestReport();
      const md = generateMarkdownReport(report);

      expect(md).toContain('| Category | Score | Max | Scaled | Grade |');
      expect(md).toContain('Architecture');
      expect(md).toContain('Database');
    });
  });

  describe('generateJSONReport', () => {
    it('should generate valid JSON matching schema', () => {
      const report = createTestReport();
      const jsonStr = generateJSONReport(report);
      const parsed = JSON.parse(jsonStr);

      expect(parsed.cortex_analyze).toBeDefined();
      expect(parsed.cortex_analyze.version).toBe('2.0');
      expect(parsed.cortex_analyze.score.global).toBe(85);
      expect(parsed.cortex_analyze.score.grade).toBe('A++');
      expect(parsed.cortex_analyze.project.name).toBe('test-project');
      expect(parsed.cortex_analyze.project.stack).toContain('typescript');
      expect(parsed.cortex_analyze.issues).toBeInstanceOf(Array);
      expect(parsed.cortex_analyze.metrics.totalFiles).toBe(50);
      expect(parsed.cortex_analyze.action_plan).toBeDefined();
    });

    it('should include all issues from all categories', () => {
      const report = createTestReport();
      const parsed = JSON.parse(generateJSONReport(report));

      expect(parsed.cortex_analyze.issues.length).toBe(1);
      expect(parsed.cortex_analyze.issues[0].id).toBe('ARCH-001');
    });

    it('should classify action plan items by severity', () => {
      const report = createTestReport();
      const parsed = JSON.parse(generateJSONReport(report));

      // ARCH-001 is major, should be in structural
      expect(parsed.cortex_analyze.action_plan.structural.length).toBe(1);
    });
  });

  describe('buildReport', () => {
    it('should populate all report fields', () => {
      const report = createTestReport();

      expect(report.version).toBe('2.0');
      expect(report.timestamp).toBeDefined();
      expect(report.project.name).toBe('test-project');
      expect(report.categoryResults).toHaveLength(3);
      expect(report.metrics.totalFiles).toBe(50);
      expect(report.actionPlan).toBeDefined();
    });
  });

  describe('JSON fixable/fixType fields', () => {
    it('should include fixable and fixType in issue output', () => {
      const report = createTestReportWithFixable();
      const parsed = JSON.parse(generateJSONReport(report));

      const issue = parsed.cortex_analyze.issues[0];
      expect(issue.fixable).toBe(true);
      expect(issue.fixType).toBe('extract-function');
    });

    it('should default fixable to false and fixType to null when absent', () => {
      const report = createTestReport();
      const parsed = JSON.parse(generateJSONReport(report));

      const issue = parsed.cortex_analyze.issues[0];
      expect(issue.fixable).toBe(false);
      expect(issue.fixType).toBeNull();
    });

    it('should include action_plan.items array with enriched data', () => {
      const report = createTestReportWithFixable();
      const parsed = JSON.parse(generateJSONReport(report));

      expect(parsed.cortex_analyze.action_plan.items).toBeInstanceOf(Array);
      expect(parsed.cortex_analyze.action_plan.items.length).toBeGreaterThan(0);

      const item = parsed.cortex_analyze.action_plan.items[0];
      expect(item.effort).toBeDefined();
      expect(item.pointsRecoverable).toBeDefined();
      expect(item.fixable).toBe(true);
      expect(item.fixType).toBe('extract-function');
    });

    it('should include fixable/fixType in summarized findings', () => {
      const report = createTestReportWithFixable();
      const parsed = JSON.parse(generateJSONReport(report));

      const structural = parsed.cortex_analyze.action_plan.structural[0];
      expect(structural.fixable).toBe(true);
      expect(structural.fixType).toBe('extract-function');
    });
  });

  describe('buildActionPlanItems', () => {
    it('should compute effort from fixType', () => {
      const results: CategoryResult[] = [
        {
          category: 'quality',
          name: 'Quality',
          maxPoints: 20,
          score: 18,
          isNA: false,
          findings: [
            {
              ruleId: 'QUAL-009',
              title: 'Debug statements',
              description: 'Remove console.log',
              severity: 'minor',
              deduction: 0.5,
              fixable: true,
              fixType: 'remove-code',
            },
            {
              ruleId: 'ARCH-004',
              title: 'Dependency cycle',
              description: 'Circular dep',
              severity: 'critical',
              deduction: 1,
              fixable: false,
              fixType: 'refactor',
            },
          ],
        },
      ];

      const items = buildActionPlanItems(results);
      expect(items).toHaveLength(2);

      const removeItem = items.find((i) => i.ruleId === 'QUAL-009');
      expect(removeItem?.effort).toBe('low');
      expect(removeItem?.fixable).toBe(true);
      expect(removeItem?.pointsRecoverable).toBe(0.5);

      const refactorItem = items.find((i) => i.ruleId === 'ARCH-004');
      expect(refactorItem?.effort).toBe('high');
      expect(refactorItem?.fixable).toBe(false);
    });
  });
});

function createTestReportWithFixable(): AnalysisReport {
  const categoryResults: CategoryResult[] = [
    {
      category: 'quality',
      name: 'Code Quality',
      maxPoints: 20,
      score: 15,
      isNA: false,
      findings: [
        {
          ruleId: 'QUAL-001',
          title: 'High complexity',
          description: 'Cyclomatic complexity too high',
          severity: 'major',
          filePath: 'src/core/complex.ts',
          deduction: 2,
          suggestion: 'Extract functions',
          fixable: true,
          fixType: 'extract-function',
        },
      ],
    },
  ];

  const score: ScoreResult = {
    totalScore: 80,
    grade: 'A',
    categories: {
      quality: { score: 15, maxPoints: 20, scaledScore: 75, scaledMax: 100, isNA: false },
    },
  };

  return buildReport(
    score,
    categoryResults,
    'test-project',
    '/home/test/project',
    ['typescript'],
    30,
    8000,
    2,
    3,
    1,
    '2.0',
  );
}
