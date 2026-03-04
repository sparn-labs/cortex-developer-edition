/**
 * Tests & Documentation Analyzer (10 pts)
 *
 * Checks test coverage estimation, test naming, JSDoc coverage,
 * README quality, CHANGELOG/ADR presence, error testing, XMLDoc.
 */

import { basename } from 'node:path';
import type { AnalysisContext, Analyzer, AnalyzerFinding, CategoryResult } from './types.js';

export function createTestDocsAnalyzer(): Analyzer {
  return {
    category: 'tests',
    name: 'Tests & Documentation',
    maxPoints: 10,

    async analyze(context: AnalysisContext): Promise<CategoryResult> {
      const findings: AnalyzerFinding[] = [];
      let deductions = 0;

      deductions += checkTestCoverage(context, findings);
      deductions += checkTestNaming(context, findings);
      deductions += checkJSDocCoverage(context, findings);
      deductions += checkReadme(context, findings);
      deductions += checkChangelog(context, findings);
      deductions += checkADR(context, findings);
      deductions += checkErrorTesting(context, findings);

      if (context.stackTags.has('dotnet')) {
        deductions += checkXMLDocCoverage(context, findings);
      }

      const score = Math.max(0, 10 - deductions);

      return {
        category: 'tests',
        name: 'Tests & Documentation',
        maxPoints: 10,
        score,
        isNA: false,
        findings,
      };
    },
  };
}

function checkTestCoverage(context: AnalysisContext, findings: AnalyzerFinding[]): number {
  const sourceFiles = new Set<string>();
  const testedFiles = new Set<string>();

  for (const filePath of context.files.keys()) {
    if (
      !filePath.endsWith('.ts') &&
      !filePath.endsWith('.tsx') &&
      !filePath.endsWith('.js') &&
      !filePath.endsWith('.jsx')
    ) {
      continue;
    }

    if (isTestFile(filePath)) {
      // Extract the source file name from test file
      const base = basename(filePath)
        .replace('.test.ts', '.ts')
        .replace('.test.tsx', '.tsx')
        .replace('.test.js', '.js')
        .replace('.test.jsx', '.jsx')
        .replace('.spec.ts', '.ts')
        .replace('.spec.tsx', '.tsx')
        .replace('.spec.js', '.js')
        .replace('.spec.jsx', '.jsx');
      testedFiles.add(base);
    } else {
      // Skip index/config/types files that typically don't need direct tests
      const base = basename(filePath);
      if (base !== 'index.ts' && base !== 'index.js' && !filePath.includes('/types/')) {
        sourceFiles.add(basename(filePath));
      }
    }
  }

  if (sourceFiles.size === 0) return 0;

  const coverage = (testedFiles.size / sourceFiles.size) * 100;
  const threshold = context.config.minTestCoverage;

  if (coverage < threshold) {
    const severity = coverage < 30 ? 'critical' : coverage < 50 ? 'major' : 'minor';
    const deduction = coverage < 30 ? 3 : coverage < 50 ? 2 : 1;

    findings.push({
      ruleId: 'DOC-001',
      title: 'Low test coverage',
      description: `Estimated test coverage: ${coverage.toFixed(0)}% (${testedFiles.size}/${sourceFiles.size} files have matching tests). Threshold: ${threshold}%`,
      severity,
      suggestion: `Add test files for untested modules. Target at least ${threshold}% coverage.`,
      deduction,
      fixable: true,
      fixType: 'add-test',
    });

    return deduction;
  }

  return 0;
}

function checkTestNaming(context: AnalysisContext, findings: AnalyzerFinding[]): number {
  let poorNames = 0;
  let totalTests = 0;

  for (const [filePath, content] of context.files) {
    if (!isTestFile(filePath)) continue;

    const testNames = [...content.matchAll(/(?:it|test)\s*\(\s*['"]([^'"]+)['"]/g)];

    for (const match of testNames) {
      totalTests++;
      const name = match[1] || '';
      // Poor names: too short, generic, or not descriptive
      if (name.length < 10 || /^(?:test|works|should work|it works|basic)$/i.test(name)) {
        poorNames++;
      }
    }
  }

  if (totalTests === 0) return 0;

  const poorRatio = poorNames / totalTests;
  if (poorRatio > 0.3) {
    findings.push({
      ruleId: 'DOC-002',
      title: 'Poor test naming',
      description: `${poorNames}/${totalTests} tests have non-descriptive names`,
      severity: 'minor',
      suggestion: `Use descriptive test names: "should [expected behavior] when [condition]".`,
      deduction: 0.5,
      fixable: true,
      fixType: 'replace-pattern',
    });
    return 0.5;
  }

  return 0;
}

function checkJSDocCoverage(context: AnalysisContext, findings: AnalyzerFinding[]): number {
  let exportedFunctions = 0;
  let documentedFunctions = 0;

  for (const [filePath, content] of context.files) {
    if (!filePath.endsWith('.ts') && !filePath.endsWith('.tsx')) continue;
    if (isTestFile(filePath)) continue;

    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] || '';
      if (/export\s+(?:async\s+)?function\s+\w+/.test(line)) {
        exportedFunctions++;
        // Check if preceded by JSDoc
        let hasJSDoc = false;
        for (let j = i - 1; j >= Math.max(0, i - 5); j--) {
          const prevLine = (lines[j] || '').trim();
          if (prevLine.endsWith('*/')) {
            hasJSDoc = true;
            break;
          }
          if (prevLine && !prevLine.startsWith('*') && !prevLine.startsWith('//')) {
            break;
          }
        }
        if (hasJSDoc) documentedFunctions++;
      }
    }
  }

  if (exportedFunctions === 0) return 0;

  const coverage = (documentedFunctions / exportedFunctions) * 100;

  if (coverage < 50) {
    findings.push({
      ruleId: 'DOC-003',
      title: 'Low JSDoc coverage',
      description: `${documentedFunctions}/${exportedFunctions} exported functions have JSDoc (${coverage.toFixed(0)}%)`,
      severity: 'minor',
      suggestion: `Add JSDoc comments to exported functions for better developer experience.`,
      deduction: 1,
      fixable: true,
      fixType: 'add-docs',
    });
    return 1;
  }

  return 0;
}

function checkReadme(context: AnalysisContext, findings: AnalyzerFinding[]): number {
  const readme = context.files.get('README.md');

  if (!readme) {
    findings.push({
      ruleId: 'DOC-004',
      title: 'Missing README.md',
      description: 'No README.md found at project root',
      severity: 'major',
      suggestion: `Create a README.md with project description, setup instructions, and usage examples.`,
      deduction: 1,
      fixable: true,
      fixType: 'add-docs',
    });
    return 1;
  }

  // Check for key sections
  const sections = ['install', 'usage', 'getting started', 'api', 'setup'];
  const hasSection = sections.some((s) => readme.toLowerCase().includes(s));

  if (!hasSection || readme.length < 200) {
    findings.push({
      ruleId: 'DOC-004',
      title: 'Minimal README.md',
      description: `README.md exists but is ${readme.length < 200 ? 'very short' : 'missing key sections (install/usage)'}`,
      severity: 'minor',
      suggestion: `Expand README with installation, usage, and API documentation.`,
      deduction: 0.5,
      fixable: true,
      fixType: 'add-docs',
    });
    return 0.5;
  }

  return 0;
}

function checkChangelog(context: AnalysisContext, findings: AnalyzerFinding[]): number {
  if (!context.files.has('CHANGELOG.md')) {
    findings.push({
      ruleId: 'DOC-005',
      title: 'Missing CHANGELOG.md',
      description: 'No CHANGELOG.md found — consider documenting version changes',
      severity: 'info',
      suggestion: `Create a CHANGELOG.md following Keep a Changelog format.`,
      deduction: 0.5,
      fixable: true,
      fixType: 'add-docs',
    });
    return 0.5;
  }
  return 0;
}

function checkADR(context: AnalysisContext, findings: AnalyzerFinding[]): number {
  const hasADR = [...context.files.keys()].some(
    (f) => f.includes('adr/') || f.includes('ADR/') || f.includes('decisions/'),
  );

  if (!hasADR) {
    findings.push({
      ruleId: 'DOC-006',
      title: 'No Architecture Decision Records',
      description: 'No ADR directory found — architectural decisions are undocumented',
      severity: 'info',
      suggestion: `Create an adr/ directory with architecture decision records.`,
      deduction: 0.5,
      fixable: true,
      fixType: 'add-docs',
    });
    return 0.5;
  }
  return 0;
}

function checkErrorTesting(context: AnalysisContext, findings: AnalyzerFinding[]): number {
  let totalTestFiles = 0;
  let filesWithErrorTests = 0;

  for (const [filePath, content] of context.files) {
    if (!isTestFile(filePath)) continue;
    totalTestFiles++;

    if (
      /\.toThrow/g.test(content) ||
      /\.rejects/g.test(content) ||
      /expect\(.*error/gi.test(content) ||
      /catch\s*\(/g.test(content)
    ) {
      filesWithErrorTests++;
    }
  }

  if (totalTestFiles === 0) return 0;

  const ratio = filesWithErrorTests / totalTestFiles;
  if (ratio < 0.3) {
    findings.push({
      ruleId: 'DOC-007',
      title: 'Low error case testing',
      description: `Only ${filesWithErrorTests}/${totalTestFiles} test files include error/exception assertions`,
      severity: 'minor',
      suggestion: `Add error case tests to verify behavior with invalid inputs and edge cases.`,
      deduction: 0.5,
      fixable: true,
      fixType: 'add-test',
    });
    return 0.5;
  }

  return 0;
}

function checkXMLDocCoverage(context: AnalysisContext, findings: AnalyzerFinding[]): number {
  let publicMethods = 0;
  let documentedMethods = 0;

  for (const [filePath, content] of context.files) {
    if (!filePath.endsWith('.cs')) continue;

    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] || '';
      if (/public\s+(?:async\s+)?(?:\w+\s+)+\w+\s*\(/.test(line)) {
        publicMethods++;
        // Check for /// summary above
        for (let j = i - 1; j >= Math.max(0, i - 5); j--) {
          const prev = (lines[j] || '').trim();
          if (prev.startsWith('/// <summary>') || prev.startsWith('///')) {
            documentedMethods++;
            break;
          }
          if (prev && !prev.startsWith('///') && !prev.startsWith('[')) {
            break;
          }
        }
      }
    }
  }

  if (publicMethods === 0) return 0;

  const coverage = (documentedMethods / publicMethods) * 100;
  if (coverage < 50) {
    findings.push({
      ruleId: 'DOC-008',
      title: 'Low XMLDoc coverage',
      description: `${documentedMethods}/${publicMethods} public methods have XMLDoc comments (${coverage.toFixed(0)}%)`,
      severity: 'minor',
      suggestion: `Add /// summary comments to public methods for IntelliSense support.`,
      deduction: 0.5,
      fixable: true,
      fixType: 'add-docs',
    });
    return 0.5;
  }

  return 0;
}

function isTestFile(path: string): boolean {
  return (
    path.includes('.test.') ||
    path.includes('.spec.') ||
    path.includes('__tests__') ||
    path.includes('/tests/')
  );
}
