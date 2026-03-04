import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { buildAnalysisContext } from '../../../src/core/analyzers/context-builder.js';
import { createTestDocsAnalyzer } from '../../../src/core/analyzers/testdocs-analyzer.js';

describe('TestDocs Analyzer', () => {
  const tmpDir = join(process.cwd(), '.test-testdocs-analyzer-tmp');

  beforeEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    mkdirSync(join(tmpDir, 'src'), { recursive: true });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should detect low test coverage', async () => {
    // Create source files without matching tests
    for (let i = 0; i < 10; i++) {
      writeFileSync(join(tmpDir, 'src', `module${i}.ts`), `export const val${i} = ${i};\n`);
    }

    const context = await buildAnalysisContext(tmpDir);
    const analyzer = createTestDocsAnalyzer();
    const result = await analyzer.analyze(context);

    const finding = result.findings.find((f) => f.ruleId === 'DOC-001');
    expect(finding).toBeDefined();
  });

  it('should recognize test files matching source files', async () => {
    mkdirSync(join(tmpDir, 'tests'), { recursive: true });

    writeFileSync(join(tmpDir, 'src', 'parser.ts'), 'export function parse() {}\n');
    writeFileSync(join(tmpDir, 'src', 'formatter.ts'), 'export function format() {}\n');
    writeFileSync(
      join(tmpDir, 'tests', 'parser.test.ts'),
      "it('should parse correctly', () => { expect(true).toBe(true); });\n",
    );
    writeFileSync(
      join(tmpDir, 'tests', 'formatter.test.ts'),
      "it('should format correctly', () => { expect(true).toBe(true); });\n",
    );

    const context = await buildAnalysisContext(tmpDir);
    const analyzer = createTestDocsAnalyzer();
    const result = await analyzer.analyze(context);

    // With 100% coverage, DOC-001 should not fire
    const coverageFinding = result.findings.find((f) => f.ruleId === 'DOC-001');
    expect(coverageFinding).toBeUndefined();
  });

  it('should detect missing README', async () => {
    writeFileSync(join(tmpDir, 'src', 'app.ts'), 'export const app = true;\n');

    const context = await buildAnalysisContext(tmpDir);
    const analyzer = createTestDocsAnalyzer();
    const result = await analyzer.analyze(context);

    const finding = result.findings.find((f) => f.ruleId === 'DOC-004');
    expect(finding).toBeDefined();
  });

  it('should not flag README when it exists with good content', async () => {
    writeFileSync(join(tmpDir, 'src', 'app.ts'), 'export const app = true;\n');
    writeFileSync(
      join(tmpDir, 'README.md'),
      '# My Project\n\n## Installation\n\nnpm install\n\n## Usage\n\nRun the app with `npm start`.\n\nMore documentation available in the docs/ directory.\n',
    );

    const context = await buildAnalysisContext(tmpDir);
    const analyzer = createTestDocsAnalyzer();
    const result = await analyzer.analyze(context);

    const finding = result.findings.find(
      (f) => f.ruleId === 'DOC-004' && f.title === 'Missing README.md',
    );
    expect(finding).toBeUndefined();
  });

  it('should detect low JSDoc coverage on exported functions', async () => {
    const code = Array.from(
      { length: 10 },
      (_, i) => `export function fn${i}() { return ${i}; }`,
    ).join('\n');
    writeFileSync(join(tmpDir, 'src', 'functions.ts'), code);

    const context = await buildAnalysisContext(tmpDir);
    const analyzer = createTestDocsAnalyzer();
    const result = await analyzer.analyze(context);

    const finding = result.findings.find((f) => f.ruleId === 'DOC-003');
    expect(finding).toBeDefined();
  });

  it('should return score between 0 and 10', async () => {
    writeFileSync(join(tmpDir, 'src', 'app.ts'), 'export const app = true;\n');

    const context = await buildAnalysisContext(tmpDir);
    const analyzer = createTestDocsAnalyzer();
    const result = await analyzer.analyze(context);

    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(10);
    expect(result.category).toBe('tests');
  });
});
