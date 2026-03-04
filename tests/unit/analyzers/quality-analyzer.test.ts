import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { buildAnalysisContext } from '../../../src/core/analyzers/context-builder.js';
import { createQualityAnalyzer } from '../../../src/core/analyzers/quality-analyzer.js';

describe('Quality Analyzer', () => {
  const tmpDir = join(process.cwd(), '.test-quality-analyzer-tmp');

  beforeEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    mkdirSync(join(tmpDir, 'src'), { recursive: true });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should detect high cyclomatic complexity', async () => {
    const complexFunction = `
export function complexFn(a: number, b: number, c: number) {
  if (a > 0) {
    if (b > 0) {
      if (c > 0) {
        for (let i = 0; i < a; i++) {
          while (b > 0) {
            if (a && b || c) {
              switch (a) {
                case 1: break;
                case 2: break;
                case 3: break;
                case 4: break;
                case 5: break;
                case 6: break;
                case 7: break;
                case 8: break;
                case 9: break;
                case 10: break;
              }
            }
          }
        }
      }
    }
  }
  return a ?? b ?? c;
}
`;
    writeFileSync(join(tmpDir, 'src', 'complex.ts'), complexFunction);

    const context = await buildAnalysisContext(tmpDir);
    const analyzer = createQualityAnalyzer();
    const result = await analyzer.analyze(context);

    const finding = result.findings.find((f) => f.ruleId === 'QUAL-001');
    expect(finding).toBeDefined();
  });

  it('should detect TypeScript anti-patterns', async () => {
    const antiPatterns = `
const x = someValue as any;
// @ts-ignore
const y = 42;
const z = foo!.bar;
`;
    writeFileSync(join(tmpDir, 'src', 'bad.ts'), antiPatterns);

    const context = await buildAnalysisContext(tmpDir);
    const analyzer = createQualityAnalyzer();
    const result = await analyzer.analyze(context);

    const tsFindings = result.findings.filter((f) => f.ruleId === 'QUAL-004');
    expect(tsFindings.length).toBeGreaterThan(0);
  });

  it('should detect long files', async () => {
    const longContent = Array.from({ length: 600 }, (_, i) => `const line${i} = ${i};`).join('\n');
    writeFileSync(join(tmpDir, 'src', 'long.ts'), longContent);

    const context = await buildAnalysisContext(tmpDir);
    const analyzer = createQualityAnalyzer();
    const result = await analyzer.analyze(context);

    const finding = result.findings.find((f) => f.ruleId === 'QUAL-003');
    expect(finding).toBeDefined();
  });

  it('should skip debug statement warnings in test files', async () => {
    mkdirSync(join(tmpDir, 'tests'), { recursive: true });
    writeFileSync(
      join(tmpDir, 'tests', 'foo.test.ts'),
      'console.log("test debug");\nconsole.log("another");\nconsole.log("third");\nconsole.log("fourth");\n',
    );

    const context = await buildAnalysisContext(tmpDir);
    const analyzer = createQualityAnalyzer();
    const result = await analyzer.analyze(context);

    const debugFinding = result.findings.find(
      (f) => f.ruleId === 'QUAL-009' && f.filePath?.includes('test'),
    );
    expect(debugFinding).toBeUndefined();
  });

  it('should return score between 0 and 20', async () => {
    writeFileSync(join(tmpDir, 'src', 'clean.ts'), 'export const clean = true;\n');

    const context = await buildAnalysisContext(tmpDir);
    const analyzer = createQualityAnalyzer();
    const result = await analyzer.analyze(context);

    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(20);
    expect(result.category).toBe('quality');
  });
});
