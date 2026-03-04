import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { buildAnalysisContext } from '../../../src/core/analyzers/context-builder.js';
import { createTokenAnalyzer } from '../../../src/core/analyzers/token-analyzer.js';

describe('Token Analyzer', () => {
  const tmpDir = join(process.cwd(), '.test-token-analyzer-tmp');

  beforeEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    mkdirSync(join(tmpDir, 'src'), { recursive: true });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should detect barrel files', async () => {
    writeFileSync(join(tmpDir, 'src', 'a.ts'), 'export const a = 1;\n');
    writeFileSync(join(tmpDir, 'src', 'b.ts'), 'export const b = 2;\n');
    writeFileSync(join(tmpDir, 'src', 'c.ts'), 'export const c = 3;\n');
    writeFileSync(join(tmpDir, 'src', 'd.ts'), 'export const d = 4;\n');
    writeFileSync(
      join(tmpDir, 'src', 'index.ts'),
      [
        "export { a } from './a.js';",
        "export { b } from './b.js';",
        "export { c } from './c.js';",
        "export { d } from './d.js';",
      ].join('\n'),
    );

    const context = await buildAnalysisContext(tmpDir);
    const analyzer = createTokenAnalyzer();
    const result = await analyzer.analyze(context);

    const finding = result.findings.find((f) => f.ruleId === 'TOK-004');
    expect(finding).toBeDefined();
    expect(finding?.title).toBe('Barrel file');
  });

  it('should detect high token waste ratio with heavy comments', async () => {
    const heavyComments = Array.from(
      { length: 200 },
      (_, i) => `// This is a very detailed comment explaining line ${i} in great detail`,
    ).join('\n');
    const code = 'export const x = 1;\n';
    writeFileSync(join(tmpDir, 'src', 'commented.ts'), `${heavyComments}\n${code}`);

    const context = await buildAnalysisContext(tmpDir);
    const analyzer = createTokenAnalyzer();
    const result = await analyzer.analyze(context);

    const finding = result.findings.find((f) => f.ruleId === 'TOK-001');
    expect(finding).toBeDefined();
  });

  it('should detect duplicate type declarations', async () => {
    // Create 4+ types defined in multiple files (use non-common names to trigger detection)
    for (let i = 0; i < 5; i++) {
      writeFileSync(
        join(tmpDir, 'src', `module${i}.ts`),
        `export interface UserProfile { value: number; }\nexport type TaskStatus = 'ok' | 'error';\nexport type ApiResponse = { data: string };\nexport type QueryParams = { flag: boolean };\nexport const x${i} = ${i};\n`,
      );
    }

    const context = await buildAnalysisContext(tmpDir);
    const analyzer = createTokenAnalyzer();
    const result = await analyzer.analyze(context);

    const finding = result.findings.find((f) => f.ruleId === 'TOK-006');
    expect(finding).toBeDefined();
  });

  it('should return score between 0 and 10', async () => {
    writeFileSync(join(tmpDir, 'src', 'clean.ts'), 'export const clean = true;\n');

    const context = await buildAnalysisContext(tmpDir);
    const analyzer = createTokenAnalyzer();
    const result = await analyzer.analyze(context);

    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(10);
    expect(result.category).toBe('tokens');
  });
});
