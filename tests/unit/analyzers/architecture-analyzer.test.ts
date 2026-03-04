import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createArchitectureAnalyzer } from '../../../src/core/analyzers/architecture-analyzer.js';
import { buildAnalysisContext } from '../../../src/core/analyzers/context-builder.js';

describe('Architecture Analyzer', () => {
  const tmpDir = join(process.cwd(), '.test-arch-analyzer-tmp');

  beforeEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    mkdirSync(join(tmpDir, 'src'), { recursive: true });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should detect dependency cycles', async () => {
    writeFileSync(
      join(tmpDir, 'src', 'a.ts'),
      "import { b } from './b.js';\nexport const a = 1;\n",
    );
    writeFileSync(
      join(tmpDir, 'src', 'b.ts'),
      "import { a } from './a.js';\nexport const b = 2;\n",
    );

    const context = await buildAnalysisContext(tmpDir);
    const analyzer = createArchitectureAnalyzer();
    const result = await analyzer.analyze(context);

    const cycleFinding = result.findings.find((f) => f.ruleId === 'ARCH-004');
    expect(cycleFinding).toBeDefined();
    expect(cycleFinding?.severity).toBe('critical');
  });

  it('should detect high afferent coupling', async () => {
    // Create a file imported by many others
    writeFileSync(join(tmpDir, 'src', 'shared.ts'), 'export const shared = 1;\n');

    for (let i = 0; i < 20; i++) {
      writeFileSync(
        join(tmpDir, 'src', `file${i}.ts`),
        `import { shared } from './shared.js';\nexport const val${i} = shared;\n`,
      );
    }

    const context = await buildAnalysisContext(tmpDir);
    const analyzer = createArchitectureAnalyzer();
    const result = await analyzer.analyze(context);

    const couplingFinding = result.findings.find((f) => f.ruleId === 'ARCH-001');
    expect(couplingFinding).toBeDefined();
    expect(couplingFinding?.severity).toBe('major');
  });

  it('should detect god files', async () => {
    // Create a large file with many exports and imports
    const imports = Array.from(
      { length: 16 },
      (_, i) => `import { val${i} } from './dep${i}.js';`,
    ).join('\n');
    const exports = Array.from({ length: 22 }, (_, i) => `export const fn${i} = () => ${i};`).join(
      '\n',
    );
    const padding = Array.from({ length: 500 }, (_, i) => `// line ${i}`).join('\n');

    writeFileSync(join(tmpDir, 'src', 'god.ts'), `${imports}\n${exports}\n${padding}\n`);

    // Create the dependency files
    for (let i = 0; i < 16; i++) {
      writeFileSync(join(tmpDir, 'src', `dep${i}.ts`), `export const val${i} = ${i};\n`);
    }

    const context = await buildAnalysisContext(tmpDir);
    const analyzer = createArchitectureAnalyzer();
    const result = await analyzer.analyze(context);

    const godFinding = result.findings.find((f) => f.ruleId === 'ARCH-007');
    expect(godFinding).toBeDefined();
    expect(godFinding?.severity).toBe('major');
  });

  it('should detect orphaned files', async () => {
    writeFileSync(join(tmpDir, 'src', 'orphan.ts'), 'const lonely = 42;\n');

    const context = await buildAnalysisContext(tmpDir);
    const analyzer = createArchitectureAnalyzer();
    const result = await analyzer.analyze(context);

    const orphanFinding = result.findings.find((f) => f.ruleId === 'ARCH-009');
    expect(orphanFinding).toBeDefined();
  });

  it('should return score between 0 and 25', async () => {
    writeFileSync(join(tmpDir, 'src', 'clean.ts'), 'export const hello = "world";\n');

    const context = await buildAnalysisContext(tmpDir);
    const analyzer = createArchitectureAnalyzer();
    const result = await analyzer.analyze(context);

    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(25);
    expect(result.category).toBe('architecture');
    expect(result.isNA).toBe(false);
  });
});
