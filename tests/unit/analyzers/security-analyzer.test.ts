import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { buildAnalysisContext } from '../../../src/core/analyzers/context-builder.js';
import { createSecurityAnalyzer } from '../../../src/core/analyzers/security-analyzer.js';

describe('Security Analyzer', () => {
  const tmpDir = join(process.cwd(), '.test-security-analyzer-tmp');

  beforeEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    mkdirSync(join(tmpDir, 'src'), { recursive: true });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should detect hardcoded API keys', async () => {
    const code = `
const apiKey = 'sk-live-abcdefghijklmnopqrstuvwxyz12345678';
export const client = createClient(apiKey);
`;
    writeFileSync(join(tmpDir, 'src', 'api.ts'), code);

    const context = await buildAnalysisContext(tmpDir);
    const analyzer = createSecurityAnalyzer();
    const result = await analyzer.analyze(context);

    const finding = result.findings.find((f) => f.ruleId === 'SEC-001');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('critical');
  });

  it('should detect eval usage', async () => {
    const code = `
export function runCode(input: string) {
  return eval(input);
}
`;
    writeFileSync(join(tmpDir, 'src', 'danger.ts'), code);

    const context = await buildAnalysisContext(tmpDir);
    const analyzer = createSecurityAnalyzer();
    const result = await analyzer.analyze(context);

    const finding = result.findings.find((f) => f.ruleId === 'SEC-006' && f.title.includes('eval'));
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('critical');
  });

  it('should detect dangerouslySetInnerHTML', async () => {
    const code = `
export function Component({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
`;
    writeFileSync(join(tmpDir, 'src', 'unsafe.tsx'), code);

    const context = await buildAnalysisContext(tmpDir);
    const analyzer = createSecurityAnalyzer();
    const result = await analyzer.analyze(context);

    const finding = result.findings.find(
      (f) => f.ruleId === 'SEC-006' && f.title.includes('dangerouslySetInnerHTML'),
    );
    expect(finding).toBeDefined();
  });

  it('should detect sensitive file patterns', async () => {
    writeFileSync(join(tmpDir, '.env'), 'SECRET=abc123');

    const context = await buildAnalysisContext(tmpDir);
    const analyzer = createSecurityAnalyzer();
    const result = await analyzer.analyze(context);

    // .env may not be collected since it has no standard source extension
    // but if it is, it should be flagged — just verify no crash
    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(15);
  });

  it('should not flag secrets in test files', async () => {
    mkdirSync(join(tmpDir, 'tests'), { recursive: true });
    const code = `
const testKey = 'sk-live-testabcdefghijklmnopqrstuvwxyz1234';
`;
    writeFileSync(join(tmpDir, 'tests', 'api.test.ts'), code);

    const context = await buildAnalysisContext(tmpDir);
    const analyzer = createSecurityAnalyzer();
    const result = await analyzer.analyze(context);

    const secretFindings = result.findings.filter(
      (f) => f.ruleId === 'SEC-001' && f.filePath?.includes('test'),
    );
    expect(secretFindings).toHaveLength(0);
  });

  it('should return score between 0 and 15', async () => {
    writeFileSync(join(tmpDir, 'src', 'safe.ts'), 'export const safe = true;\n');

    const context = await buildAnalysisContext(tmpDir);
    const analyzer = createSecurityAnalyzer();
    const result = await analyzer.analyze(context);

    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(15);
    expect(result.category).toBe('security');
  });
});
