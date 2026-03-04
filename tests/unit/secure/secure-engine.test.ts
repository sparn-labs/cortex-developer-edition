import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { runSecureAudit } from '../../../src/core/secure/engine.js';

const tmpDir = join(process.cwd(), '.test-secure-engine-tmp');

describe('Secure Engine', () => {
  beforeEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    mkdirSync(join(tmpDir, 'src'), { recursive: true });

    // Create a minimal project
    writeFileSync(
      join(tmpDir, 'package.json'),
      JSON.stringify({
        name: 'test-project',
        version: '1.0.0',
        dependencies: { express: '4.18.0' },
      }),
    );

    writeFileSync(
      join(tmpDir, 'src', 'app.ts'),
      `
import express from 'express';
const app = express();
app.get('/api/users', (req, res) => res.json([]));
app.listen(3000);
      `,
    );
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should return a complete SecureReport structure', async () => {
    const report = await runSecureAudit({ path: tmpDir });

    // Verify report structure
    expect(report.version).toBeDefined();
    expect(report.timestamp).toBeDefined();
    expect(report.project.name).toBe('test-project');
    expect(report.project.path).toBe(tmpDir);
    expect(report.project.stack).toBeDefined();

    // Score
    expect(report.score.global).toBeGreaterThanOrEqual(0);
    expect(report.score.global).toBeLessThanOrEqual(100);
    expect(report.score.grade).toBeDefined();
    expect(Object.keys(report.score.layers).length).toBeGreaterThan(0);

    // Findings
    expect(Array.isArray(report.findings)).toBe(true);

    // Compliance
    expect(report.compliance.framework).toBeDefined();
    expect(report.compliance.items.length).toBeGreaterThan(0);
    expect(report.compliance.passRate).toBeGreaterThanOrEqual(0);

    // Attack surface
    expect(report.attackSurface).toBeDefined();
    expect(typeof report.attackSurface.totalEndpoints).toBe('number');

    // Remediation
    expect(report.remediationRoadmap).toBeDefined();
    expect(report.remediationRoadmap.totalFindings).toBe(report.findings.length);
  });

  it('should respect layer filter', async () => {
    const report = await runSecureAudit({ path: tmpDir, layer: '1,5' });

    const layerNumbers = Object.values(report.score.layers).map((l) => l.layer);
    expect(layerNumbers).toContain(1);
    expect(layerNumbers).toContain(5);
    expect(layerNumbers).not.toContain(2);
    expect(layerNumbers).not.toContain(3);
  });

  it('should run quick mode with only critical layers', async () => {
    const report = await runSecureAudit({ path: tmpDir, quick: true });

    const layerNumbers = Object.values(report.score.layers).map((l) => l.layer);
    // Quick mode: layers 1, 3, 4, 5
    expect(layerNumbers).toContain(1);
    expect(layerNumbers).toContain(3);
    expect(layerNumbers).toContain(4);
    expect(layerNumbers).toContain(5);
    expect(layerNumbers).not.toContain(6);
    expect(layerNumbers).not.toContain(9);
  });

  it('should detect findings in a project with vulnerabilities', async () => {
    // Add a vulnerable file
    writeFileSync(
      join(tmpDir, 'src', 'bad.ts'),
      `
const secret = 'sk-live-1234567890abcdefghijklm';
const hash = createHash('md5').update('test').digest('hex');
const result = eval(userInput);
      `,
    );

    const report = await runSecureAudit({ path: tmpDir });

    // Should find critical issues
    const criticals = report.findings.filter((f) => f.severity === 'critical');
    expect(criticals.length).toBeGreaterThan(0);

    // Should cap grade due to critical findings
    const gradeOrder = ['Zero', 'D', 'C', 'B-', 'B', 'B+', 'A-', 'A', 'A+', 'A++', 'A+++', 'S'];
    const gradeIdx = gradeOrder.indexOf(report.score.grade);
    expect(gradeIdx).toBeLessThanOrEqual(gradeOrder.indexOf('B+'));
  });

  it('should produce all layer scores with correct weights', async () => {
    const report = await runSecureAudit({ path: tmpDir });

    for (const layer of Object.values(report.score.layers)) {
      expect(layer.score).toBeGreaterThanOrEqual(0);
      expect(layer.score).toBeLessThanOrEqual(layer.weight);
      expect(layer.passed).toBeLessThanOrEqual(layer.total);
    }
  });
});
