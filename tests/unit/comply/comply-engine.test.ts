/**
 * Comply Engine Tests — full audit on synthetic project, report structure validation
 */

import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { runComplyAudit } from '../../../src/core/comply/engine.js';

describe('Comply Engine', () => {
  const tmpDir = join(process.cwd(), '.test-comply-tmp');

  beforeEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    mkdirSync(join(tmpDir, 'src'), { recursive: true });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should run full audit and return valid report structure', async () => {
    // Create a minimal project
    writeFileSync(
      join(tmpDir, 'package.json'),
      JSON.stringify({ name: 'test-app', dependencies: {} }),
    );
    writeFileSync(join(tmpDir, 'src', 'app.ts'), 'const app = express();\napp.listen(3000);');

    const report = await runComplyAudit({ path: tmpDir });

    // Report structure
    expect(report.version).toBe('1.0.0');
    expect(report.timestamp).toBeTruthy();
    expect(report.project.name).toBeTruthy();
    expect(report.project.path).toBe(tmpDir);
    expect(Array.isArray(report.project.stack)).toBe(true);

    // Score
    expect(typeof report.score.global).toBe('number');
    expect(report.score.global).toBeGreaterThanOrEqual(0);
    expect(report.score.global).toBeLessThanOrEqual(100);
    expect(report.score.grade).toBeTruthy();

    // Frameworks
    expect(report.frameworks).toContain('gdpr');
    expect(report.frameworks).toContain('ccpa');
    expect(report.frameworks).toContain('hipaa');
    expect(report.frameworks).toContain('soc2');

    // Framework matrices
    expect(report.frameworkMatrices.length).toBeGreaterThan(0);
    for (const matrix of report.frameworkMatrices) {
      expect(matrix.framework).toBeTruthy();
      expect(Array.isArray(matrix.items)).toBe(true);
      expect(typeof matrix.complianceRate).toBe('number');
    }

    // Data flow
    expect(typeof report.dataFlow.totalDataTypes).toBe('number');
    expect(typeof report.dataFlow.consentCoverage).toBe('number');
    expect(typeof report.dataFlow.encryptionCoverage).toBe('number');

    // Remediation
    expect(Array.isArray(report.remediationRoadmap.immediate)).toBe(true);
    expect(Array.isArray(report.remediationRoadmap.sprint)).toBe(true);
    expect(Array.isArray(report.remediationRoadmap.quarter)).toBe(true);
    expect(typeof report.remediationRoadmap.totalFindings).toBe('number');
  });

  it('should respect --framework filter', async () => {
    writeFileSync(join(tmpDir, 'package.json'), JSON.stringify({ name: 'test-app' }));
    writeFileSync(join(tmpDir, 'src', 'app.ts'), 'export default {};');

    const report = await runComplyAudit({ path: tmpDir, framework: 'gdpr' });

    expect(report.frameworks).toContain('gdpr');
    expect(report.frameworks).not.toContain('ccpa');
    expect(report.frameworkMatrices.length).toBe(1);
    expect(report.frameworkMatrices[0].framework).toBe('gdpr');
  });

  it('should respect --quick mode (layers 1,2,3 only)', async () => {
    writeFileSync(join(tmpDir, 'package.json'), JSON.stringify({ name: 'test-app' }));
    writeFileSync(join(tmpDir, 'src', 'app.ts'), 'export default {};');

    const report = await runComplyAudit({ path: tmpDir, quick: true });

    const layerNumbers = Object.values(report.score.layers).map((l) => l.layer);
    expect(layerNumbers).toContain(1);
    expect(layerNumbers).toContain(2);
    expect(layerNumbers).toContain(3);
    expect(layerNumbers).not.toContain(4);
    expect(layerNumbers).not.toContain(5);
    expect(layerNumbers).not.toContain(6);
    expect(layerNumbers).not.toContain(7);
    expect(layerNumbers).not.toContain(8);
  });

  it('should respect --layer filter', async () => {
    writeFileSync(join(tmpDir, 'package.json'), JSON.stringify({ name: 'test-app' }));
    writeFileSync(join(tmpDir, 'src', 'app.ts'), 'export default {};');

    const report = await runComplyAudit({ path: tmpDir, layer: '1,6' });

    const layerNumbers = Object.values(report.score.layers).map((l) => l.layer);
    expect(layerNumbers).toContain(1);
    expect(layerNumbers).toContain(6);
    expect(layerNumbers).not.toContain(2);
    expect(layerNumbers).not.toContain(3);
  });

  it('should detect PII and generate data flow summary', async () => {
    writeFileSync(join(tmpDir, 'package.json'), JSON.stringify({ name: 'test-app' }));
    writeFileSync(
      join(tmpDir, 'src', 'user.ts'),
      'const email = req.body.email;\nconst ssn = form.ssn;\ndb.save({ email, ssn });',
    );

    const report = await runComplyAudit({ path: tmpDir });

    expect(report.findings.length).toBeGreaterThan(0);
    expect(report.dataFlow.totalDataTypes).toBeGreaterThan(0);
  });

  it('should produce all findings with valid structure', async () => {
    writeFileSync(
      join(tmpDir, 'package.json'),
      JSON.stringify({ name: 'test-app', dependencies: { prisma: '5.0' } }),
    );
    writeFileSync(
      join(tmpDir, 'src', 'app.ts'),
      'const email = req.body.email;\nasync function signup() {}\napp.listen(3000);',
    );

    const report = await runComplyAudit({ path: tmpDir });

    for (const finding of report.findings) {
      expect(finding.id).toMatch(/^CMP-/);
      expect(['critical', 'high', 'medium', 'low', 'info']).toContain(finding.severity);
      expect(finding.layer).toBeGreaterThanOrEqual(1);
      expect(finding.layer).toBeLessThanOrEqual(8);
      expect(finding.layerName).toBeTruthy();
      expect(Array.isArray(finding.regulation)).toBe(true);
      expect(finding.regulation.length).toBeGreaterThan(0);
      expect(finding.title).toBeTruthy();
      expect(finding.evidence.file).toBeTruthy();
      expect(['immediate', 'sprint', 'quarter']).toContain(finding.fix.effort);
    }
  });
});
