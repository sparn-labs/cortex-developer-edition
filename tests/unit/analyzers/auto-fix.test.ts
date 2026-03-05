import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  type AnalyzerFixAction,
  applyFixAction,
  collectFixableActions,
} from '../../../src/core/analyzers/auto-fix.js';
import type { AnalyzerFinding } from '../../../src/core/analyzers/types.js';

describe('Analyzer Auto-Fix', () => {
  const tmpDir = join(process.cwd(), '.test-auto-fix-tmp');

  beforeEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    mkdirSync(join(tmpDir, 'src'), { recursive: true });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('QUAL-009: Remove debug statements', () => {
    it('should remove console.log lines', () => {
      const file = join(tmpDir, 'src', 'helper.ts');
      writeFileSync(
        file,
        [
          'export function add(a: number, b: number) {',
          '  console.log("debug value", a);',
          '  return a + b;',
          '}',
        ].join('\n'),
      );

      const finding: AnalyzerFinding = {
        ruleId: 'QUAL-009',
        title: 'Debug statements in production code',
        description: 'src/helper.ts: 1 console.log/debug/info calls',
        severity: 'minor',
        filePath: 'src/helper.ts',
        deduction: 0.05,
        fixable: true,
        fixType: 'remove-code',
      };

      const actions = collectFixableActions(tmpDir, [finding]);
      expect(actions).toHaveLength(1);
      expect(actions[0]!.ruleId).toBe('QUAL-009');
      expect(actions[0]!.preview.length).toBeGreaterThan(0);

      const success = applyFixAction(actions[0]!);
      expect(success).toBe(true);

      const result = readFileSync(file, 'utf-8');
      expect(result).not.toContain('console.log');
      expect(result).toContain('return a + b');
    });

    it('should remove debugger statements', () => {
      const file = join(tmpDir, 'src', 'debug.ts');
      writeFileSync(
        file,
        ['function test() {', '  debugger;', '  return 42;', '}'].join('\n'),
      );

      const finding: AnalyzerFinding = {
        ruleId: 'QUAL-009',
        title: 'Debug statements in production code',
        description: 'src/debug.ts: debug statements',
        severity: 'minor',
        filePath: 'src/debug.ts',
        deduction: 0.05,
        fixable: true,
        fixType: 'remove-code',
      };

      const actions = collectFixableActions(tmpDir, [finding]);
      expect(actions).toHaveLength(1);

      applyFixAction(actions[0]!);
      const result = readFileSync(file, 'utf-8');
      expect(result).not.toContain('debugger');
      expect(result).toContain('return 42');
    });

    it('should remove multiple debug statement types', () => {
      const file = join(tmpDir, 'src', 'multi.ts');
      writeFileSync(
        file,
        [
          'const x = 1;',
          '  console.log("test");',
          '  console.debug("debug");',
          '  console.warn("warn");',
          '  console.info("info");',
          'const y = 2;',
        ].join('\n'),
      );

      const finding: AnalyzerFinding = {
        ruleId: 'QUAL-009',
        title: 'Debug statements in production code',
        description: 'src/multi.ts: 4 console calls',
        severity: 'minor',
        filePath: 'src/multi.ts',
        deduction: 0.2,
        fixable: true,
        fixType: 'remove-code',
      };

      const actions = collectFixableActions(tmpDir, [finding]);
      expect(actions).toHaveLength(1);
      expect(actions[0]!.preview.length).toBe(4);

      applyFixAction(actions[0]!);
      const result = readFileSync(file, 'utf-8');
      expect(result).toContain('const x = 1');
      expect(result).toContain('const y = 2');
      expect(result).not.toContain('console.');
    });
  });

  describe('SEC-003: Replace weak crypto', () => {
    it('should replace MD5 with SHA-256', () => {
      const file = join(tmpDir, 'src', 'auth.ts');
      writeFileSync(
        file,
        [
          "import { createHash } from 'node:crypto';",
          "const hash = createHash('md5').update(data).digest('hex');",
        ].join('\n'),
      );

      const finding: AnalyzerFinding = {
        ruleId: 'SEC-003',
        title: 'Weak cryptography: MD5',
        description: 'src/auth.ts: MD5 is cryptographically weak',
        severity: 'minor',
        filePath: 'src/auth.ts',
        deduction: 0.5,
        fixable: true,
        fixType: 'replace-pattern',
      };

      const actions = collectFixableActions(tmpDir, [finding]);
      expect(actions).toHaveLength(1);
      expect(actions[0]!.preview).toContain('MD5 -> SHA-256');

      applyFixAction(actions[0]!);
      const result = readFileSync(file, 'utf-8');
      expect(result).toContain("createHash('sha256')");
      expect(result).not.toContain("createHash('md5')");
    });

    it('should replace SHA1 with SHA-256', () => {
      const file = join(tmpDir, 'src', 'hash.ts');
      writeFileSync(
        file,
        "const h = createHash('sha1').update('test').digest('hex');\n",
      );

      const finding: AnalyzerFinding = {
        ruleId: 'SEC-003',
        title: 'Weak cryptography: SHA1',
        description: 'src/hash.ts: SHA1 is weak',
        severity: 'minor',
        filePath: 'src/hash.ts',
        deduction: 0.5,
        fixable: true,
        fixType: 'replace-pattern',
      };

      const actions = collectFixableActions(tmpDir, [finding]);
      expect(actions).toHaveLength(1);

      applyFixAction(actions[0]!);
      const result = readFileSync(file, 'utf-8');
      expect(result).toContain("createHash('sha256')");
      expect(result).not.toContain("createHash('sha1')");
    });
  });

  describe('QUAL-004: Remove @ts-ignore/@ts-nocheck', () => {
    it('should remove @ts-ignore comments', () => {
      const file = join(tmpDir, 'src', 'ignore.ts');
      writeFileSync(
        file,
        [
          'const a = 1;',
          '// @ts-ignore',
          'const b: any = a;',
          'const c = 3;',
        ].join('\n'),
      );

      const finding: AnalyzerFinding = {
        ruleId: 'QUAL-004',
        title: 'TS anti-pattern: @ts-ignore directive',
        description: 'src/ignore.ts: 1 occurrence(s) of @ts-ignore directive',
        severity: 'major',
        filePath: 'src/ignore.ts',
        deduction: 0.15,
        fixable: true,
        fixType: 'replace-pattern',
      };

      const actions = collectFixableActions(tmpDir, [finding]);
      expect(actions).toHaveLength(1);

      applyFixAction(actions[0]!);
      const result = readFileSync(file, 'utf-8');
      expect(result).not.toContain('@ts-ignore');
      expect(result).toContain('const a = 1');
      expect(result).toContain('const b: any = a');
    });

    it('should remove @ts-nocheck comments', () => {
      const file = join(tmpDir, 'src', 'nocheck.ts');
      writeFileSync(
        file,
        ['// @ts-nocheck', 'const x = 1;'].join('\n'),
      );

      const finding: AnalyzerFinding = {
        ruleId: 'QUAL-004',
        title: 'TS anti-pattern: @ts-nocheck directive',
        description: 'src/nocheck.ts: 1 occurrence(s)',
        severity: 'major',
        filePath: 'src/nocheck.ts',
        deduction: 0.15,
        fixable: true,
        fixType: 'replace-pattern',
      };

      const actions = collectFixableActions(tmpDir, [finding]);
      expect(actions).toHaveLength(1);

      applyFixAction(actions[0]!);
      const result = readFileSync(file, 'utf-8');
      expect(result).not.toContain('@ts-nocheck');
      expect(result).toContain('const x = 1');
    });

    it('should skip non ts-ignore QUAL-004 findings', () => {
      const finding: AnalyzerFinding = {
        ruleId: 'QUAL-004',
        title: 'TS anti-pattern: as any cast',
        description: 'src/foo.ts: 1 occurrence(s) of as any cast',
        severity: 'major',
        filePath: 'src/foo.ts',
        deduction: 0.15,
        fixable: true,
        fixType: 'replace-pattern',
      };

      const actions = collectFixableActions(tmpDir, [finding]);
      expect(actions).toHaveLength(0);
    });
  });

  describe('SEC-004: Replace CORS wildcard', () => {
    it('should replace origin wildcard with placeholder', () => {
      const file = join(tmpDir, 'src', 'server.ts');
      writeFileSync(
        file,
        [
          "app.use(cors({",
          "  origin: '*',",
          "  credentials: true,",
          "}));",
        ].join('\n'),
      );

      const finding: AnalyzerFinding = {
        ruleId: 'SEC-004',
        title: 'CORS wildcard origin',
        description: 'src/server.ts: Allow-Origin set to *',
        severity: 'minor',
        filePath: 'src/server.ts',
        deduction: 0.5,
        fixable: true,
        fixType: 'config-change',
      };

      const actions = collectFixableActions(tmpDir, [finding]);
      expect(actions).toHaveLength(1);

      applyFixAction(actions[0]!);
      const result = readFileSync(file, 'utf-8');
      expect(result).not.toContain("'*'");
      expect(result).toContain('https://your-domain.com');
    });
  });

  describe('collectFixableActions', () => {
    it('should skip non-fixable findings', () => {
      const finding: AnalyzerFinding = {
        ruleId: 'QUAL-001',
        title: 'High cyclomatic complexity',
        description: 'src/foo.ts: complexity 25',
        severity: 'major',
        deduction: 1,
        fixable: false,
      };

      const actions = collectFixableActions(tmpDir, [finding]);
      expect(actions).toHaveLength(0);
    });

    it('should skip findings with unknown ruleId', () => {
      const finding: AnalyzerFinding = {
        ruleId: 'UNKNOWN-999',
        title: 'Unknown rule',
        description: 'test',
        severity: 'minor',
        deduction: 0.1,
        fixable: true,
      };

      const actions = collectFixableActions(tmpDir, [finding]);
      expect(actions).toHaveLength(0);
    });

    it('should deduplicate by ruleId + file', () => {
      const file = join(tmpDir, 'src', 'dup.ts');
      writeFileSync(
        file,
        [
          '  console.log("a");',
          '  console.log("b");',
        ].join('\n'),
      );

      const findings: AnalyzerFinding[] = [
        {
          ruleId: 'QUAL-009',
          title: 'Debug statements in production code',
          description: 'src/dup.ts: 2 calls',
          severity: 'minor',
          filePath: 'src/dup.ts',
          deduction: 0.1,
          fixable: true,
          fixType: 'remove-code',
        },
        {
          ruleId: 'QUAL-009',
          title: 'Debug statements in production code',
          description: 'src/dup.ts: 2 calls',
          severity: 'minor',
          filePath: 'src/dup.ts',
          deduction: 0.1,
          fixable: true,
          fixType: 'remove-code',
        },
      ];

      const actions = collectFixableActions(tmpDir, findings);
      expect(actions).toHaveLength(1);
    });

    it('should collect multiple different fix types', () => {
      writeFileSync(
        join(tmpDir, 'src', 'mixed.ts'),
        [
          '  console.log("test");',
          "const h = createHash('md5').update('x').digest('hex');",
        ].join('\n'),
      );

      const findings: AnalyzerFinding[] = [
        {
          ruleId: 'QUAL-009',
          title: 'Debug statements in production code',
          description: 'src/mixed.ts: 1 call',
          severity: 'minor',
          filePath: 'src/mixed.ts',
          deduction: 0.05,
          fixable: true,
          fixType: 'remove-code',
        },
        {
          ruleId: 'SEC-003',
          title: 'Weak cryptography: MD5',
          description: 'src/mixed.ts: MD5',
          severity: 'minor',
          filePath: 'src/mixed.ts',
          deduction: 0.5,
          fixable: true,
          fixType: 'replace-pattern',
        },
      ];

      const actions = collectFixableActions(tmpDir, findings);
      expect(actions).toHaveLength(2);
      expect(actions.map((a) => a.ruleId).sort()).toEqual(['QUAL-009', 'SEC-003']);
    });
  });

  describe('applyFixAction', () => {
    it('should return false for a failing action', () => {
      const action: AnalyzerFixAction = {
        ruleId: 'TEST',
        file: 'nonexistent.ts',
        description: 'test',
        preview: [],
        apply: () => false,
      };

      expect(applyFixAction(action)).toBe(false);
    });

    it('should catch exceptions from apply()', () => {
      const action: AnalyzerFixAction = {
        ruleId: 'TEST',
        file: 'nonexistent.ts',
        description: 'test',
        preview: [],
        apply: () => {
          throw new Error('boom');
        },
      };

      expect(applyFixAction(action)).toBe(false);
    });
  });
});
