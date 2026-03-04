import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createCortexIgnore, parseCortexIgnore } from '../../../src/core/analyzers/cortexignore.js';

describe('CortexIgnore', () => {
  const tmpDir = join(process.cwd(), '.test-cortexignore-tmp');

  beforeEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    mkdirSync(tmpDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('parseCortexIgnore', () => {
    it('should parse simple glob patterns', () => {
      const rules = parseCortexIgnore('src/legacy/**\ndist/**');
      expect(rules).toHaveLength(2);
      expect(rules[0]?.pattern).toBe('src/legacy/**');
      expect(rules[0]?.ruleIds).toBeNull();
      expect(rules[1]?.pattern).toBe('dist/**');
    });

    it('should parse rule-specific ignores', () => {
      const rules = parseCortexIgnore('src/legacy/** QUAL-001,QUAL-002');
      expect(rules).toHaveLength(1);
      expect(rules[0]?.pattern).toBe('src/legacy/**');
      expect(rules[0]?.ruleIds).toEqual(['QUAL-001', 'QUAL-002']);
    });

    it('should skip comments and empty lines', () => {
      const rules = parseCortexIgnore('# Comment\n\nsrc/**\n  \n# Another comment');
      expect(rules).toHaveLength(1);
      expect(rules[0]?.pattern).toBe('src/**');
    });

    it('should handle single rule-specific ignore', () => {
      const rules = parseCortexIgnore('*.test.ts DOC-001');
      expect(rules).toHaveLength(1);
      expect(rules[0]?.ruleIds).toEqual(['DOC-001']);
    });
  });

  describe('CortexIgnore matching', () => {
    it('should exclude files matching glob patterns', () => {
      writeFileSync(join(tmpDir, '.cortexignore'), 'src/legacy/**\n');
      const ignore = createCortexIgnore(tmpDir);

      expect(ignore.isFileExcluded('src/legacy/old.ts')).toBe(true);
      expect(ignore.isFileExcluded('src/core/new.ts')).toBe(false);
    });

    it('should suppress specific rules for matched paths', () => {
      writeFileSync(join(tmpDir, '.cortexignore'), 'src/generated/** QUAL-001,QUAL-003\n');
      const ignore = createCortexIgnore(tmpDir);

      // File is not fully excluded
      expect(ignore.isFileExcluded('src/generated/api.ts')).toBe(false);

      // But specific rules are suppressed
      expect(ignore.isRuleSuppressed('src/generated/api.ts', 'QUAL-001')).toBe(true);
      expect(ignore.isRuleSuppressed('src/generated/api.ts', 'QUAL-003')).toBe(true);
      expect(ignore.isRuleSuppressed('src/generated/api.ts', 'QUAL-002')).toBe(false);
    });

    it('should merge config excludePatterns', () => {
      const ignore = createCortexIgnore(tmpDir, ['vendor']);

      expect(ignore.isFileExcluded('vendor/lib.ts')).toBe(true);
      expect(ignore.isFileExcluded('src/core.ts')).toBe(false);
    });

    it('should work without .cortexignore file', () => {
      const ignore = createCortexIgnore(tmpDir);

      expect(ignore.isFileExcluded('src/core.ts')).toBe(false);
      expect(ignore.rules).toHaveLength(0);
    });

    it('should handle ** in middle of path', () => {
      writeFileSync(join(tmpDir, '.cortexignore'), 'src/**/test.ts\n');
      const ignore = createCortexIgnore(tmpDir);

      expect(ignore.isFileExcluded('src/test.ts')).toBe(true);
      expect(ignore.isFileExcluded('src/deep/nested/test.ts')).toBe(true);
      expect(ignore.isFileExcluded('src/other.ts')).toBe(false);
    });

    it('should handle * wildcard (non-recursive)', () => {
      writeFileSync(join(tmpDir, '.cortexignore'), '*.config.ts\n');
      const ignore = createCortexIgnore(tmpDir);

      expect(ignore.isFileExcluded('vitest.config.ts')).toBe(true);
      expect(ignore.isFileExcluded('src/vitest.config.ts')).toBe(false);
    });

    it('should fully exclude files when ruleIds is null', () => {
      writeFileSync(join(tmpDir, '.cortexignore'), 'src/legacy/**\n');
      const ignore = createCortexIgnore(tmpDir);

      expect(ignore.isRuleSuppressed('src/legacy/old.ts', 'QUAL-001')).toBe(true);
      expect(ignore.isRuleSuppressed('src/legacy/old.ts', 'ARCH-004')).toBe(true);
    });
  });
});
