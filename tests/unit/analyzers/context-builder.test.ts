import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  buildAnalysisContext,
  buildSingleFileContext,
  getProjectName,
} from '../../../src/core/analyzers/context-builder.js';

describe('Context Builder', () => {
  const tmpDir = join(process.cwd(), '.test-context-builder-tmp');

  beforeEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    mkdirSync(join(tmpDir, 'src'), { recursive: true });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('buildAnalysisContext', () => {
    it('should collect source files', async () => {
      writeFileSync(join(tmpDir, 'src', 'index.ts'), 'export const x = 1;\n');
      writeFileSync(join(tmpDir, 'src', 'utils.ts'), 'export function foo() { return 1; }\n');

      const context = await buildAnalysisContext(tmpDir);

      expect(context.files.size).toBeGreaterThanOrEqual(2);
      expect(context.files.has('src/index.ts')).toBe(true);
      expect(context.files.has('src/utils.ts')).toBe(true);
      expect(context.projectRoot).toBe(tmpDir);
    });

    it('should detect TypeScript stack', async () => {
      writeFileSync(join(tmpDir, 'src', 'app.ts'), 'const x: string = "hello";\n');

      const context = await buildAnalysisContext(tmpDir);
      expect(context.stackTags.has('typescript')).toBe(true);
    });

    it('should respect excludePatterns via .cortexignore', async () => {
      mkdirSync(join(tmpDir, 'src', 'legacy'), { recursive: true });
      writeFileSync(join(tmpDir, 'src', 'app.ts'), 'export const app = 1;\n');
      writeFileSync(join(tmpDir, 'src', 'legacy', 'old.ts'), 'export const old = 1;\n');
      writeFileSync(join(tmpDir, '.cortexignore'), 'src/legacy/**\n');

      const context = await buildAnalysisContext(tmpDir);

      expect(context.files.has('src/app.ts')).toBe(true);
      expect(context.files.has('src/legacy/old.ts')).toBe(false);
    });

    it('should include ignore in context', async () => {
      writeFileSync(join(tmpDir, 'src', 'app.ts'), 'export const app = 1;\n');

      const context = await buildAnalysisContext(tmpDir);
      expect(context.ignore).toBeDefined();
      expect(typeof context.ignore.isFileExcluded).toBe('function');
      expect(typeof context.ignore.isRuleSuppressed).toBe('function');
    });
  });

  describe('buildSingleFileContext', () => {
    it('should include only the specified file', async () => {
      writeFileSync(join(tmpDir, 'src', 'target.ts'), 'export const target = 1;\n');
      writeFileSync(join(tmpDir, 'src', 'other.ts'), 'export const other = 2;\n');

      const context = await buildSingleFileContext(tmpDir, 'src/target.ts');

      expect(context.files.size).toBe(1);
      expect(context.files.has('src/target.ts')).toBe(true);
      expect(context.files.has('src/other.ts')).toBe(false);
    });

    it('should still build dependency graph', async () => {
      writeFileSync(join(tmpDir, 'src', 'target.ts'), 'export const target = 1;\n');

      const context = await buildSingleFileContext(tmpDir, 'src/target.ts');

      expect(context.dependencyGraph).toBeDefined();
      expect(context.graphAnalysis).toBeDefined();
    });

    it('should reject path traversal attempts', async () => {
      const context = await buildSingleFileContext(tmpDir, '../../../etc/passwd');

      // Should return empty files, not read outside project root
      expect(context.files.size).toBe(0);
    });

    it('should handle nonexistent file gracefully', async () => {
      const context = await buildSingleFileContext(tmpDir, 'src/nonexistent.ts');

      expect(context.files.size).toBe(0);
    });
  });

  describe('getProjectName', () => {
    it('should read name from package.json', () => {
      writeFileSync(join(tmpDir, 'package.json'), JSON.stringify({ name: '@scope/my-project' }));

      expect(getProjectName(tmpDir)).toBe('@scope/my-project');
    });

    it('should fall back to directory basename', () => {
      // No package.json
      expect(getProjectName(tmpDir)).toBe('.test-context-builder-tmp');
    });
  });
});
