/**
 * Dependency Graph Tests
 */

import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createDependencyGraph } from '../../src/core/dependency-graph.js';

describe('Dependency Graph', () => {
  const tmpDir = join(process.cwd(), '.test-graph-tmp');

  beforeEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    mkdirSync(join(tmpDir, 'src', 'core'), { recursive: true });
    mkdirSync(join(tmpDir, 'src', 'utils'), { recursive: true });
    mkdirSync(join(tmpDir, 'src', 'cli'), { recursive: true });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  function writeFile(relativePath: string, content: string) {
    writeFileSync(join(tmpDir, relativePath), content, 'utf-8');
  }

  describe('build', () => {
    it('should discover all TypeScript files', async () => {
      writeFile('src/index.ts', 'export const x = 1;');
      writeFile('src/core/foo.ts', 'export function foo() {}');
      writeFile('src/utils/bar.ts', 'export function bar() {}');

      const graph = createDependencyGraph({ projectRoot: tmpDir });
      const nodes = await graph.build();

      expect(nodes.size).toBe(3);
      expect(nodes.has('src/index.ts')).toBe(true);
      expect(nodes.has('src/core/foo.ts')).toBe(true);
      expect(nodes.has('src/utils/bar.ts')).toBe(true);
    });

    it('should ignore node_modules and dist', async () => {
      mkdirSync(join(tmpDir, 'node_modules', 'pkg'), { recursive: true });
      mkdirSync(join(tmpDir, 'dist'), { recursive: true });

      writeFile('src/index.ts', 'export const x = 1;');
      writeFile('node_modules/pkg/index.ts', 'export const y = 1;');
      writeFile('dist/index.ts', 'export const z = 1;');

      const graph = createDependencyGraph({ projectRoot: tmpDir });
      const nodes = await graph.build();

      expect(nodes.size).toBe(1);
      expect(nodes.has('src/index.ts')).toBe(true);
    });

    it('should parse named imports', async () => {
      writeFile('src/core/foo.ts', 'export function foo() { return 1; }');
      writeFile('src/index.ts', "import { foo } from './core/foo.js';\nconsole.log(foo());");

      const graph = createDependencyGraph({ projectRoot: tmpDir });
      const nodes = await graph.build();

      const indexNode = nodes.get('src/index.ts');
      expect(indexNode).toBeDefined();
      expect(indexNode?.imports.length).toBeGreaterThan(0);
      expect(indexNode?.imports[0]?.symbols).toContain('foo');
    });

    it('should parse default imports', async () => {
      writeFile('src/core/bar.ts', 'export default function bar() {}');
      writeFile('src/index.ts', "import bar from './core/bar.js';\nbar();");

      const graph = createDependencyGraph({ projectRoot: tmpDir });
      const nodes = await graph.build();

      const indexNode = nodes.get('src/index.ts');
      expect(indexNode).toBeDefined();
      expect(indexNode?.imports.length).toBeGreaterThan(0);
    });

    it('should parse exports', async () => {
      writeFile(
        'src/core/foo.ts',
        'export function foo() {}\nexport const BAR = 1;\nexport class Baz {}',
      );

      const graph = createDependencyGraph({ projectRoot: tmpDir });
      const nodes = await graph.build();

      const fooNode = nodes.get('src/core/foo.ts');
      expect(fooNode).toBeDefined();
      expect(fooNode?.exports).toContain('foo');
      expect(fooNode?.exports).toContain('BAR');
      expect(fooNode?.exports).toContain('Baz');
    });

    it('should populate callers correctly', async () => {
      writeFile('src/utils/helper.ts', 'export function helper() {}');
      writeFile('src/core/a.ts', "import { helper } from '../utils/helper.js';\nhelper();");
      writeFile('src/core/b.ts', "import { helper } from '../utils/helper.js';\nhelper();");

      const graph = createDependencyGraph({ projectRoot: tmpDir });
      const nodes = await graph.build();

      const helperNode = nodes.get('src/utils/helper.ts');
      expect(helperNode).toBeDefined();
      expect(helperNode?.callers).toHaveLength(2);
      expect(helperNode?.callers).toContain('src/core/a.ts');
      expect(helperNode?.callers).toContain('src/core/b.ts');
    });

    it('should estimate tokens for each file', async () => {
      writeFile('src/index.ts', 'export const x = 1;\nexport const y = 2;');

      const graph = createDependencyGraph({ projectRoot: tmpDir });
      const nodes = await graph.build();

      const indexNode = nodes.get('src/index.ts');
      expect(indexNode).toBeDefined();
      expect(indexNode?.tokenEstimate).toBeGreaterThan(0);
    });

    it('should skip external package imports', async () => {
      writeFile(
        'src/index.ts',
        "import { readFileSync } from 'node:fs';\nimport chalk from 'chalk';\nreadFileSync('.');",
      );

      const graph = createDependencyGraph({ projectRoot: tmpDir });
      const nodes = await graph.build();

      const indexNode = nodes.get('src/index.ts');
      expect(indexNode?.imports).toHaveLength(0);
    });
  });

  describe('analyze', () => {
    it('should identify entry points (files with no callers but with imports)', async () => {
      writeFile('src/utils/helper.ts', 'export function helper() {}');
      writeFile('src/index.ts', "import { helper } from './utils/helper.js';\nhelper();");

      const graph = createDependencyGraph({ projectRoot: tmpDir });
      const analysis = await graph.analyze();

      expect(analysis.entryPoints).toContain('src/index.ts');
    });

    it('should identify orphaned files', async () => {
      writeFile('src/orphan.ts', 'const x = 1;');
      writeFile('src/used.ts', 'export function used() {}');
      writeFile('src/index.ts', "import { used } from './used.js';\nused();");

      const graph = createDependencyGraph({ projectRoot: tmpDir });
      const analysis = await graph.analyze();

      expect(analysis.orphans).toContain('src/orphan.ts');
    });

    it('should identify hot paths', async () => {
      writeFile('src/utils/common.ts', 'export function common() {}');
      writeFile('src/core/a.ts', "import { common } from '../utils/common.js';\ncommon();");
      writeFile('src/core/b.ts', "import { common } from '../utils/common.js';\ncommon();");
      writeFile('src/core/c.ts', "import { common } from '../utils/common.js';\ncommon();");

      const graph = createDependencyGraph({ projectRoot: tmpDir });
      const analysis = await graph.analyze();

      expect(analysis.hotPaths).toContain('src/utils/common.ts');
    });

    it('should calculate total tokens', async () => {
      writeFile('src/a.ts', 'export const a = "hello world";');
      writeFile('src/b.ts', 'export const b = "foo bar baz";');

      const graph = createDependencyGraph({ projectRoot: tmpDir });
      const analysis = await graph.analyze();

      expect(analysis.totalTokens).toBeGreaterThan(0);
    });
  });

  describe('focus', () => {
    it('should return matching files and their dependencies', async () => {
      writeFile('src/utils/helper.ts', 'export function helper() {}');
      writeFile(
        'src/core/auth.ts',
        "import { helper } from '../utils/helper.js';\nexport function auth() { helper(); }",
      );
      writeFile('src/core/other.ts', 'export function other() {}');

      const graph = createDependencyGraph({ projectRoot: tmpDir });
      await graph.build();

      const focused = await graph.focus('auth');

      expect(focused.has('src/core/auth.ts')).toBe(true);
      // Should include the dependency
      expect(focused.has('src/utils/helper.ts')).toBe(true);
      // Should NOT include unrelated
      expect(focused.has('src/core/other.ts')).toBe(false);
    });
  });

  describe('getFilesFromEntry', () => {
    it('should traverse dependencies from entry point', async () => {
      writeFile('src/utils/helper.ts', 'export function helper() {}');
      writeFile(
        'src/core/foo.ts',
        "import { helper } from '../utils/helper.js';\nexport function foo() { helper(); }",
      );
      writeFile('src/index.ts', "import { foo } from './core/foo.js';\nfoo();");

      const graph = createDependencyGraph({ projectRoot: tmpDir });
      await graph.build();

      const files = await graph.getFilesFromEntry('src/index.ts');

      expect(files).toContain('src/index.ts');
      expect(files).toContain('src/core/foo.ts');
      expect(files).toContain('src/utils/helper.ts');
    });

    it('should respect depth limit', async () => {
      writeFile('src/utils/deep.ts', 'export function deep() {}');
      writeFile(
        'src/core/mid.ts',
        "import { deep } from '../utils/deep.js';\nexport function mid() { deep(); }",
      );
      writeFile('src/index.ts', "import { mid } from './core/mid.js';\nmid();");

      const graph = createDependencyGraph({ projectRoot: tmpDir });
      await graph.build();

      const files = await graph.getFilesFromEntry('src/index.ts', 1);

      expect(files).toContain('src/index.ts');
      expect(files).toContain('src/core/mid.ts');
      // Depth 1 should not reach the deep dependency
      expect(files).not.toContain('src/utils/deep.ts');
    });
  });

  describe('edge cases', () => {
    it('should handle empty project', async () => {
      const graph = createDependencyGraph({ projectRoot: tmpDir });
      const nodes = await graph.build();

      expect(nodes.size).toBe(0);
    });

    it('should handle circular dependencies', async () => {
      writeFile('src/a.ts', "import { b } from './b.js';\nexport function a() { return b(); }");
      writeFile('src/b.ts', "import { a } from './a.js';\nexport function b() { return a(); }");

      const graph = createDependencyGraph({ projectRoot: tmpDir });
      const nodes = await graph.build();

      expect(nodes.size).toBe(2);
      // Should not infinite loop
      const files = await graph.getFilesFromEntry('src/a.ts');
      expect(files).toContain('src/a.ts');
      expect(files).toContain('src/b.ts');
    });

    it('should handle files with no imports or exports', async () => {
      writeFile('src/standalone.ts', 'const x = 1;\nconsole.log(x);');

      const graph = createDependencyGraph({ projectRoot: tmpDir });
      const nodes = await graph.build();

      expect(nodes.has('src/standalone.ts')).toBe(true);
      const node = nodes.get('src/standalone.ts');
      expect(node?.imports).toHaveLength(0);
    });
  });
});
