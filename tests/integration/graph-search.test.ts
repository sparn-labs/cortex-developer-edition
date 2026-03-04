/**
 * Integration Tests - Graph + Search working together
 */

import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createDependencyGraph } from '../../src/core/dependency-graph.js';
import { createSearchEngine } from '../../src/core/search-engine.js';

describe('Graph + Search Integration', () => {
  const tmpDir = join(process.cwd(), '.test-graph-search-tmp');
  const searchDbPath = join(tmpDir, '.cortex', 'search.db');

  beforeEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    mkdirSync(join(tmpDir, '.cortex'), { recursive: true });
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

  it('should use graph to find dependencies then search for details', async () => {
    // Setup a mini project
    writeFile(
      'src/utils/auth.ts',
      'export function validateToken(token: string): boolean {\n  if (!token) return false;\n  // JWT validation logic\n  return token.startsWith("Bearer ");\n}',
    );
    writeFile(
      'src/core/handler.ts',
      "import { validateToken } from '../utils/auth.js';\n\nexport function handleRequest(req: { token: string }) {\n  const valid = validateToken(req.token);\n  if (!valid) throw new Error('Unauthorized');\n  return { status: 200 };\n}",
    );
    writeFile(
      'src/cli/app.ts',
      "import { handleRequest } from '../core/handler.js';\n\nconst result = handleRequest({ token: 'test' });\nconsole.log(result);",
    );

    // Build dependency graph
    const graph = createDependencyGraph({ projectRoot: tmpDir });
    const nodes = await graph.build();

    // Verify graph structure
    expect(nodes.size).toBe(3);

    // Find files that depend on auth
    const authFocused = await graph.focus('auth');
    expect(authFocused.size).toBeGreaterThanOrEqual(2); // auth.ts + handler.ts at minimum

    // Now search for specific content
    const engine = createSearchEngine(searchDbPath);
    await engine.init(tmpDir);
    await engine.index();

    const results = await engine.search('validateToken', { useRipgrep: false });
    expect(results.length).toBeGreaterThan(0);

    // The auth file should be in results
    const authResult = results.find((r) => r.filePath.includes('auth'));
    expect(authResult).toBeDefined();

    await engine.close();
  });

  it('should analyze graph and search within hot paths', async () => {
    // Create files where helper is imported by many modules
    writeFile(
      'src/utils/helper.ts',
      // biome-ignore lint/suspicious/noTemplateCurlyInString: test fixture with template literal content
      'export function formatError(err: Error) {\n  return `Error: ${err.message}`;\n}',
    );
    writeFile(
      'src/core/a.ts',
      "import { formatError } from '../utils/helper.js';\nexport function a() { return formatError(new Error('a')); }",
    );
    writeFile(
      'src/core/b.ts',
      "import { formatError } from '../utils/helper.js';\nexport function b() { return formatError(new Error('b')); }",
    );
    writeFile(
      'src/core/c.ts',
      "import { formatError } from '../utils/helper.js';\nexport function c() { return formatError(new Error('c')); }",
    );

    // Build graph
    const graph = createDependencyGraph({ projectRoot: tmpDir });
    const analysis = await graph.analyze();

    // helper.ts should be a hot path
    expect(analysis.hotPaths).toContain('src/utils/helper.ts');

    // Search within the hot path files
    const engine = createSearchEngine(searchDbPath);
    await engine.init(tmpDir);
    await engine.index();

    const results = await engine.search('formatError', { useRipgrep: false });
    expect(results.length).toBeGreaterThan(0);

    await engine.close();
  });

  it('should handle entry point traversal then targeted search', async () => {
    writeFile('src/utils/db.ts', 'export function query(sql: string) { return []; }');
    writeFile(
      'src/core/user.ts',
      `import { query } from '../utils/db.js';\nexport function getUser(id: number) { return query(\`SELECT * FROM users WHERE id = \${id}\`); }`,
    );
    writeFile(
      'src/index.ts',
      "import { getUser } from './core/user.js';\nconst user = getUser(1);\nconsole.log(user);",
    );

    const graph = createDependencyGraph({ projectRoot: tmpDir });
    await graph.build();

    // Get files reachable from entry point
    const files = await graph.getFilesFromEntry('src/index.ts');
    expect(files).toContain('src/index.ts');
    expect(files).toContain('src/core/user.ts');
    expect(files).toContain('src/utils/db.ts');

    // Search specifically in those files
    const engine = createSearchEngine(searchDbPath);
    await engine.init(tmpDir);
    await engine.index(files);

    const results = await engine.search('getUser', { useRipgrep: false });
    expect(results.length).toBeGreaterThan(0);

    await engine.close();
  });
});
