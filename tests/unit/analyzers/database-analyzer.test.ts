import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { buildAnalysisContext } from '../../../src/core/analyzers/context-builder.js';
import { createDatabaseAnalyzer } from '../../../src/core/analyzers/database-analyzer.js';

describe('Database Analyzer', () => {
  const tmpDir = join(process.cwd(), '.test-db-analyzer-tmp');

  beforeEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    mkdirSync(join(tmpDir, 'src'), { recursive: true });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should return N/A when no SQL files exist', async () => {
    writeFileSync(join(tmpDir, 'src', 'app.ts'), 'export const app = true;\n');

    const context = await buildAnalysisContext(tmpDir);
    const analyzer = createDatabaseAnalyzer();
    const result = await analyzer.analyze(context);

    expect(result.isNA).toBe(true);
    expect(result.findings).toHaveLength(0);
  });

  it('should detect missing PRIMARY KEY', async () => {
    const sql = `
CREATE TABLE users (
  id INT,
  name VARCHAR(100)
);
`;
    writeFileSync(join(tmpDir, 'src', 'schema.sql'), sql);

    const context = await buildAnalysisContext(tmpDir);
    const analyzer = createDatabaseAnalyzer();
    const result = await analyzer.analyze(context);

    expect(result.isNA).toBe(false);
    const finding = result.findings.find((f) => f.ruleId === 'DB-001');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('critical');
  });

  it('should detect SELECT * usage', async () => {
    const sql = 'SELECT * FROM users WHERE id = 1;';
    writeFileSync(join(tmpDir, 'src', 'query.sql'), sql);

    const context = await buildAnalysisContext(tmpDir);
    const analyzer = createDatabaseAnalyzer();
    const result = await analyzer.analyze(context);

    const finding = result.findings.find((f) => f.ruleId === 'DB-005');
    expect(finding).toBeDefined();
  });

  it('should detect NOLOCK hints', async () => {
    const sql = 'SELECT id FROM users WITH (NOLOCK) WHERE active = 1;';
    writeFileSync(join(tmpDir, 'src', 'query.sql'), sql);

    const context = await buildAnalysisContext(tmpDir);
    const analyzer = createDatabaseAnalyzer();
    const result = await analyzer.analyze(context);

    const finding = result.findings.find((f) => f.ruleId === 'DB-008');
    expect(finding).toBeDefined();
  });

  it('should detect overly permissive GRANT', async () => {
    const sql = 'GRANT ALL ON database TO public;';
    writeFileSync(join(tmpDir, 'src', 'perms.sql'), sql);

    const context = await buildAnalysisContext(tmpDir);
    const analyzer = createDatabaseAnalyzer();
    const result = await analyzer.analyze(context);

    const finding = result.findings.find((f) => f.ruleId === 'DB-010');
    expect(finding).toBeDefined();
  });

  it('should detect inline SQL in TypeScript with SELECT *', async () => {
    const tsCode = `
const query = 'SELECT * FROM users';
export const getUsers = () => db.raw(query);
`;
    writeFileSync(join(tmpDir, 'src', 'repo.ts'), tsCode);

    const context = await buildAnalysisContext(tmpDir);
    const analyzer = createDatabaseAnalyzer();
    const result = await analyzer.analyze(context);

    expect(result.isNA).toBe(false);
    const finding = result.findings.find((f) => f.ruleId === 'DB-005');
    expect(finding).toBeDefined();
  });
});
