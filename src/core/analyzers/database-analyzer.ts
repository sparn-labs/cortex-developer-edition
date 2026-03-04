/**
 * Database Analyzer (20 pts)
 *
 * Static analysis of .sql files and inline SQL in .ts/.cs code.
 * Marks itself N/A if no SQL is found.
 */

import type { AnalysisContext, Analyzer, AnalyzerFinding, CategoryResult } from './types.js';

const DB_RULE_CAPS: Record<string, number> = {
  'DB-001': 3,
  'DB-002': 2,
  'DB-003': 2,
  'DB-004': 2,
  'DB-005': 2,
  'DB-006': 3,
  'DB-007': 2,
  'DB-008': 1,
  'DB-009': 1,
  'DB-010': 2,
};

function classifySQLFiles(context: AnalysisContext): {
  sqlFiles: Array<[string, string]>;
  codeFilesWithSQL: Array<[string, string]>;
} {
  const sqlFiles: Array<[string, string]> = [];
  const codeFilesWithSQL: Array<[string, string]> = [];

  for (const [filePath, content] of context.files) {
    if (filePath.endsWith('.sql')) {
      sqlFiles.push([filePath, content]);
    } else if (isCodeWithSQL(filePath, content)) {
      codeFilesWithSQL.push([filePath, content]);
    }
  }
  return { sqlFiles, codeFilesWithSQL };
}

function isCodeWithSQL(filePath: string, content: string): boolean {
  if (!filePath.endsWith('.ts') && !filePath.endsWith('.cs') && !filePath.endsWith('.js')) {
    return false;
  }
  return !isAnalyzerOrTestFile(filePath) && hasInlineSQL(content);
}

function applyCappedDeductions(findings: AnalyzerFinding[], caps: Record<string, number>): number {
  const ruleDeductions = new Map<string, number>();
  let total = 0;
  for (const finding of findings) {
    const current = ruleDeductions.get(finding.ruleId) ?? 0;
    const cap = caps[finding.ruleId] ?? 2;
    const available = Math.max(0, cap - current);
    const actual = Math.min(finding.deduction, available);
    ruleDeductions.set(finding.ruleId, current + actual);
    total += actual;
  }
  return total;
}

export function createDatabaseAnalyzer(): Analyzer {
  return {
    category: 'database',
    name: 'Database',
    maxPoints: 20,

    async analyze(context: AnalysisContext): Promise<CategoryResult> {
      const { sqlFiles, codeFilesWithSQL } = classifySQLFiles(context);

      if (sqlFiles.length === 0 && codeFilesWithSQL.length === 0) {
        return {
          category: 'database',
          name: 'Database',
          maxPoints: 20,
          score: 0,
          isNA: true,
          findings: [],
        };
      }

      const findings: AnalyzerFinding[] = [];

      for (const [filePath, content] of sqlFiles) {
        checkMissingPrimaryKey(filePath, content, findings);
        checkMissingNotNull(filePath, content, findings);
        checkDeprecatedTypes(filePath, content, findings);
        checkMissingFKIndex(filePath, content, findings);
        checkSelectStar(filePath, content, findings);
        checkNolockHints(filePath, content, findings);
        checkMissingAuditColumns(filePath, content, findings);
        checkPermissiveGrant(filePath, content, findings);
      }

      for (const [filePath, content] of codeFilesWithSQL) {
        checkSelectStar(filePath, content, findings);
        checkNPlusOne(filePath, content, findings);
        checkSQLConcatenation(filePath, content, findings);
      }

      for (const [filePath, content] of sqlFiles) {
        checkNPlusOne(filePath, content, findings);
        checkSQLConcatenation(filePath, content, findings);
      }

      const deductions = applyCappedDeductions(findings, DB_RULE_CAPS);
      const score = Math.max(0, 20 - deductions);

      return {
        category: 'database',
        name: 'Database',
        maxPoints: 20,
        score,
        isNA: false,
        findings,
      };
    },
  };
}

function isAnalyzerOrTestFile(path: string): boolean {
  return (
    (path.includes('analyzers/') &&
      (path.endsWith('-analyzer.ts') || path.endsWith('-analyzer.js'))) ||
    path.includes('.test.') ||
    path.includes('.spec.')
  );
}

function hasInlineSQL(content: string): boolean {
  // Must contain actual SQL statements (not just references to keywords in strings/regexes)
  if (!/\b(SELECT|INSERT|UPDATE|DELETE|CREATE\s+TABLE)\b/i.test(content)) return false;
  // Skip files that exclusively use ORM/prepared statements
  if (usesORMOrPreparedStatements(content)) return false;
  return true;
}

function usesORMOrPreparedStatements(content: string): boolean {
  const ormPatterns = [
    /\bprisma\b/i,
    /\btypeorm\b/i,
    /\bsequelize\b/i,
    /\bdrizzle\b/i,
    /\bknex\b/i,
    /\b\.prepare\s*\(/,
    /\bpreparedStatement\b/i,
    /\b\.query\s*\([^,]+,\s*\[/, // parameterized query: .query(sql, [params])
    /\bbetter-sqlite3\b/,
    /\.run\s*\([^,]+,\s*/, // better-sqlite3 style: .run(sql, params)
  ];
  return ormPatterns.some((p) => p.test(content));
}

function checkMissingPrimaryKey(
  filePath: string,
  content: string,
  findings: AnalyzerFinding[],
): number {
  const createTables = [...content.matchAll(/CREATE\s+TABLE\s+(\S+)\s*\(([\s\S]*?)\);/gi)];
  let total = 0;

  for (const match of createTables) {
    const tableName = match[1] || 'unknown';
    const body = match[2] || '';
    if (!/PRIMARY\s+KEY/i.test(body)) {
      total += 0.5;
      findings.push({
        ruleId: 'DB-001',
        title: 'Missing PRIMARY KEY',
        description: `${filePath}: table ${tableName} has no PRIMARY KEY`,
        severity: 'critical',
        filePath,
        suggestion: `Add a PRIMARY KEY constraint to ensure data integrity.`,
        deduction: 0.5,
        fixable: true,
        fixType: 'add-constraint',
      });
    }
  }

  return Math.min(total, 3);
}

function checkMissingNotNull(
  filePath: string,
  content: string,
  findings: AnalyzerFinding[],
): number {
  // Look for columns that are likely non-nullable but missing NOT NULL
  const columnPattern =
    /^\s+(\w+)\s+(INT|BIGINT|VARCHAR|NVARCHAR|DATETIME|BIT|DECIMAL)\b(?!.*NOT\s+NULL)(?!.*NULL)/gim;
  const matches = [...content.matchAll(columnPattern)];

  if (matches.length > 3) {
    findings.push({
      ruleId: 'DB-002',
      title: 'Missing NOT NULL constraints',
      description: `${filePath}: ${matches.length} columns without explicit NULL/NOT NULL`,
      severity: 'minor',
      filePath,
      suggestion: `Explicitly declare NULL or NOT NULL for all columns.`,
      deduction: 0.5,
      fixable: true,
      fixType: 'add-constraint',
    });
    return 0.5;
  }

  return 0;
}

function checkDeprecatedTypes(
  filePath: string,
  content: string,
  findings: AnalyzerFinding[],
): number {
  const deprecated = [
    { pattern: /VARCHAR\s*\(\s*MAX\s*\)/gi, name: 'VARCHAR(MAX)' },
    { pattern: /\bNTEXT\b/gi, name: 'NTEXT' },
    { pattern: /\bIMAGE\b/gi, name: 'IMAGE' },
    { pattern: /\bTEXT\b(?!\s*NOT)/gi, name: 'TEXT' },
  ];

  let total = 0;

  for (const { pattern, name } of deprecated) {
    const matches = content.match(pattern);
    if (matches) {
      total += 0.25;
      findings.push({
        ruleId: 'DB-003',
        title: `Deprecated type: ${name}`,
        description: `${filePath}: ${matches.length} usage(s) of deprecated type ${name}`,
        severity: 'minor',
        filePath,
        suggestion: `Replace with modern types (NVARCHAR(n), VARBINARY(MAX), etc.)`,
        deduction: 0.25,
        fixable: true,
        fixType: 'replace-pattern',
      });
    }
  }

  return Math.min(total, 2);
}

function checkMissingFKIndex(
  filePath: string,
  content: string,
  findings: AnalyzerFinding[],
): number {
  const fkPattern = /FOREIGN\s+KEY\s*\(\s*(\w+)\s*\)/gi;
  const indexPattern = /CREATE\s+(?:UNIQUE\s+)?(?:NONCLUSTERED\s+)?INDEX/gi;
  const fks = [...content.matchAll(fkPattern)];
  const hasIndexes = indexPattern.test(content);

  if (fks.length > 0 && !hasIndexes) {
    findings.push({
      ruleId: 'DB-004',
      title: 'Foreign keys without indexes',
      description: `${filePath}: ${fks.length} FOREIGN KEY(s) found but no corresponding indexes`,
      severity: 'major',
      filePath,
      suggestion: `Create indexes on foreign key columns for query performance.`,
      deduction: 0.5,
      fixable: true,
      fixType: 'add-index',
    });
    return 0.5;
  }

  return 0;
}

function checkSelectStar(filePath: string, content: string, findings: AnalyzerFinding[]): number {
  const matches = content.match(/SELECT\s+\*/gi);
  if (matches && matches.length > 0) {
    findings.push({
      ruleId: 'DB-005',
      title: 'SELECT * usage',
      description: `${filePath}: ${matches.length} SELECT * statement(s)`,
      severity: 'minor',
      filePath,
      suggestion: `Explicitly list needed columns to improve performance and maintainability.`,
      deduction: 0.25,
      fixable: true,
      fixType: 'replace-pattern',
    });
    return 0.25;
  }
  return 0;
}

function checkNPlusOne(filePath: string, content: string, findings: AnalyzerFinding[]): number {
  // Use brace-depth tracking to find SQL queries inside loops
  const loopStarts =
    /\b(?:for|while)\s*\([^)]*\)\s*\{|\.(?:forEach|map|each)\s*\([^)]*(?:=>|function)\s*\{/g;
  // Match SQL keywords only when used as statements, not as method names (.delete()) or variables (updated)
  const sqlKeywords = /(?:^|[\s('"`;])(?:SELECT|INSERT\s+INTO|UPDATE\s+\w|DELETE\s+FROM)\b/im;
  let count = 0;
  let match: RegExpExecArray | null;

  // biome-ignore lint/suspicious/noAssignInExpressions: regex iteration pattern
  while ((match = loopStarts.exec(content)) !== null) {
    // Find the matching closing brace via depth tracking
    const startIdx = match.index + match[0].length - 1; // position of the opening {
    let braceCount = 1;
    let endIdx = startIdx + 1;

    for (let i = startIdx + 1; i < content.length && braceCount > 0; i++) {
      if (content[i] === '{') braceCount++;
      else if (content[i] === '}') braceCount--;
      endIdx = i;
    }

    const loopBody = content.slice(startIdx + 1, endIdx);
    if (sqlKeywords.test(loopBody)) {
      count++;
    }
  }

  if (count > 0) {
    findings.push({
      ruleId: 'DB-006',
      title: 'N+1 query pattern',
      description: `${filePath}: ${count} SQL query/queries inside loop(s)`,
      severity: 'critical',
      filePath,
      suggestion: `Batch queries or use JOINs to avoid N+1 patterns.`,
      deduction: 1,
      fixable: true,
      fixType: 'replace-pattern',
    });
    return Math.min(count, 3);
  }

  return 0;
}

function checkSQLConcatenation(
  filePath: string,
  content: string,
  findings: AnalyzerFinding[],
): number {
  // Skip if file uses ORM or prepared statements (low injection risk)
  if (usesORMOrPreparedStatements(content)) return 0;

  // Skip analyzer/test files that contain regex patterns referencing SQL keywords
  if (filePath.includes('analyzer') || filePath.includes('.test.') || filePath.includes('.spec.')) {
    return 0;
  }

  // String concatenation in SQL queries (injection risk)
  const concatPatterns = [
    /(?:SELECT|INSERT|UPDATE|DELETE|WHERE).*\+\s*(?:req|params|query|body|input|user)/gi,
    /`\$\{.*\}.*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)/gi,
    /(?:SELECT|INSERT|UPDATE|DELETE|WHERE).*`\$\{/gi,
  ];

  for (const pattern of concatPatterns) {
    const matches = content.match(pattern);
    if (matches) {
      findings.push({
        ruleId: 'DB-007',
        title: 'SQL string concatenation',
        description: `${filePath}: potential SQL injection via string concatenation`,
        severity: 'critical',
        filePath,
        suggestion: `Use parameterized queries or prepared statements.`,
        deduction: 1,
        fixable: true,
        fixType: 'replace-pattern',
      });
      return 1;
    }
  }

  return 0;
}

function checkNolockHints(filePath: string, content: string, findings: AnalyzerFinding[]): number {
  const matches = content.match(/\bNOLOCK\b/gi);
  if (matches) {
    findings.push({
      ruleId: 'DB-008',
      title: 'NOLOCK hints',
      description: `${filePath}: ${matches.length} NOLOCK hint(s) — risk of dirty reads`,
      severity: 'minor',
      filePath,
      suggestion: `Use appropriate transaction isolation levels instead of NOLOCK.`,
      deduction: 0.25,
      fixable: true,
      fixType: 'remove-code',
    });
    return 0.25;
  }
  return 0;
}

function checkMissingAuditColumns(
  filePath: string,
  content: string,
  findings: AnalyzerFinding[],
): number {
  const createTables = [...content.matchAll(/CREATE\s+TABLE\s+\S+\s*\(([\s\S]*?)\);/gi)];

  for (const match of createTables) {
    const body = match[1] || '';
    const hasCreated = /created_at|createdat|date_created|created_date/i.test(body);
    const hasUpdated = /updated_at|updatedat|date_updated|modified_date|last_modified/i.test(body);

    if (!hasCreated || !hasUpdated) {
      findings.push({
        ruleId: 'DB-009',
        title: 'Missing audit columns',
        description: `${filePath}: table missing ${!hasCreated ? 'created_at' : ''}${!hasCreated && !hasUpdated ? ' and ' : ''}${!hasUpdated ? 'updated_at' : ''}`,
        severity: 'info',
        filePath,
        suggestion: `Add created_at and updated_at timestamp columns for auditing.`,
        deduction: 0.25,
        fixable: true,
        fixType: 'add-constraint',
      });
      return 0.25;
    }
  }

  return 0;
}

function checkPermissiveGrant(
  filePath: string,
  content: string,
  findings: AnalyzerFinding[],
): number {
  const patterns = [/GRANT\s+ALL/gi, /GRANT\s+\w+\s+TO\s+public/gi];

  for (const pattern of patterns) {
    const matches = content.match(pattern);
    if (matches) {
      findings.push({
        ruleId: 'DB-010',
        title: 'Overly permissive GRANT',
        description: `${filePath}: ${matches.length} overly permissive GRANT statement(s)`,
        severity: 'major',
        filePath,
        suggestion: `Grant only the minimum required permissions.`,
        deduction: 0.5,
        fixable: true,
        fixType: 'replace-pattern',
      });
      return 0.5;
    }
  }

  return 0;
}
