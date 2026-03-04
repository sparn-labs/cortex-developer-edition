/**
 * Code Quality Analyzer (20 pts)
 *
 * Checks cyclomatic complexity, function/file length, anti-patterns,
 * nested complexity, debug statements, and magic numbers.
 */

import type { AnalysisContext, Analyzer, AnalyzerFinding, CategoryResult } from './types.js';

export function createQualityAnalyzer(): Analyzer {
  return {
    category: 'quality',
    name: 'Code Quality',
    maxPoints: 20,

    async analyze(context: AnalysisContext): Promise<CategoryResult> {
      const findings: AnalyzerFinding[] = [];

      // Track deductions per rule with global caps (max deduction from plan)
      const RULE_CAPS: Record<string, number> = {
        'QUAL-001': 4, // cyclomatic complexity
        'QUAL-002': 2, // function length
        'QUAL-003': 1, // file length
        'QUAL-004': 3, // TS anti-patterns
        'QUAL-005': 2, // React anti-patterns
        'QUAL-006': 2, // .NET anti-patterns
        'QUAL-007': 2, // SQL anti-patterns
        'QUAL-008': 1, // nested complexity
        'QUAL-009': 1, // debug statements
        'QUAL-010': 2, // magic numbers
      };
      const ruleDeductions = new Map<string, number>();

      function addDeduction(ruleId: string, amount: number): number {
        const current = ruleDeductions.get(ruleId) ?? 0;
        const cap = RULE_CAPS[ruleId] ?? 2;
        const available = Math.max(0, cap - current);
        const actual = Math.min(amount, available);
        ruleDeductions.set(ruleId, current + actual);
        return actual;
      }

      for (const [filePath, content] of context.files) {
        if (!isCodeFile(filePath)) continue;

        checkCyclomaticComplexity(filePath, content, context, findings);
        checkFunctionLength(filePath, content, context, findings);
        checkFileLength(filePath, content, context, findings);
        checkTSAntiPatterns(filePath, content, findings);

        if (context.stackTags.has('react')) {
          checkReactAntiPatterns(filePath, content, findings);
        }
        if (filePath.endsWith('.cs')) {
          checkDotNetAntiPatterns(filePath, content, findings);
        }
        if (filePath.endsWith('.sql')) {
          checkSQLAntiPatterns(filePath, content, findings);
        }

        checkNestedComplexity(filePath, content, findings);
        checkDebugStatements(filePath, content, findings);
        checkMagicNumbers(filePath, content, findings);
      }

      // Apply global rule caps to deductions
      let deductions = 0;
      for (const finding of findings) {
        const actual = addDeduction(finding.ruleId, finding.deduction);
        deductions += actual;
      }

      const score = Math.max(0, 20 - deductions);

      return {
        category: 'quality',
        name: 'Code Quality',
        maxPoints: 20,
        score,
        isNA: false,
        findings,
      };
    },
  };
}

function isCodeFile(path: string): boolean {
  return (
    path.endsWith('.ts') ||
    path.endsWith('.tsx') ||
    path.endsWith('.js') ||
    path.endsWith('.jsx') ||
    path.endsWith('.cs') ||
    path.endsWith('.sql')
  );
}

function isTestFile(path: string): boolean {
  return (
    path.includes('.test.') ||
    path.includes('.spec.') ||
    path.includes('__tests__') ||
    path.includes('/tests/')
  );
}

function isBenchmarkFile(path: string): boolean {
  return path.includes('/benchmarks/') || path.includes('benchmarks/');
}

function isAnalyzerSourceFile(path: string): boolean {
  return (
    path.includes('analyzers/') && (path.endsWith('-analyzer.ts') || path.endsWith('-analyzer.js'))
  );
}

// Branch patterns for cyclomatic complexity counting
const BRANCH_PATTERNS = [
  /\bif\s*\(/g,
  /\belse\s+if\s*\(/g,
  /\bfor\s*\(/g,
  /\bwhile\s*\(/g,
  /\bcase\s+/g,
  /\bcatch\s*\(/g,
  /&&/g,
  /\|\|/g,
  /\?\?/g,
  /(?<!\?)\?(?!\?|\.)[^?:]/g, // ternary (excludes ?. and ??)
];

const CONTROL_FLOW_KEYWORDS = new Set(['if', 'for', 'while', 'switch', 'catch', 'else']);

function extractFunctionBody(content: string, startPos: number): string | null {
  let braceCount = 0;
  let started = false;
  for (let i = startPos; i < content.length && i < startPos + 5000; i++) {
    if (content[i] === '{') {
      braceCount++;
      started = true;
    } else if (content[i] === '}') {
      braceCount--;
      if (started && braceCount === 0) return content.slice(startPos, i + 1);
    }
  }
  return null;
}

function countBranchPoints(body: string): number {
  let complexity = 1;
  for (const pattern of BRANCH_PATTERNS) {
    const matches = body.match(pattern);
    if (matches) complexity += matches.length;
  }
  return complexity;
}

function checkCyclomaticComplexity(
  filePath: string,
  content: string,
  context: AnalysisContext,
  findings: AnalyzerFinding[],
): number {
  const threshold = context.config.maxCyclomaticComplexity;
  let total = 0;

  const funcPattern =
    /(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:\([^)]*\)|[^=])\s*=>|(\w+)\s*\([^)]*\)\s*\{)/g;
  let match: RegExpExecArray | null;

  // biome-ignore lint/suspicious/noAssignInExpressions: regex iteration pattern
  while ((match = funcPattern.exec(content)) !== null) {
    const rawName = match[1] || match[2] || match[3] || 'anonymous';
    if (CONTROL_FLOW_KEYWORDS.has(rawName)) continue;

    const body = extractFunctionBody(content, match.index);
    if (!body) continue;

    const complexity = countBranchPoints(body);
    if (complexity > threshold) {
      total += 0.5;
      findings.push({
        ruleId: 'QUAL-001',
        title: 'High cyclomatic complexity',
        description: `${filePath}: function "${rawName}" has complexity ${complexity} (threshold: ${threshold})`,
        severity: complexity > threshold * 2 ? 'critical' : 'major',
        filePath,
        suggestion: `Extract conditional branches into separate functions or use strategy pattern.`,
        deduction: 0.5,
        fixable: true,
        fixType: 'extract-function',
      });
    }
  }

  return Math.min(total, 4);
}

function checkFunctionLength(
  filePath: string,
  content: string,
  context: AnalysisContext,
  findings: AnalyzerFinding[],
): number {
  if (isBenchmarkFile(filePath)) return 0;
  const threshold = context.config.maxFunctionLength;
  let total = 0;

  const CONTROL_FLOW_KEYWORDS = new Set(['if', 'for', 'while', 'switch', 'catch', 'else']);
  const funcPattern =
    /(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:\([^)]*\)|[^=])\s*=>)/g;
  let match: RegExpExecArray | null;

  // biome-ignore lint/suspicious/noAssignInExpressions: regex iteration pattern
  while ((match = funcPattern.exec(content)) !== null) {
    const rawName = match[1] || match[2] || 'anonymous';
    if (CONTROL_FLOW_KEYWORDS.has(rawName)) continue;
    const funcName = rawName;
    const startLine = content.slice(0, match.index).split('\n').length;

    // Find end of function
    let braceCount = 0;
    let started = false;
    let endLine = startLine;

    for (let i = match.index; i < content.length; i++) {
      if (content[i] === '{') {
        braceCount++;
        started = true;
      } else if (content[i] === '}') {
        braceCount--;
        if (started && braceCount === 0) {
          endLine = content.slice(0, i).split('\n').length;
          break;
        }
      }
    }

    const length = endLine - startLine + 1;
    if (length > threshold) {
      total += 0.25;
      findings.push({
        ruleId: 'QUAL-002',
        title: 'Long function',
        description: `${filePath}: function "${funcName}" is ${length} lines (threshold: ${threshold})`,
        severity: 'minor',
        filePath,
        line: startLine,
        suggestion: `Extract logical blocks into smaller helper functions.`,
        deduction: 0.25,
        fixable: true,
        fixType: 'extract-function',
      });
    }
  }

  return Math.min(total, 2);
}

function checkFileLength(
  filePath: string,
  content: string,
  context: AnalysisContext,
  findings: AnalyzerFinding[],
): number {
  // Test files and benchmarks are naturally large — skip
  if (isTestFile(filePath) || isBenchmarkFile(filePath)) return 0;
  const threshold = context.config.maxFileLength;
  const lines = content.split('\n').length;

  if (lines > threshold) {
    findings.push({
      ruleId: 'QUAL-003',
      title: 'Long file',
      description: `${filePath} is ${lines} lines (threshold: ${threshold})`,
      severity: 'minor',
      filePath,
      suggestion: `Split into multiple focused modules.`,
      deduction: 0.25,
      fixable: true,
      fixType: 'extract-function',
    });
    return 0.25;
  }

  return 0;
}

function checkTSAntiPatterns(
  filePath: string,
  content: string,
  findings: AnalyzerFinding[],
): number {
  if (!filePath.endsWith('.ts') && !filePath.endsWith('.tsx')) return 0;
  // Skip analyzer source files to avoid self-detection (patterns in regex definitions)
  if (isAnalyzerSourceFile(filePath)) return 0;
  // Skip test files — they intentionally contain anti-patterns as test fixtures
  if (isTestFile(filePath)) return 0;

  let total = 0;
  const patterns: Array<{
    pattern: RegExp;
    title: string;
    severity: 'critical' | 'major' | 'minor' | 'info';
  }> = [
    { pattern: /\bas\s+any\b/g, title: 'as any cast', severity: 'major' },
    { pattern: /@ts-ignore/g, title: '@ts-ignore directive', severity: 'major' },
    { pattern: /@ts-nocheck/g, title: '@ts-nocheck directive', severity: 'major' },
    { pattern: /\beval\s*\(/g, title: 'eval() usage', severity: 'critical' },
    { pattern: /\w!\./g, title: 'non-null assertion', severity: 'minor' },
  ];

  for (const { pattern, title, severity } of patterns) {
    const matches = content.match(pattern);
    if (matches && matches.length > 0) {
      // Filter out matches that have biome-ignore or eslint-disable comments nearby
      const lines = content.split('\n');
      let unsuppressedCount = 0;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i] ?? '';
        if (pattern.test(line)) {
          const prevLine = lines[i - 1] ?? '';
          if (!prevLine.includes('biome-ignore') && !prevLine.includes('eslint-disable')) {
            unsuppressedCount++;
          }
        }
        // Reset lastIndex for global regex
        pattern.lastIndex = 0;
      }

      if (unsuppressedCount > 0) {
        const deduction = Math.min(unsuppressedCount * 0.15, 1);
        total += deduction;
        findings.push({
          ruleId: 'QUAL-004',
          title: `TS anti-pattern: ${title}`,
          description: `${filePath}: ${unsuppressedCount} occurrence(s) of ${title}`,
          severity,
          filePath,
          suggestion: `Replace with proper type narrowing or explicit types.`,
          deduction,
          fixable: true,
          fixType: 'replace-pattern',
        });
      }
    }
  }

  return Math.min(total, 3);
}

function checkReactAntiPatterns(
  filePath: string,
  content: string,
  findings: AnalyzerFinding[],
): number {
  if (!filePath.endsWith('.tsx') && !filePath.endsWith('.jsx')) return 0;

  let total = 0;

  // Giant useEffect (more than 20 lines)
  const effectPattern = /useEffect\s*\(\s*(?:async\s*)?\(\)\s*=>\s*\{/g;
  let match: RegExpExecArray | null;

  // biome-ignore lint/suspicious/noAssignInExpressions: regex iteration pattern
  while ((match = effectPattern.exec(content)) !== null) {
    let braceCount = 0;
    let started = false;
    let length = 0;

    for (let i = match.index; i < content.length; i++) {
      if (content[i] === '{') {
        braceCount++;
        started = true;
      } else if (content[i] === '}') {
        braceCount--;
        if (started && braceCount === 0) {
          length = content.slice(match.index, i).split('\n').length;
          break;
        }
      }
    }

    if (length > 20) {
      total += 0.5;
      findings.push({
        ruleId: 'QUAL-005',
        title: 'Giant useEffect',
        description: `${filePath}: useEffect with ${length} lines — extract into custom hook`,
        severity: 'major',
        filePath,
        suggestion: `Extract effect logic into a custom hook for reusability and testability.`,
        deduction: 0.5,
        fixable: true,
        fixType: 'extract-function',
      });
    }
  }

  // Inline object props: prop={{
  const inlineProps = content.match(/\w+=\{\{/g);
  if (inlineProps && inlineProps.length > 3) {
    total += 0.25;
    findings.push({
      ruleId: 'QUAL-005',
      title: 'Inline object props',
      description: `${filePath}: ${inlineProps.length} inline object props causing unnecessary re-renders`,
      severity: 'minor',
      filePath,
      suggestion: `Extract inline objects to constants or useMemo.`,
      deduction: 0.25,
      fixable: true,
      fixType: 'extract-function',
    });
  }

  return Math.min(total, 2);
}

function checkDotNetAntiPatterns(
  filePath: string,
  content: string,
  findings: AnalyzerFinding[],
): number {
  let total = 0;

  const patterns: Array<{ pattern: RegExp; title: string; deduction: number }> = [
    { pattern: /catch\s*\(\s*\w*\s*\)\s*\{\s*\}/g, title: 'Empty catch block', deduction: 0.5 },
    { pattern: /Thread\.Sleep/g, title: 'Thread.Sleep usage', deduction: 0.25 },
    { pattern: /GC\.Collect/g, title: 'GC.Collect usage', deduction: 0.25 },
    { pattern: /async\s+void\b/g, title: 'async void method', deduction: 0.5 },
  ];

  for (const { pattern, title, deduction } of patterns) {
    const matches = content.match(pattern);
    if (matches) {
      total += deduction;
      findings.push({
        ruleId: 'QUAL-006',
        title: `.NET anti-pattern: ${title}`,
        description: `${filePath}: ${matches.length} occurrence(s)`,
        severity: 'major',
        filePath,
        suggestion: `Review and fix the anti-pattern.`,
        deduction,
        fixable: true,
        fixType: 'replace-pattern',
      });
    }
  }

  return Math.min(total, 2);
}

function checkSQLAntiPatterns(
  filePath: string,
  content: string,
  findings: AnalyzerFinding[],
): number {
  let total = 0;

  const patterns: Array<{ pattern: RegExp; title: string; deduction: number }> = [
    { pattern: /SELECT\s+\*/gi, title: 'SELECT *', deduction: 0.25 },
    { pattern: /\bCURSOR\b/gi, title: 'Cursor usage', deduction: 0.5 },
    { pattern: /\bNOLOCK\b/gi, title: 'NOLOCK hint', deduction: 0.25 },
    { pattern: /\bGOTO\b/gi, title: 'GOTO statement', deduction: 0.5 },
  ];

  for (const { pattern, title, deduction } of patterns) {
    const matches = content.match(pattern);
    if (matches) {
      total += deduction;
      findings.push({
        ruleId: 'QUAL-007',
        title: `SQL anti-pattern: ${title}`,
        description: `${filePath}: ${matches.length} occurrence(s)`,
        severity: 'minor',
        filePath,
        suggestion: `Review SQL patterns for best practices.`,
        deduction,
        fixable: true,
        fixType: 'replace-pattern',
      });
    }
  }

  return Math.min(total, 2);
}

function checkNestedComplexity(
  filePath: string,
  content: string,
  findings: AnalyzerFinding[],
): number {
  let total = 0;

  // Nested ternaries — exclude ?. (optional chaining) and ?? (nullish coalescing)
  const nestedTernary = /(?<!\?)\?(?!\?|\.)(?:[^:?]*?)(?<!\?)\?(?!\?|\.)(?:[^:]*?):/g;
  const ternaryMatches = content.match(nestedTernary);
  if (ternaryMatches) {
    total += 0.25;
    findings.push({
      ruleId: 'QUAL-008',
      title: 'Nested ternary',
      description: `${filePath}: ${ternaryMatches.length} nested ternary expression(s)`,
      severity: 'minor',
      filePath,
      suggestion: `Replace nested ternaries with if/else blocks or extract to helper functions.`,
      deduction: 0.25,
      fixable: true,
      fixType: 'extract-function',
    });
  }

  // Deep nesting (>4 levels) — track brace depth paired with control flow
  const lines = content.split('\n');
  let maxNesting = 0;
  let braceDepth = 0;
  const controlFlowBraceDepths: number[] = [];

  for (const line of lines) {
    const trimmed = line.trim();

    // Track control flow that opens a brace block
    if (/^(if|for|while|switch)\s*\(/.test(trimmed)) {
      // Will push to stack when we see the opening brace
      if (trimmed.includes('{')) {
        braceDepth++;
        controlFlowBraceDepths.push(braceDepth);
        maxNesting = Math.max(maxNesting, controlFlowBraceDepths.length);
      }
    } else {
      // Count braces on non-control-flow lines
      for (const ch of trimmed) {
        if (ch === '{') {
          braceDepth++;
        } else if (ch === '}') {
          // If this closing brace matches a control flow depth, pop it
          if (
            controlFlowBraceDepths.length > 0 &&
            controlFlowBraceDepths[controlFlowBraceDepths.length - 1] === braceDepth
          ) {
            controlFlowBraceDepths.pop();
          }
          braceDepth = Math.max(0, braceDepth - 1);
        }
      }
    }
  }

  if (maxNesting > 4) {
    total += 0.5;
    findings.push({
      ruleId: 'QUAL-008',
      title: 'Deeply nested control flow',
      description: `${filePath}: nesting depth ${maxNesting} (max recommended: 4)`,
      severity: 'major',
      filePath,
      suggestion: `Use early returns, guard clauses, or extract nested logic.`,
      deduction: 0.5,
      fixable: true,
      fixType: 'extract-function',
    });
  }

  return Math.min(total, 1);
}

function isCliOutputFile(path: string): boolean {
  return (
    path.includes('/cli/') ||
    path.includes('/hooks/') ||
    path.includes('/daemon/') ||
    path.includes('/mcp/')
  );
}

function checkDebugStatements(
  filePath: string,
  content: string,
  findings: AnalyzerFinding[],
): number {
  if (isTestFile(filePath) || isBenchmarkFile(filePath)) return 0;
  // CLI commands, hooks, and daemon processes legitimately output to console
  if (isCliOutputFile(filePath)) return 0;

  const debugPatterns = /console\.(log|debug|info)\s*\(/g;
  const matches = content.match(debugPatterns);

  if (matches && matches.length > 3) {
    const deduction = Math.min(matches.length * 0.05, 0.5);
    findings.push({
      ruleId: 'QUAL-009',
      title: 'Debug statements in production code',
      description: `${filePath}: ${matches.length} console.log/debug/info calls`,
      severity: 'minor',
      filePath,
      suggestion: `Replace with a proper logger or remove debug statements.`,
      deduction,
      fixable: true,
      fixType: 'remove-code',
    });
    return deduction;
  }

  return 0;
}

const SKIP_LINE_PREFIXES = [
  '//',
  '*',
  '/*',
  'const ',
  'let ',
  'var ',
  'enum ',
  'import ',
  'export const ',
  'export let ',
  'export enum ',
  'return ',
];

const SKIP_LINE_INCLUDES = ['default:', 'case ', 'type ', 'interface '];

const COMMON_NUMBERS = new Set([
  0, 1, 2, 3, 4, 5, 8, 10, 12, 16, 24, 32, 50, 60, 64, 80, 100, 128, 200, 256, 300, 400, 404, 500,
  512, 1000, 1024, 2000, 3000, 4096, 5000, 8080, 8000, 9000,
]);

function isNonMagicContext(trimmed: string): boolean {
  if (SKIP_LINE_PREFIXES.some((p) => trimmed.startsWith(p))) return true;
  if (SKIP_LINE_INCLUDES.some((p) => trimmed.includes(p))) return true;
  if (/^\s*\d+\s*[,\]]/.test(trimmed)) return true; // array literals
  if (/^\s*['"`]/.test(trimmed)) return true; // string literals
  if (/:\s*\d/.test(trimmed)) return true; // object property values
  return false;
}

function checkMagicNumbers(filePath: string, content: string, findings: AnalyzerFinding[]): number {
  if (
    isTestFile(filePath) ||
    isBenchmarkFile(filePath) ||
    isAnalyzerSourceFile(filePath) ||
    filePath.endsWith('.json') ||
    filePath.endsWith('.sql')
  )
    return 0;

  const lines = content.split('\n');
  let magicCount = 0;

  for (const line of lines) {
    const trimmed = line.trim();
    if (isNonMagicContext(trimmed)) continue;

    const numbers = trimmed.match(/(?<!\w)\d{2,}(?!\w)/g);
    if (numbers) {
      for (const num of numbers) {
        const n = Number.parseInt(num, 10);
        if (!COMMON_NUMBERS.has(n) && n > 2) {
          magicCount++;
        }
      }
    }
  }

  if (magicCount > 5) {
    const deduction = Math.min(magicCount * 0.05, 1);
    findings.push({
      ruleId: 'QUAL-010',
      title: 'Magic numbers',
      description: `${filePath}: ${magicCount} magic number(s) — use named constants`,
      severity: 'minor',
      filePath,
      suggestion: `Extract magic numbers into named constants for clarity.`,
      deduction,
      fixable: true,
      fixType: 'replace-pattern',
    });
    return deduction;
  }

  return 0;
}
