/**
 * Token Efficiency Analyzer (10 pts)
 *
 * Measures token waste ratio, context utilization, compression potential,
 * barrel files, oversized low-import files, and duplicate types.
 */

import { estimateTokens } from '../../utils/tokenizer.js';
import type { AnalysisContext, Analyzer, AnalyzerFinding, CategoryResult } from './types.js';

export function createTokenAnalyzer(): Analyzer {
  return {
    category: 'tokens',
    name: 'Token Efficiency',
    maxPoints: 10,

    async analyze(context: AnalysisContext): Promise<CategoryResult> {
      const findings: AnalyzerFinding[] = [];
      let deductions = 0;

      deductions += checkTokenWasteRatio(context, findings);
      deductions += checkContextUtilization(context, findings);
      deductions += checkCompressionPotential(context, findings);
      deductions += checkBarrelFiles(context, findings);
      deductions += checkOversizedLowImport(context, findings);
      deductions += checkDuplicateTypes(context, findings);

      const score = Math.max(0, 10 - deductions);

      return {
        category: 'tokens',
        name: 'Token Efficiency',
        maxPoints: 10,
        score,
        isNA: false,
        findings,
      };
    },
  };
}

function checkTokenWasteRatio(context: AnalysisContext, findings: AnalyzerFinding[]): number {
  // Token Waste Ratio: estimate redundant tokens (comments, blank lines, imports of unused)
  let totalTokens = 0;
  let wasteTokens = 0;

  for (const [filePath, content] of context.files) {
    if (!filePath.endsWith('.ts') && !filePath.endsWith('.tsx') && !filePath.endsWith('.js')) {
      continue;
    }

    const fileTokens = estimateTokens(content);
    totalTokens += fileTokens;

    // Count comment tokens
    const comments = content.match(/\/\/[^\n]*/g) || [];
    const blockComments = content.match(/\/\*[\s\S]*?\*\//g) || [];
    const commentText = [...comments, ...blockComments].join('\n');
    const commentTokens = estimateTokens(commentText);

    // Count blank line "tokens" (whitespace waste)
    const blankLines = content.split('\n').filter((l) => l.trim() === '').length;
    const blankWaste = Math.ceil(blankLines * 0.5);

    wasteTokens += commentTokens + blankWaste;
  }

  if (totalTokens === 0) return 0;

  const twr = wasteTokens / totalTokens;

  if (twr > 0.3) {
    findings.push({
      ruleId: 'TOK-001',
      title: 'High Token Waste Ratio',
      description: `TWR: ${(twr * 100).toFixed(1)}% — ${wasteTokens.toLocaleString()} of ${totalTokens.toLocaleString()} tokens are comments/whitespace`,
      severity: 'major',
      suggestion: `Remove excessive comments and blank lines to improve context efficiency.`,
      deduction: 1,
      fixable: true,
      fixType: 'refactor',
    });
    return 1;
  }

  if (twr > 0.2) {
    findings.push({
      ruleId: 'TOK-001',
      title: 'Moderate Token Waste Ratio',
      description: `TWR: ${(twr * 100).toFixed(1)}% — consider reducing comments/whitespace`,
      severity: 'minor',
      suggestion: `Review excessive documentation for conciseness.`,
      deduction: 0.5,
      fixable: true,
      fixType: 'refactor',
    });
    return 0.5;
  }

  return 0;
}

function checkContextUtilization(context: AnalysisContext, findings: AnalyzerFinding[]): number {
  // CUE: actual code tokens vs total tokens (including non-code files like .md, .json)
  let codeTokens = 0;
  let totalTokens = 0;

  for (const [filePath, content] of context.files) {
    const tokens = estimateTokens(content);
    totalTokens += tokens;

    if (
      filePath.endsWith('.ts') ||
      filePath.endsWith('.tsx') ||
      filePath.endsWith('.js') ||
      filePath.endsWith('.jsx') ||
      filePath.endsWith('.cs') ||
      filePath.endsWith('.sql')
    ) {
      codeTokens += tokens;
    }
  }

  if (totalTokens === 0) return 0;

  const cue = codeTokens / totalTokens;

  if (cue < 0.5) {
    findings.push({
      ruleId: 'TOK-002',
      title: 'Low Context Utilization',
      description: `CUE: ${(cue * 100).toFixed(1)}% — more than half of tokens are non-code (docs, config)`,
      severity: 'major',
      suggestion: `Consider separating documentation from code for more efficient context loading.`,
      deduction: 1,
      fixable: true,
      fixType: 'refactor',
    });
    return 1;
  }

  if (cue < 0.7) {
    findings.push({
      ruleId: 'TOK-002',
      title: 'Moderate Context Utilization',
      description: `CUE: ${(cue * 100).toFixed(1)}% — significant non-code token usage`,
      severity: 'minor',
      suggestion: `Review non-code files for context optimization.`,
      deduction: 0.5,
      fixable: true,
      fixType: 'refactor',
    });
    return 0.5;
  }

  return 0;
}

function checkCompressionPotential(context: AnalysisContext, findings: AnalyzerFinding[]): number {
  // CPS: hot path tokens as % of total
  const { hotPaths, totalTokens } = context.graphAnalysis;

  if (totalTokens === 0) return 0;

  let hotPathTokens = 0;
  for (const path of hotPaths) {
    const node = context.nodes.get(path);
    if (node) hotPathTokens += node.tokenEstimate;
  }

  const cps = hotPathTokens / totalTokens;

  if (cps < 0.05) {
    findings.push({
      ruleId: 'TOK-003',
      title: 'Low Compression Potential',
      description: `CPS: ${(cps * 100).toFixed(1)}% — hot paths represent very few tokens, limited optimization opportunity`,
      severity: 'info',
      suggestion: `Concentrate shared logic in hot paths for better context optimization.`,
      deduction: 0.5,
      fixable: true,
      fixType: 'refactor',
    });
    return 0.5;
  }

  if (cps > 0.4) {
    findings.push({
      ruleId: 'TOK-003',
      title: 'High token concentration in hot paths',
      description: `CPS: ${(cps * 100).toFixed(1)}% — hot paths are token-heavy, good compression target`,
      severity: 'minor',
      suggestion: `Consider splitting hot path modules to reduce context loading cost.`,
      deduction: 0.5,
      fixable: true,
      fixType: 'refactor',
    });
    return 0.5;
  }

  return 0;
}

function checkBarrelFiles(context: AnalysisContext, findings: AnalyzerFinding[]): number {
  let total = 0;

  for (const [filePath, content] of context.files) {
    if (!filePath.endsWith('index.ts') && !filePath.endsWith('index.js')) continue;

    const lines = content.split('\n').filter((l) => l.trim().length > 0);
    const exportLines = lines.filter((l) => l.trim().startsWith('export'));

    // If >80% of non-empty lines are re-exports
    if (lines.length > 3 && exportLines.length / lines.length > 0.8) {
      const allReExports = exportLines.every(
        (l) => /export\s+(?:type\s+)?\{.*\}\s+from/.test(l) || /export\s+\*\s+from/.test(l),
      );

      if (allReExports) {
        total += 0.5;
        findings.push({
          ruleId: 'TOK-004',
          title: 'Barrel file',
          description: `${filePath}: pure re-export barrel file (${exportLines.length} exports) — adds tokens without code`,
          severity: 'minor',
          filePath,
          suggestion: `Import directly from source modules to avoid loading unnecessary barrel file tokens.`,
          deduction: 0.5,
          fixable: true,
          fixType: 'refactor',
        });
      }
    }
  }

  return Math.min(total, 2);
}

function checkOversizedLowImport(context: AnalysisContext, findings: AnalyzerFinding[]): number {
  let total = 0;

  for (const [filePath, node] of context.nodes) {
    if (node.tokenEstimate > 2000 && node.callers.length <= 1) {
      // Skip CLI command files (lazy-loaded via dynamic import, naturally have 1 caller)
      if (isLazyLoadedOrStandalone(filePath)) continue;
      // Skip entry point files (CLI, daemon, MCP — naturally have 0 callers)
      if (isEntryPoint(filePath)) continue;
      total += 0.25;
      findings.push({
        ruleId: 'TOK-005',
        title: 'Oversized low-import file',
        description: `${filePath}: ${node.tokenEstimate} tokens but only ${node.callers.length} caller(s)`,
        severity: 'info',
        filePath,
        suggestion: `Consider if this file can be split or its unused parts removed.`,
        deduction: 0.25,
        fixable: true,
        fixType: 'extract-function',
      });
    }
  }

  return Math.min(total, 1);
}

function isLazyLoadedOrStandalone(filePath: string): boolean {
  // CLI commands are lazy-loaded via `await import()` from the CLI entry point
  if (filePath.startsWith('src/cli/commands/') || filePath.startsWith('src/cli/dashboard/')) {
    return true;
  }
  // Hook files are standalone entry points invoked externally
  if (filePath.startsWith('src/hooks/')) return true;
  // Test files are standalone (run by test runner, not imported)
  if (filePath.startsWith('tests/') || filePath.includes('.test.') || filePath.includes('.spec.')) {
    return true;
  }
  return false;
}

function isEntryPoint(filePath: string): boolean {
  const entryPoints = [
    'src/cli/index.ts',
    'src/daemon/index.ts',
    'src/mcp/index.ts',
    'src/index.ts',
  ];
  return entryPoints.includes(filePath);
}

// Common type names that are idiomatic per-component/per-module (not real duplicates)
const COMMON_TYPE_NAMES = new Set(['Props', 'State', 'Options', 'Config', 'Result', 'Context']);

function checkDuplicateTypes(context: AnalysisContext, findings: AnalyzerFinding[]): number {
  // Find type/interface declarations that appear in multiple source files
  const typeDeclarations = new Map<string, string[]>();

  for (const [filePath, content] of context.files) {
    if (!filePath.endsWith('.ts') && !filePath.endsWith('.tsx')) continue;
    // Skip test files — they commonly redeclare types for test isolation
    if (
      filePath.includes('.test.') ||
      filePath.includes('.spec.') ||
      filePath.startsWith('tests/')
    ) {
      continue;
    }

    // Match only actual type/interface declarations (not imports)
    const typeMatches = [...content.matchAll(/^(?:export\s+)?(?:type|interface)\s+(\w+)/gm)];

    for (const match of typeMatches) {
      const name = match[1];
      if (!name || COMMON_TYPE_NAMES.has(name)) continue;
      const existing = typeDeclarations.get(name) || [];
      existing.push(filePath);
      typeDeclarations.set(name, existing);
    }
  }

  const duplicates = [...typeDeclarations.entries()].filter(([, files]) => files.length > 1);

  if (duplicates.length > 3) {
    const deduction = Math.min(duplicates.length * 0.1, 1);
    const examples = duplicates
      .slice(0, 3)
      .map(([name, files]) => `${name} (${files.length} files)`)
      .join(', ');

    findings.push({
      ruleId: 'TOK-006',
      title: 'Duplicate type declarations',
      description: `${duplicates.length} types defined in multiple files: ${examples}`,
      severity: 'minor',
      suggestion: `Consolidate shared types into a single types file.`,
      deduction,
      fixable: true,
      fixType: 'remove-code',
    });

    return deduction;
  }

  return 0;
}
