/**
 * Auto-fix engine for analyzer findings — applies safe automated fixes.
 * Follows the same pattern as src/core/secure/auto-fix.ts.
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { AnalyzerFinding } from './types.js';

export interface AnalyzerFixAction {
  ruleId: string;
  file: string;
  description: string;
  preview: string[];
  apply: () => boolean;
}

type FixFactory = (
  projectRoot: string,
  finding: AnalyzerFinding,
) => AnalyzerFixAction | null;

const SAFE_FIXES: Record<string, FixFactory> = {
  'QUAL-009': fixDebugStatements,
  'SEC-003': fixWeakCrypto,
  'QUAL-004': fixTsIgnoreComments,
  'SEC-004': fixCorsWildcard,
};

/**
 * QUAL-009: Remove console.log/debug/info and debugger statements (full lines only).
 */
function fixDebugStatements(
  projectRoot: string,
  finding: AnalyzerFinding,
): AnalyzerFixAction | null {
  if (!finding.filePath) return null;
  const filePath = join(projectRoot, finding.filePath);
  if (!existsSync(filePath)) return null;

  const content = readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');
  const debugPattern = /^\s*(console\.(log|debug|warn|info)\s*\(.*\);?\s*|debugger;?\s*)$/;
  const targets: Array<{ line: number; text: string }> = [];

  for (let i = 0; i < lines.length; i++) {
    if (debugPattern.test(lines[i]!)) {
      targets.push({ line: i + 1, text: lines[i]!.trim() });
    }
  }

  if (targets.length === 0) return null;

  return {
    ruleId: 'QUAL-009',
    file: finding.filePath,
    description: `Remove ${targets.length} debug statement(s)`,
    preview: targets.map((t) => `L${t.line}: ${t.text}`),
    apply: () => {
      try {
        const current = readFileSync(filePath, 'utf-8');
        const currentLines = current.split('\n');
        const filtered = currentLines.filter((line) => !debugPattern.test(line));
        writeFileSync(filePath, filtered.join('\n'), 'utf-8');
        return true;
      } catch {
        return false;
      }
    },
  };
}

/**
 * SEC-003: Replace weak crypto MD5/SHA1 → SHA-256.
 */
function fixWeakCrypto(
  projectRoot: string,
  finding: AnalyzerFinding,
): AnalyzerFixAction | null {
  if (!finding.filePath) return null;
  const filePath = join(projectRoot, finding.filePath);
  if (!existsSync(filePath)) return null;

  const content = readFileSync(filePath, 'utf-8');
  const replacements: string[] = [];

  if (/createHash\s*\(\s*['"]md5['"]\s*\)/.test(content)) {
    replacements.push('MD5 -> SHA-256');
  }
  if (/createHash\s*\(\s*['"]sha1['"]\s*\)/.test(content)) {
    replacements.push('SHA1 -> SHA-256');
  }

  if (replacements.length === 0) return null;

  return {
    ruleId: 'SEC-003',
    file: finding.filePath,
    description: `Replace weak crypto: ${replacements.join(', ')}`,
    preview: replacements,
    apply: () => {
      try {
        let current = readFileSync(filePath, 'utf-8');
        current = current.replace(
          /createHash\s*\(\s*['"]md5['"]\s*\)/g,
          "createHash('sha256')",
        );
        current = current.replace(
          /createHash\s*\(\s*['"]sha1['"]\s*\)/g,
          "createHash('sha256')",
        );
        writeFileSync(filePath, current, 'utf-8');
        return true;
      } catch {
        return false;
      }
    },
  };
}

/**
 * QUAL-004 (partial): Remove @ts-ignore and @ts-nocheck comments.
 */
function fixTsIgnoreComments(
  projectRoot: string,
  finding: AnalyzerFinding,
): AnalyzerFixAction | null {
  if (!finding.filePath) return null;
  // Only handle ts-ignore/ts-nocheck, not other QUAL-004 patterns
  if (!finding.title.includes('ts-ignore') && !finding.title.includes('ts-nocheck')) {
    return null;
  }

  const filePath = join(projectRoot, finding.filePath);
  if (!existsSync(filePath)) return null;

  const content = readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');
  const tsIgnorePattern = /^\s*\/\/\s*@ts-(ignore|nocheck)\s*$/;
  const targets: Array<{ line: number; text: string }> = [];

  for (let i = 0; i < lines.length; i++) {
    if (tsIgnorePattern.test(lines[i]!)) {
      targets.push({ line: i + 1, text: lines[i]!.trim() });
    }
  }

  if (targets.length === 0) return null;

  return {
    ruleId: 'QUAL-004',
    file: finding.filePath,
    description: `Remove ${targets.length} @ts-ignore/@ts-nocheck comment(s)`,
    preview: targets.map((t) => `L${t.line}: ${t.text}`),
    apply: () => {
      try {
        const current = readFileSync(filePath, 'utf-8');
        const currentLines = current.split('\n');
        const filtered = currentLines.filter((line) => !tsIgnorePattern.test(line));
        writeFileSync(filePath, filtered.join('\n'), 'utf-8');
        return true;
      } catch {
        return false;
      }
    },
  };
}

/**
 * SEC-004: Replace CORS wildcard * → placeholder.
 */
function fixCorsWildcard(
  projectRoot: string,
  finding: AnalyzerFinding,
): AnalyzerFixAction | null {
  if (!finding.filePath) return null;
  const filePath = join(projectRoot, finding.filePath);
  if (!existsSync(filePath)) return null;

  const content = readFileSync(filePath, 'utf-8');
  const corsPattern = /(origin\s*:\s*)['"]?\*['"]?/g;

  if (!corsPattern.test(content)) return null;

  return {
    ruleId: 'SEC-004',
    file: finding.filePath,
    description: 'Replace CORS wildcard * with placeholder',
    preview: ["origin: '*' -> origin: 'https://your-domain.com'"],
    apply: () => {
      try {
        let current = readFileSync(filePath, 'utf-8');
        current = current.replace(
          /(origin\s*:\s*)['"]?\*['"]?/g,
          "$1'https://your-domain.com'",
        );
        writeFileSync(filePath, current, 'utf-8');
        return true;
      } catch {
        return false;
      }
    },
  };
}

/**
 * Collect all fixable actions from findings without applying anything.
 */
export function collectFixableActions(
  projectRoot: string,
  findings: AnalyzerFinding[],
): AnalyzerFixAction[] {
  const actions: AnalyzerFixAction[] = [];
  const seen = new Set<string>();

  for (const finding of findings) {
    if (!finding.fixable) continue;

    const factory = SAFE_FIXES[finding.ruleId];
    if (!factory) continue;

    const action = factory(projectRoot, finding);
    if (!action) continue;

    // Deduplicate by ruleId + file
    const key = `${action.ruleId}:${action.file}`;
    if (seen.has(key)) continue;
    seen.add(key);

    actions.push(action);
  }

  return actions;
}

/**
 * Apply a single fix action, returns success status.
 */
export function applyFixAction(action: AnalyzerFixAction): boolean {
  try {
    return action.apply();
  } catch {
    return false;
  }
}
