/**
 * .cortexignore parser and matcher.
 *
 * Supports glob patterns to exclude files from analysis.
 * Optionally limits ignores to specific rule IDs:
 *   src/legacy/**              ← ignore all rules
 *   src/legacy/** QUAL-001,QUAL-002  ← ignore only these rules
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

export interface IgnoreRule {
  pattern: string;
  regex: RegExp;
  ruleIds: string[] | null; // null = all rules
}

export interface CortexIgnore {
  isFileExcluded(relPath: string): boolean;
  isRuleSuppressed(relPath: string, ruleId: string): boolean;
  readonly rules: IgnoreRule[];
}

// Characters that need escaping in a RegExp
const REGEX_SPECIAL = /[$()+.[\]\\^{|}]/g;

/**
 * Convert a glob pattern to a RegExp.
 * Supports *, **, and ? wildcards.
 * Uses possessive-safe patterns to prevent ReDoS.
 */
function globToRegex(pattern: string): RegExp {
  let result = '';
  let i = 0;
  while (i < pattern.length) {
    const ch = pattern[i] as string;
    if (ch === '*') {
      if (pattern[i + 1] === '*') {
        // ** matches any number of path segments
        if (pattern[i + 2] === '/') {
          result += '(?:[^/]+/)*';
          i += 3;
        } else {
          // trailing ** — match everything remaining
          result += '.*';
          i += 2;
        }
      } else {
        // * matches anything except /
        result += '[^/]*';
        i++;
      }
    } else if (ch === '?') {
      result += '[^/]';
      i++;
    } else if (ch === '/') {
      result += '/';
      i++;
    } else {
      // Escape all regex-special characters
      result += ch.replace(REGEX_SPECIAL, '\\$&');
      i++;
    }
  }
  return new RegExp(`^${result}$`);
}

/**
 * Parse .cortexignore file content into rules.
 */
export function parseCortexIgnore(content: string): IgnoreRule[] {
  const rules: IgnoreRule[] = [];

  for (const rawLine of content.split('\n')) {
    const line = rawLine.trim();
    // Skip empty lines and comments
    if (!line || line.startsWith('#')) continue;

    // Check for rule-specific ignore: "pattern RULE-001,RULE-002"
    const spaceIdx = line.indexOf(' ');
    let pattern: string;
    let ruleIds: string[] | null = null;

    if (spaceIdx > 0) {
      const afterSpace = line.slice(spaceIdx + 1).trim();
      // If it looks like rule IDs (contains uppercase letters and dashes)
      if (/^[A-Z]+-\d+(,[A-Z]+-\d+)*$/.test(afterSpace)) {
        pattern = line.slice(0, spaceIdx);
        ruleIds = afterSpace.split(',').map((r) => r.trim());
      } else {
        pattern = line;
      }
    } else {
      pattern = line;
    }

    rules.push({
      pattern,
      regex: globToRegex(pattern),
      ruleIds,
    });
  }

  return rules;
}

/**
 * Create a CortexIgnore instance by reading .cortexignore at the project root
 * and merging with config excludePatterns.
 */
export function createCortexIgnore(
  projectRoot: string,
  configExcludePatterns: string[] = [],
): CortexIgnore {
  const rules: IgnoreRule[] = [];

  // Parse .cortexignore file if it exists
  const ignorePath = join(projectRoot, '.cortexignore');
  if (existsSync(ignorePath)) {
    try {
      const content = readFileSync(ignorePath, 'utf-8');
      rules.push(...parseCortexIgnore(content));
    } catch {
      // Skip unreadable file
    }
  }

  // Add config excludePatterns as glob rules (all rules)
  for (const pattern of configExcludePatterns) {
    // Config patterns are simple substring matches — convert to glob
    const globPattern = pattern.includes('*') ? pattern : `**/${pattern}/**`;
    rules.push({
      pattern: globPattern,
      regex: globToRegex(globPattern),
      ruleIds: null,
    });
  }

  function matchesAny(relPath: string, onlyFullExclude: boolean): IgnoreRule | undefined {
    for (const rule of rules) {
      if (onlyFullExclude && rule.ruleIds !== null) continue;
      if (rule.regex.test(relPath)) return rule;
    }
    return undefined;
  }

  return {
    rules,

    isFileExcluded(relPath: string): boolean {
      return matchesAny(relPath, true) !== undefined;
    },

    isRuleSuppressed(relPath: string, ruleId: string): boolean {
      for (const rule of rules) {
        if (rule.regex.test(relPath)) {
          if (rule.ruleIds === null) return true; // all rules excluded
          if (rule.ruleIds.includes(ruleId)) return true;
        }
      }
      return false;
    },
  };
}
