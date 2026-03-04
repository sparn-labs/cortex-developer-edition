/**
 * Auto-fix engine for cortex secure — applies safe automated fixes.
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { SecureFinding } from './types.js';

export interface AutoFixResult {
  applied: number;
  skipped: number;
  details: Array<{
    findingId: string;
    file: string;
    action: string;
    success: boolean;
  }>;
}

const SAFE_FIXES: Record<
  string,
  (projectRoot: string, finding: SecureFinding) => FixAction | null
> = {
  'SEC-CR-001': fixWeakHash,
  'SEC-CR-005': fixMathRandom,
  'SEC-SC-003': fixDependencyPinning,
  'SEC-AC-007': fixCookieFlags,
  'SEC-MC-005': fixSourceMaps,
};

interface FixAction {
  file: string;
  description: string;
  apply: () => boolean;
}

function fixWeakHash(projectRoot: string, finding: SecureFinding): FixAction | null {
  const filePath = join(projectRoot, finding.evidence.file);
  if (!existsSync(filePath)) return null;

  return {
    file: finding.evidence.file,
    description: 'Replace MD5/SHA1 with SHA-256',
    apply: () => {
      try {
        let content = readFileSync(filePath, 'utf-8');
        let changed = false;

        if (content.includes("createHash('md5')")) {
          content = content.replace(/createHash\s*\(\s*['"]md5['"]\s*\)/g, "createHash('sha256')");
          changed = true;
        }
        if (content.includes("createHash('sha1')")) {
          content = content.replace(/createHash\s*\(\s*['"]sha1['"]\s*\)/g, "createHash('sha256')");
          changed = true;
        }

        if (changed) {
          writeFileSync(filePath, content, 'utf-8');
          return true;
        }
        return false;
      } catch {
        return false;
      }
    },
  };
}

function fixMathRandom(projectRoot: string, finding: SecureFinding): FixAction | null {
  const filePath = join(projectRoot, finding.evidence.file);
  if (!existsSync(filePath)) return null;

  return {
    file: finding.evidence.file,
    description: 'Replace Math.random() with crypto.randomUUID()',
    apply: () => {
      try {
        let content = readFileSync(filePath, 'utf-8');

        if (content.includes('Math.random()')) {
          // Add crypto import if not present
          if (!/import.*crypto|require.*crypto/.test(content)) {
            content = `import { randomUUID } from 'node:crypto';\n${content}`;
          }
          content = content.replace(/Math\.random\s*\(\s*\)/g, 'randomUUID()');
          writeFileSync(filePath, content, 'utf-8');
          return true;
        }
        return false;
      } catch {
        return false;
      }
    },
  };
}

function fixDependencyPinning(projectRoot: string, _finding: SecureFinding): FixAction | null {
  const pkgPath = join(projectRoot, 'package.json');
  if (!existsSync(pkgPath)) return null;

  return {
    file: 'package.json',
    description: 'Pin dependency versions (remove ^ and ~)',
    apply: () => {
      try {
        const content = readFileSync(pkgPath, 'utf-8');
        const pkg = JSON.parse(content);
        let changed = false;

        for (const section of ['dependencies', 'devDependencies']) {
          const deps = pkg[section];
          if (!deps) continue;

          for (const [name, version] of Object.entries(deps)) {
            if (typeof version === 'string' && /^[\^~]/.test(version)) {
              deps[name] = version.replace(/^[\^~]/, '');
              changed = true;
            }
          }
        }

        if (changed) {
          writeFileSync(pkgPath, `${JSON.stringify(pkg, null, 2)}\n`, 'utf-8');
          return true;
        }
        return false;
      } catch {
        return false;
      }
    },
  };
}

function fixCookieFlags(projectRoot: string, finding: SecureFinding): FixAction | null {
  const filePath = join(projectRoot, finding.evidence.file);
  if (!existsSync(filePath)) return null;

  return {
    file: finding.evidence.file,
    description: 'Add httpOnly, secure, SameSite to cookie configuration',
    apply: () => {
      try {
        let content = readFileSync(filePath, 'utf-8');
        let changed = false;

        // Add missing cookie flags in cookie configuration objects
        const cookieObjPattern = /(cookie\s*:\s*\{[^}]*)(})/gi;
        content = content.replace(cookieObjPattern, (match, before, after) => {
          let additions = '';
          if (!/httpOnly/.test(before)) additions += ', httpOnly: true';
          if (!/secure\s*:/.test(before)) additions += ', secure: true';
          if (!/sameSite/.test(before)) additions += ", sameSite: 'strict'";

          if (additions) {
            changed = true;
            return `${before}${additions} ${after}`;
          }
          return match;
        });

        if (changed) {
          writeFileSync(filePath, content, 'utf-8');
          return true;
        }
        return false;
      } catch {
        return false;
      }
    },
  };
}

function fixSourceMaps(projectRoot: string, finding: SecureFinding): FixAction | null {
  const filePath = join(projectRoot, finding.evidence.file);
  if (!existsSync(filePath)) return null;

  return {
    file: finding.evidence.file,
    description: 'Disable source maps in production config',
    apply: () => {
      try {
        let content = readFileSync(filePath, 'utf-8');

        if (/devtool\s*:\s*['"]source-map['"]/.test(content)) {
          content = content.replace(
            /devtool\s*:\s*['"]source-map['"]/g,
            "devtool: process.env.NODE_ENV === 'production' ? false : 'source-map'",
          );
          writeFileSync(filePath, content, 'utf-8');
          return true;
        }
        return false;
      } catch {
        return false;
      }
    },
  };
}

function addGitignoreEntries(projectRoot: string): FixAction {
  return {
    file: '.gitignore',
    description: 'Add sensitive file patterns to .gitignore',
    apply: () => {
      const gitignorePath = join(projectRoot, '.gitignore');
      const entries = ['.env', '.env.*', '*.pem', '*.key', '*.p12', 'credentials.json'];

      try {
        let content = existsSync(gitignorePath) ? readFileSync(gitignorePath, 'utf-8') : '';
        let added = false;

        for (const entry of entries) {
          if (!content.includes(entry)) {
            content += `\n${entry}`;
            added = true;
          }
        }

        if (added) {
          writeFileSync(gitignorePath, `${content.trim()}\n`, 'utf-8');
          return true;
        }
        return false;
      } catch {
        return false;
      }
    },
  };
}

export function applyAutoFixes(projectRoot: string, findings: SecureFinding[]): AutoFixResult {
  const result: AutoFixResult = { applied: 0, skipped: 0, details: [] };

  // Apply finding-specific fixes
  for (const finding of findings) {
    if (!finding.fix.automated) continue;

    const fixFactory = SAFE_FIXES[finding.id];
    if (!fixFactory) {
      result.skipped++;
      continue;
    }

    const action = fixFactory(projectRoot, finding);
    if (!action) {
      result.skipped++;
      continue;
    }

    const success = action.apply();
    result.details.push({
      findingId: finding.id,
      file: action.file,
      action: action.description,
      success,
    });

    if (success) result.applied++;
    else result.skipped++;
  }

  // Always add gitignore entries for sensitive files
  const hasSensitiveFileFindings = findings.some((f) => f.id === 'SEC-CR-002');
  if (hasSensitiveFileFindings) {
    const gitignoreFix = addGitignoreEntries(projectRoot);
    const success = gitignoreFix.apply();
    result.details.push({
      findingId: 'SEC-CR-002',
      file: gitignoreFix.file,
      action: gitignoreFix.description,
      success,
    });
    if (success) result.applied++;
  }

  return result;
}
