/**
 * Layer 5 — Injection Prevention (12%)
 * OWASP A03:2025 — Injection
 */

import type { LayerResult, SecureFinding } from '../types.js';
import { getLayerName, getLayerWeight } from '../types.js';

const LAYER = 5;
const WEIGHT = getLayerWeight(LAYER);
const NAME = getLayerName(LAYER);

function isTestFile(path: string): boolean {
  return /\.(test|spec)\.|__tests__|\/tests\/|\/fixtures\/|benchmarks\/|\.bench\./i.test(path);
}

function isSecureFile(path: string): boolean {
  return /secure\/|layers\//.test(path) && path.endsWith('.ts');
}

function isNonCodeFile(path: string): boolean {
  return /\.md$|\.txt$|\.json$|\.ya?ml$|\/docs?\//i.test(path);
}

function isAnalyzerFile(path: string): boolean {
  return (
    /analyzers\//.test(path) && (path.endsWith('-analyzer.ts') || path.endsWith('-analyzer.js'))
  );
}

function getLineNumber(content: string, index: number): number {
  return content.substring(0, index).split('\n').length;
}

function checkSQLInjection(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (
      isTestFile(filePath) ||
      isSecureFile(filePath) ||
      isAnalyzerFile(filePath) ||
      isNonCodeFile(filePath)
    )
      continue;

    // Skip files using prepared statements or ORMs
    if (/\.prepare\s*\(/.test(content)) continue;
    if (/\bprisma\b|\btypeorm\b|\bsequelize\b|\bdrizzle\b|\bknex\b/i.test(content)) continue;

    // Only flag SQL injection if the file actually uses database/query APIs
    const hasDatabaseUsage =
      /(?:\.query\s*\(|\.execute\s*\(|\.raw\s*\(|db\.|sql\.|database\.|connection\.|pool\.)/i.test(
        content,
      );
    if (!hasDatabaseUsage) continue;

    const injectionPatterns = [
      {
        pattern: /(?:query|execute|raw)\s*\(\s*`[^`]*\$\{[^}]+\}[^`]*`/gi,
        name: 'Dynamic query with interpolation',
      },
      {
        pattern:
          /(?:query|execute|raw)\s*\(\s*(?:['"](?:SELECT|INSERT|UPDATE|DELETE|WHERE)\b[^'"]*['"]\s*\+|`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)\b[^`]*\$\{)/gi,
        name: 'SQL with string concatenation',
      },
      {
        pattern: /`\s*(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{[^}]+\}[^`]*`/gi,
        name: 'Template literal SQL',
      },
    ];

    for (const { pattern, name } of injectionPatterns) {
      const match = pattern.exec(content);
      if (match) {
        total++;
        issues++;
        findings.push({
          id: 'SEC-INJ-001',
          severity: 'critical',
          layer: LAYER,
          layerName: NAME,
          owasp: 'A03:2025',
          cwe: 'CWE-89',
          cvss: 9.8,
          title: `SQL injection risk: ${name}`,
          description: `${filePath} builds SQL queries via string interpolation/concatenation`,
          impact: 'Attackers can execute arbitrary SQL commands on the database',
          evidence: {
            file: filePath,
            line: getLineNumber(content, match.index),
            snippet: match[0].substring(0, 80),
          },
          fix: {
            description: 'Use parameterized queries or an ORM',
            effort: 'sprint',
            automated: false,
          },
          references: [
            'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
          ],
        });
        break;
      }
    }
  }

  return { passed: Math.max(1, total) - issues, total: Math.max(total, 1) };
}

function checkXSS(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath) || isAnalyzerFile(filePath)) continue;

    const xssPatterns = [
      {
        pattern: /dangerouslySetInnerHTML/g,
        name: 'dangerouslySetInnerHTML',
        severity: 'high' as const,
      },
      { pattern: /\.innerHTML\s*=/g, name: 'innerHTML assignment', severity: 'high' as const },
      { pattern: /document\.write\s*\(/g, name: 'document.write()', severity: 'high' as const },
      {
        pattern: /\$\s*\(\s*['"][^'"]*['"]\s*\)\.html\s*\(/g,
        name: 'jQuery .html()',
        severity: 'medium' as const,
      },
    ];

    for (const { pattern, name, severity } of xssPatterns) {
      const match = pattern.exec(content);
      if (match) {
        total++;
        issues++;
        findings.push({
          id: 'SEC-INJ-002',
          severity,
          layer: LAYER,
          layerName: NAME,
          owasp: 'A03:2025',
          cwe: 'CWE-79',
          cvss: 6.1,
          title: `XSS risk: ${name}`,
          description: `${filePath} uses ${name} which can lead to cross-site scripting`,
          impact: 'Attackers can inject malicious scripts into the application',
          evidence: {
            file: filePath,
            line: getLineNumber(content, match.index),
            snippet: match[0],
          },
          fix: {
            description: 'Use framework-safe rendering methods or sanitize HTML input',
            effort: 'sprint',
            automated: false,
          },
          references: [
            'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
          ],
        });
      }
    }
  }

  return { passed: Math.max(1, total) - issues, total: Math.max(total, 1) };
}

function checkCommandInjection(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath) || isAnalyzerFile(filePath)) continue;

    const cmdPatterns = [
      { pattern: /\beval\s*\(/g, name: 'eval()' },
      { pattern: /new\s+Function\s*\(/g, name: 'new Function()' },
      {
        pattern: /child_process.*exec\s*\(\s*(?:`[^`]*\$\{|['"]\s*\+)/g,
        name: 'exec() with interpolation',
      },
      {
        pattern: /execSync\s*\(\s*(?:`[^`]*\$\{|['"]\s*\+)/g,
        name: 'execSync() with interpolation',
      },
    ];

    for (const { pattern, name } of cmdPatterns) {
      const match = pattern.exec(content);
      if (match) {
        total++;
        issues++;
        findings.push({
          id: 'SEC-INJ-003',
          severity: 'critical',
          layer: LAYER,
          layerName: NAME,
          owasp: 'A03:2025',
          cwe: 'CWE-78',
          cvss: 9.8,
          title: `Command injection risk: ${name}`,
          description: `${filePath} uses ${name} which may allow command injection`,
          impact: 'Attackers can execute arbitrary system commands',
          evidence: {
            file: filePath,
            line: getLineNumber(content, match.index),
            snippet: match[0],
          },
          fix: {
            description: 'Use execFile() with argument arrays instead of exec() with strings',
            effort: 'sprint',
            automated: false,
          },
          references: ['https://cwe.mitre.org/data/definitions/78.html'],
        });
      }
    }
  }

  return { passed: Math.max(1, total) - issues, total: Math.max(total, 1) };
}

function checkTemplateInjection(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath) || isAnalyzerFile(filePath)) continue;

    // Server-side template injection
    const templatePattern =
      /(?:ejs|pug|handlebars|mustache|nunjucks).*(?:render|compile)\s*\(.*(?:req\.|request\.|body\.|query\.)/gi;
    const match = templatePattern.exec(content);

    if (match) {
      total++;
      issues++;
      findings.push({
        id: 'SEC-INJ-004',
        severity: 'high',
        layer: LAYER,
        layerName: NAME,
        owasp: 'A03:2025',
        cwe: 'CWE-94',
        title: 'Server-side template injection risk',
        description: `${filePath} renders templates with user-supplied data`,
        impact: 'Attackers can execute arbitrary code through template expressions',
        evidence: { file: filePath, line: getLineNumber(content, match.index) },
        fix: {
          description: 'Sanitize user input before passing to template engines',
          effort: 'sprint',
          automated: false,
        },
        references: ['https://portswigger.net/web-security/server-side-template-injection'],
      });
    }
  }

  return { passed: Math.max(1, total) - issues, total: Math.max(total, 1) };
}

function checkPathTraversal(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath) || isAnalyzerFile(filePath)) continue;

    // File operations with user input
    const fileOpPattern =
      /(?:readFile|writeFile|createReadStream|createWriteStream|access|unlink|stat)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)/gi;
    const pathJoinUnsafe =
      /(?:path\.)?(?:join|resolve)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.)/gi;

    const match = fileOpPattern.exec(content) || pathJoinUnsafe.exec(content);
    if (match) {
      total++;
      // Check for sanitization
      if (
        !/(?:path\.normalize|sanitize|\.startsWith\(|path\.resolve.*\.startsWith)/i.test(content)
      ) {
        issues++;
        findings.push({
          id: 'SEC-INJ-005',
          severity: 'high',
          layer: LAYER,
          layerName: NAME,
          owasp: 'A03:2025',
          cwe: 'CWE-22',
          cvss: 7.5,
          title: 'Path traversal risk',
          description: `${filePath} performs file operations with user-supplied paths`,
          impact: 'Attackers can read or write arbitrary files on the server',
          evidence: {
            file: filePath,
            line: getLineNumber(content, match.index),
            snippet: match[0],
          },
          fix: {
            description:
              'Validate and normalize paths, ensure they stay within allowed directories',
            effort: 'sprint',
            automated: false,
          },
          references: ['https://cwe.mitre.org/data/definitions/22.html'],
        });
      }
    }
  }

  return { passed: Math.max(1, total) - issues, total: Math.max(total, 1) };
}

function checkReact2Shell(
  files: Map<string, string>,
  stackTags: Set<string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  if (!stackTags.has('react')) return { passed: 1, total: 1 };

  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;

    // React Server Components with unsanitized server actions
    const serverAction = /['"]use server['"]/;
    const unsafeOp = /(?:exec|execSync|spawn|fork)\s*\(/;

    if (serverAction.test(content) && unsafeOp.test(content)) {
      total++;
      issues++;
      findings.push({
        id: 'SEC-INJ-006',
        severity: 'critical',
        layer: LAYER,
        layerName: NAME,
        owasp: 'A03:2025',
        cwe: 'CWE-78',
        cvss: 9.8,
        title: 'React Server Action with shell execution',
        description: `${filePath} has "use server" directive with command execution`,
        impact: 'Server actions are callable from client — shell injection possible',
        evidence: { file: filePath },
        fix: {
          description: 'Never execute shell commands in server actions. Use safe APIs.',
          effort: 'sprint',
          automated: false,
        },
        references: ['https://react.dev/reference/rsc/use-server'],
      });
    }
  }

  return { passed: Math.max(1, total) - issues, total: Math.max(total, 1) };
}

function checkPrototypePollution(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath) || isAnalyzerFile(filePath)) continue;

    // Object.assign or spread with external data
    const pollutionPatterns = [
      {
        pattern: /Object\.assign\s*\(\s*\{\s*\}\s*,\s*(?:req\.|request\.|body\.|query\.)/g,
        name: 'Object.assign with user input',
      },
      {
        pattern: /\{\s*\.\.\.(?:req\.|request\.|body\.|query\.)/g,
        name: 'Spread operator with user input',
      },
      {
        pattern: /(?:__proto__|constructor\.prototype|Object\.prototype)/g,
        name: 'Direct prototype access',
      },
    ];

    for (const { pattern, name } of pollutionPatterns) {
      const match = pattern.exec(content);
      if (match) {
        total++;
        issues++;
        findings.push({
          id: 'SEC-INJ-007',
          severity: 'high',
          layer: LAYER,
          layerName: NAME,
          owasp: 'A03:2025',
          cwe: 'CWE-1321',
          title: `Prototype pollution risk: ${name}`,
          description: `${filePath} may allow prototype pollution via ${name}`,
          impact: 'Attackers can modify Object prototype, affecting all objects',
          evidence: {
            file: filePath,
            line: getLineNumber(content, match.index),
            snippet: match[0],
          },
          fix: {
            description: 'Use Object.create(null) or validate input keys before merging',
            effort: 'sprint',
            automated: false,
          },
          references: ['https://portswigger.net/web-security/prototype-pollution'],
        });
        break;
      }
    }
  }

  return { passed: Math.max(1, total) - issues, total: Math.max(total, 1) };
}

function checkReDoS(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath) || isAnalyzerFile(filePath)) continue;

    // Detect potentially dangerous regex patterns (nested quantifiers)
    const regexLiteralPattern = /\/(?:[^/\\]|\\.)+\/[gimsuy]*/g;
    let match: RegExpExecArray | null = regexLiteralPattern.exec(content);

    while (match !== null) {
      const regexBody = match[0];
      // Nested quantifiers like (a+)+ or (a|b+)*
      if (/\([^)]*[+*][^)]*\)[+*]|\([^)]*\|[^)]*[+*][^)]*\)[+*]/.test(regexBody)) {
        total++;
        issues++;
        findings.push({
          id: 'SEC-INJ-008',
          severity: 'medium',
          layer: LAYER,
          layerName: NAME,
          owasp: 'A03:2025',
          cwe: 'CWE-1333',
          title: 'ReDoS — regex with exponential backtracking',
          description: `${filePath} has a regex with nested quantifiers that may cause catastrophic backtracking`,
          impact: 'Malicious input can cause the regex engine to hang, causing DoS',
          evidence: {
            file: filePath,
            line: getLineNumber(content, match.index),
            snippet: regexBody.substring(0, 60),
          },
          fix: {
            description: 'Simplify regex or use atomic groups / possessive quantifiers',
            effort: 'sprint',
            automated: false,
          },
          references: [
            'https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS',
          ],
        });
        break;
      }
      match = regexLiteralPattern.exec(content);
    }
  }

  return { passed: Math.max(1, total) - issues, total: Math.max(total, 1) };
}

export async function runInjectionLayer(
  files: Map<string, string>,
  stackTags: Set<string>,
  _projectRoot: string,
): Promise<LayerResult> {
  const findings: SecureFinding[] = [];

  const checks = [
    checkSQLInjection(files, findings),
    checkXSS(files, findings),
    checkCommandInjection(files, findings),
    checkTemplateInjection(files, findings),
    checkPathTraversal(files, findings),
    checkReact2Shell(files, stackTags, findings),
    checkPrototypePollution(files, findings),
    checkReDoS(files, findings),
  ];

  const totalPassed = checks.reduce((s, c) => s + c.passed, 0);
  const totalChecks = checks.reduce((s, c) => s + c.total, 0);

  const ratio = totalChecks > 0 ? totalPassed / totalChecks : 1;
  const score = Math.round(ratio * WEIGHT * 100) / 100;

  return {
    layer: LAYER,
    name: NAME,
    weight: WEIGHT,
    checksPassed: totalPassed,
    checksTotal: totalChecks,
    score,
    findings,
  };
}
