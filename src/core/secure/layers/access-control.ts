/**
 * Layer 1 — Access Control & Identity (15%)
 * OWASP A01:2025 — Broken Access Control
 */

import type { LayerResult, SecureFinding } from '../types.js';
import { getLayerName, getLayerWeight } from '../types.js';

const LAYER = 1;
const WEIGHT = getLayerWeight(LAYER);
const NAME = getLayerName(LAYER);

function isTestFile(path: string): boolean {
  return /\.(test|spec)\.|__tests__|\/tests\/|\/fixtures\/|benchmarks\/|\.bench\./i.test(path);
}

function isSecureFile(path: string): boolean {
  return /secure\/|layers\//.test(path) && path.endsWith('.ts');
}

function getLineNumber(content: string, index: number): number {
  return content.substring(0, index).split('\n').length;
}

function checkDenyByDefault(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  const authPatterns =
    /(?:auth|authenticate|authorize|isAuthenticated|requireAuth|protect|guard|middleware|jwt|bearer)/i;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;

    const routePattern = /(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*['"][^'"]+['"]/g;
    const routes = [...content.matchAll(routePattern)];
    if (routes.length === 0) continue;

    total++;
    if (!authPatterns.test(content)) {
      issues++;
      findings.push({
        id: 'SEC-AC-001',
        severity: 'high',
        layer: LAYER,
        layerName: NAME,
        owasp: 'A01:2025',
        cwe: 'CWE-284',
        title: 'Routes without authentication middleware',
        description: `${routes.length} route(s) in ${filePath} lack auth middleware — deny-by-default violated`,
        impact: 'Unauthenticated users may access protected resources',
        evidence: {
          file: filePath,
          line: getLineNumber(content, routes[0]?.index ?? 0),
          snippet: routes[0]?.[0] ?? '',
        },
        fix: {
          description: 'Add authentication middleware to all route handlers',
          effort: 'sprint',
          automated: false,
        },
        references: ['https://owasp.org/Top10/A01_2021-Broken_Access_Control/'],
      });
    }
  }

  return { passed: total - issues, total: Math.max(total, 1) };
}

function checkIDOR(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;

    // Direct ID params in routes without ownership check
    const idParamPattern = /(?:params|query)\.(id|userId|user_id|accountId)\b/g;
    const ownershipPattern = /(?:req\.user|currentUser|session\.user|context\.user)/i;
    const matches = [...content.matchAll(idParamPattern)];

    if (matches.length === 0) continue;
    total++;

    if (!ownershipPattern.test(content)) {
      issues++;
      findings.push({
        id: 'SEC-AC-002',
        severity: 'high',
        layer: LAYER,
        layerName: NAME,
        owasp: 'A01:2025',
        cwe: 'CWE-639',
        title: 'Potential IDOR — direct ID access without ownership check',
        description: `${filePath} uses ID params without verifying resource ownership`,
        impact: "Attackers may access or modify other users' resources",
        evidence: {
          file: filePath,
          line: getLineNumber(content, matches[0]?.index ?? 0),
          snippet: matches[0]?.[0] ?? '',
        },
        fix: {
          description: 'Add ownership verification before accessing resources by ID',
          effort: 'sprint',
          automated: false,
        },
        references: ['https://owasp.org/Top10/A01_2021-Broken_Access_Control/'],
      });
    }
  }

  return { passed: total - issues, total: Math.max(total, 1) };
}

function checkCORS(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;

    const corsWildcard =
      /(?:Access-Control-Allow-Origin|origin)\s*[:=]\s*['"]?\*['"]?|(?:setHeader|header)\s*\(\s*['"]Access-Control-Allow-Origin['"]\s*,\s*['"]?\*['"]?\)/gi;
    const match = corsWildcard.exec(content);

    if (match) {
      total++;
      issues++;
      findings.push({
        id: 'SEC-AC-003',
        severity: 'medium',
        layer: LAYER,
        layerName: NAME,
        owasp: 'A01:2025',
        cwe: 'CWE-942',
        title: 'CORS wildcard origin',
        description: `${filePath} allows all origins via Access-Control-Allow-Origin: *`,
        impact: 'Any website can make cross-origin requests to this API',
        evidence: { file: filePath, line: getLineNumber(content, match.index), snippet: match[0] },
        fix: {
          description: 'Restrict CORS to specific trusted domains',
          effort: 'immediate',
          automated: false,
        },
        references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS'],
      });
    } else if (/cors/i.test(content)) {
      total++;
    }
  }

  return { passed: total - issues, total: Math.max(total, 1) };
}

function checkJWT(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;
    if (!/jwt|jsonwebtoken|jose/i.test(content)) continue;

    total++;

    // alg:none vulnerability
    if (/algorithms\s*:\s*\[.*['"]none['"]/i.test(content)) {
      issues++;
      findings.push({
        id: 'SEC-AC-004',
        severity: 'critical',
        layer: LAYER,
        layerName: NAME,
        owasp: 'A01:2025',
        cwe: 'CWE-345',
        cvss: 9.8,
        title: 'JWT allows "none" algorithm',
        description: `${filePath} allows the "none" algorithm in JWT verification`,
        impact: 'Attackers can forge tokens without a valid signature',
        evidence: { file: filePath, snippet: 'algorithms: [..., "none"]' },
        fix: {
          description: 'Remove "none" from allowed JWT algorithms',
          effort: 'immediate',
          automated: true,
        },
        references: ['https://cwe.mitre.org/data/definitions/345.html'],
      });
    }

    // No expiry check
    if (/jwt\.verify|jwtVerify/i.test(content) && !/exp|expiresIn|maxAge/i.test(content)) {
      issues++;
      findings.push({
        id: 'SEC-AC-004',
        severity: 'high',
        layer: LAYER,
        layerName: NAME,
        owasp: 'A01:2025',
        cwe: 'CWE-613',
        title: 'JWT without expiry validation',
        description: `${filePath} verifies JWT tokens without checking expiration`,
        impact: 'Tokens never expire, compromised tokens remain valid indefinitely',
        evidence: { file: filePath },
        fix: {
          description: 'Add expiration validation to JWT verification',
          effort: 'immediate',
          automated: false,
        },
        references: ['https://cwe.mitre.org/data/definitions/613.html'],
      });
    }
  }

  return { passed: total - issues, total: Math.max(total, 1) };
}

function checkSSRF(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;

    // URL construction from user input
    const urlFromInput =
      /(?:new\s+URL|fetch|axios\.(get|post)|http\.request)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)/g;
    const match = urlFromInput.exec(content);

    if (match) {
      total++;
      // Check for URL validation
      if (!/(?:allowlist|whitelist|validUrl|validateUrl|isAllowedUrl|URL_ALLOW)/i.test(content)) {
        issues++;
        findings.push({
          id: 'SEC-AC-005',
          severity: 'high',
          layer: LAYER,
          layerName: NAME,
          owasp: 'A01:2025',
          cwe: 'CWE-918',
          cvss: 8.6,
          title: 'Potential SSRF — URL from user input',
          description: `${filePath} constructs URLs from user input without validation`,
          impact: 'Attackers can make the server request internal resources',
          evidence: {
            file: filePath,
            line: getLineNumber(content, match.index),
            snippet: match[0],
          },
          fix: {
            description: 'Validate and restrict URLs against an allowlist of permitted domains',
            effort: 'sprint',
            automated: false,
          },
          references: ['https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/'],
        });
      }
    }
  }

  return { passed: total - issues, total: Math.max(total, 1) };
}

function checkPrivilegeEscalation(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;

    const adminRoutePattern = /(?:\/admin|\/manage|\/dashboard|\/settings|\/users)['"]?\s*[,)]/g;
    const roleCheckPattern = /(?:role|isAdmin|requireRole|hasPermission|authorize|RBAC)/i;
    const match = adminRoutePattern.exec(content);

    if (match) {
      total++;
      if (!roleCheckPattern.test(content)) {
        issues++;
        findings.push({
          id: 'SEC-AC-006',
          severity: 'high',
          layer: LAYER,
          layerName: NAME,
          owasp: 'A01:2025',
          cwe: 'CWE-269',
          title: 'Admin route without role check',
          description: `${filePath} has admin-level routes without role-based access control`,
          impact: 'Non-admin users may access privileged functionality',
          evidence: {
            file: filePath,
            line: getLineNumber(content, match.index),
            snippet: match[0],
          },
          fix: {
            description: 'Add role-based authorization middleware to admin routes',
            effort: 'sprint',
            automated: false,
          },
          references: ['https://cwe.mitre.org/data/definitions/269.html'],
        });
      }
    }
  }

  return { passed: total - issues, total: Math.max(total, 1) };
}

function checkCookieSecurity(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;

    const cookiePattern = /(?:cookie|set-cookie|setCookie|res\.cookie)\s*\(/gi;
    if (!cookiePattern.test(content)) continue;

    total++;
    const hasHttpOnly = /httpOnly\s*:\s*true/i.test(content);
    const hasSecure = /secure\s*:\s*true/i.test(content);
    const hasSameSite = /sameSite\s*:/i.test(content);

    if (!hasHttpOnly || !hasSecure || !hasSameSite) {
      issues++;
      const missing = [
        !hasHttpOnly && 'httpOnly',
        !hasSecure && 'secure',
        !hasSameSite && 'SameSite',
      ].filter(Boolean);

      findings.push({
        id: 'SEC-AC-007',
        severity: 'medium',
        layer: LAYER,
        layerName: NAME,
        owasp: 'A01:2025',
        cwe: 'CWE-614',
        title: `Cookie missing ${missing.join(', ')} flag(s)`,
        description: `${filePath} sets cookies without ${missing.join(', ')} attribute(s)`,
        impact: 'Cookies may be vulnerable to theft via XSS or CSRF attacks',
        evidence: { file: filePath },
        fix: {
          description: `Add ${missing.join(', ')} to cookie configuration`,
          effort: 'immediate',
          automated: true,
        },
        references: ['https://owasp.org/www-community/controls/SecureCookieAttribute'],
      });
    }
  }

  return { passed: total - issues, total: Math.max(total, 1) };
}

function checkCSRF(
  files: Map<string, string>,
  stackTags: Set<string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  if (!stackTags.has('dotnet')) return { passed: 1, total: 1 };

  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || !filePath.endsWith('.cs')) continue;

    const formPattern = /\[HttpPost\]|\[HttpPut\]|\[HttpDelete\]/g;
    const antiForgery = /ValidateAntiForgeryToken|AntiForgery/i;
    const matches = [...content.matchAll(formPattern)];

    if (matches.length === 0) continue;
    total++;

    if (!antiForgery.test(content)) {
      issues++;
      findings.push({
        id: 'SEC-AC-008',
        severity: 'medium',
        layer: LAYER,
        layerName: NAME,
        owasp: 'A01:2025',
        cwe: 'CWE-352',
        title: 'Missing CSRF protection (.NET)',
        description: `${filePath} has POST/PUT/DELETE actions without [ValidateAntiForgeryToken]`,
        impact: 'Forms are vulnerable to Cross-Site Request Forgery attacks',
        evidence: { file: filePath, line: getLineNumber(content, matches[0]?.index ?? 0) },
        fix: {
          description: 'Add [ValidateAntiForgeryToken] attribute to all state-changing actions',
          effort: 'immediate',
          automated: true,
        },
        references: ['https://learn.microsoft.com/aspnet/core/security/anti-request-forgery'],
      });
    }
  }

  return { passed: total - issues, total: Math.max(total, 1) };
}

export async function runAccessControlLayer(
  files: Map<string, string>,
  stackTags: Set<string>,
  _projectRoot: string,
): Promise<LayerResult> {
  const findings: SecureFinding[] = [];

  const checks = [
    checkDenyByDefault(files, findings),
    checkIDOR(files, findings),
    checkCORS(files, findings),
    checkJWT(files, findings),
    checkSSRF(files, findings),
    checkPrivilegeEscalation(files, findings),
    checkCookieSecurity(files, findings),
    checkCSRF(files, stackTags, findings),
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
