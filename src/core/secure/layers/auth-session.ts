/**
 * Layer 7 — Authentication & Session Management (10%)
 * OWASP A07:2025 — Identification and Authentication Failures
 */

import type { LayerResult, SecureFinding } from '../types.js';
import { getLayerName, getLayerWeight } from '../types.js';

const LAYER = 7;
const WEIGHT = getLayerWeight(LAYER);
const NAME = getLayerName(LAYER);

function isTestFile(path: string): boolean {
  return /\.(test|spec)\.|__tests__|\/tests\/|\/fixtures\/|benchmarks\/|\.bench\./i.test(path);
}

function isSecureFile(path: string): boolean {
  return /secure\/|layers\//.test(path) && path.endsWith('.ts');
}

function checkPasswordPolicy(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let hasPasswordHandling = false;
  let hasLengthCheck = false;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;

    if (/(?:password|passwd).*(?:length|min|validate|policy|check)/i.test(content)) {
      hasPasswordHandling = true;
      if (
        /(?:length|minLength|min_length)\s*(?:>=?|>)\s*(?:[89]|1[0-9]|2[0-9])/.test(content) ||
        /(?:minLength|minimumLength|min)\s*:\s*(?:[89]|1[0-9]|2[0-9])/.test(content)
      ) {
        hasLengthCheck = true;
      }
    }
  }

  if (hasPasswordHandling && !hasLengthCheck) {
    findings.push({
      id: 'SEC-AS-001',
      severity: 'medium',
      layer: LAYER,
      layerName: NAME,
      owasp: 'A07:2025',
      cwe: 'CWE-521',
      title: 'Weak password policy — no minimum length enforcement',
      description: 'Password handling code lacks minimum length enforcement (8+ chars)',
      impact: 'Users can set weak passwords that are easy to crack',
      evidence: { file: 'password handling files' },
      fix: {
        description: 'Enforce minimum password length of 8+ characters per NIST guidelines',
        effort: 'immediate',
        automated: false,
      },
      references: ['https://pages.nist.gov/800-63-4/sp800-63b.html'],
    });
    return { passed: 0, total: 1 };
  }

  return { passed: 1, total: 1 };
}

function checkBruteForce(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let hasLogin = false;
  let hasProtection = false;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;

    if (/(?:\/login|\/signin|\/auth|authenticate)['"]?\s*[,)]/i.test(content)) {
      hasLogin = true;
      if (
        /(?:rate.?limit|lockout|maxAttempts|max_attempts|failedAttempts|account.?lock|brute)/i.test(
          content,
        )
      ) {
        hasProtection = true;
      }
    }
  }

  if (hasLogin && !hasProtection) {
    findings.push({
      id: 'SEC-AS-002',
      severity: 'high',
      layer: LAYER,
      layerName: NAME,
      owasp: 'A07:2025',
      cwe: 'CWE-307',
      title: 'Login endpoint without brute force protection',
      description: 'Login route has no rate limiting or account lockout',
      impact: 'Attackers can perform unlimited credential stuffing attempts',
      evidence: { file: 'login handler' },
      fix: {
        description: 'Add rate limiting on login endpoint and/or account lockout after N failures',
        effort: 'sprint',
        automated: false,
      },
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html',
      ],
    });
    return { passed: 0, total: 1 };
  }

  return { passed: 1, total: 1 };
}

function checkAccountEnumeration(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;

    // Different error messages for user not found vs wrong password
    const userNotFound =
      /(?:user\s*not\s*found|no\s*(?:such\s*)?user|account\s*(?:does\s*)?not\s*exist|email\s*not\s*(?:found|registered))/i;
    const wrongPassword =
      /(?:wrong\s*password|incorrect\s*password|invalid\s*password|password\s*(?:is\s*)?incorrect)/i;

    if (userNotFound.test(content) && wrongPassword.test(content)) {
      total++;
      issues++;
      findings.push({
        id: 'SEC-AS-003',
        severity: 'medium',
        layer: LAYER,
        layerName: NAME,
        owasp: 'A07:2025',
        cwe: 'CWE-204',
        title: 'Account enumeration — different error messages for user/password',
        description: `${filePath} reveals whether an account exists via distinct error messages`,
        impact: 'Attackers can enumerate valid usernames/emails',
        evidence: { file: filePath },
        fix: {
          description: 'Use generic message: "Invalid email or password" for both cases',
          effort: 'immediate',
          automated: true,
        },
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html',
        ],
      });
    }
  }

  return { passed: Math.max(1, total) - issues, total: Math.max(total, 1) };
}

function checkSessionConfig(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let hasSession = false;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;

    if (
      /(?:express-session|cookie-session|(?:app|router)\.use\s*\(\s*session\s*\()/i.test(content)
    ) {
      hasSession = true;
      const missing: string[] = [];

      if (!/httpOnly\s*:\s*true/i.test(content)) missing.push('httpOnly');
      if (!/secure\s*:\s*true/i.test(content)) missing.push('secure');
      if (!/(?:maxAge|expires)/i.test(content)) missing.push('timeout/maxAge');

      if (missing.length > 0) {
        issues++;
        findings.push({
          id: 'SEC-AS-004',
          severity: 'medium',
          layer: LAYER,
          layerName: NAME,
          owasp: 'A07:2025',
          cwe: 'CWE-614',
          title: `Session missing: ${missing.join(', ')}`,
          description: `${filePath} session configuration lacks ${missing.join(', ')}`,
          impact: 'Sessions may be vulnerable to hijacking or fixation',
          evidence: { file: filePath },
          fix: {
            description: `Configure session with ${missing.join(', ')}`,
            effort: 'immediate',
            automated: true,
          },
          references: [
            'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
          ],
        });
      }
    }
  }

  if (!hasSession) return { passed: 1, total: 1 };
  return { passed: issues === 0 ? 1 : 0, total: 1 };
}

function checkOAuth(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let hasOAuth = false;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;

    if (/(?:oauth|oidc|openid|passport|next-auth|auth0|clerk)/i.test(content)) {
      hasOAuth = true;

      // Check for state parameter
      if (/(?:authorize|auth.*url)/i.test(content) && !/state\s*[:=]/i.test(content)) {
        issues++;
        findings.push({
          id: 'SEC-AS-005',
          severity: 'high',
          layer: LAYER,
          layerName: NAME,
          owasp: 'A07:2025',
          cwe: 'CWE-352',
          title: 'OAuth without state parameter',
          description: `${filePath} OAuth flow lacks state parameter for CSRF protection`,
          impact: 'OAuth flow is vulnerable to CSRF attacks',
          evidence: { file: filePath },
          fix: {
            description: 'Include a random state parameter in OAuth authorization requests',
            effort: 'sprint',
            automated: false,
          },
          references: ['https://datatracker.ietf.org/doc/html/rfc6749#section-10.12'],
        });
      }

      // Check for PKCE
      if (
        /(?:authorize|token)/i.test(content) &&
        !/(?:code_challenge|code_verifier|pkce)/i.test(content)
      ) {
        issues++;
        findings.push({
          id: 'SEC-AS-005',
          severity: 'medium',
          layer: LAYER,
          layerName: NAME,
          owasp: 'A07:2025',
          cwe: 'CWE-345',
          title: 'OAuth without PKCE',
          description: `${filePath} OAuth flow does not use PKCE (Proof Key for Code Exchange)`,
          impact: 'Authorization code interception attacks are possible',
          evidence: { file: filePath },
          fix: {
            description: 'Implement PKCE (code_challenge + code_verifier) in OAuth flow',
            effort: 'sprint',
            automated: false,
          },
          references: ['https://datatracker.ietf.org/doc/html/rfc7636'],
        });
      }
    }
  }

  if (!hasOAuth) return { passed: 1, total: 1 };
  return { passed: issues === 0 ? 1 : 0, total: 1 };
}

function checkMFA(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  const allContent = [...files.values()].join('\n');
  const hasAdminRoutes = /(?:\/admin|\/manage|\/dashboard)/i.test(allContent);

  if (!hasAdminRoutes) return { passed: 1, total: 1 };

  const hasMFA = /(?:mfa|multi.?factor|two.?factor|2fa|totp|authenticator|otp)/i.test(allContent);

  if (!hasMFA) {
    findings.push({
      id: 'SEC-AS-006',
      severity: 'medium',
      layer: LAYER,
      layerName: NAME,
      owasp: 'A07:2025',
      cwe: 'CWE-308',
      title: 'No MFA detected for admin/privileged routes',
      description: 'Admin routes exist without multi-factor authentication',
      impact: 'Compromised passwords grant full admin access without additional verification',
      evidence: { file: 'admin routes' },
      fix: {
        description: 'Implement MFA (TOTP/WebAuthn) for admin and privileged operations',
        effort: 'quarter',
        automated: false,
      },
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html',
      ],
    });
    return { passed: 0, total: 1 };
  }

  return { passed: 1, total: 1 };
}

function checkPasswordStorage(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let hasPasswordStorage = false;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;

    if (/(?:password|passwd).*(?:hash|save|store|create)/i.test(content)) {
      hasPasswordStorage = true;

      const hasStrongHash = /(?:bcrypt|argon2|scrypt|pbkdf2)/i.test(content);
      if (!hasStrongHash) {
        issues++;
        findings.push({
          id: 'SEC-AS-007',
          severity: 'high',
          layer: LAYER,
          layerName: NAME,
          owasp: 'A07:2025',
          cwe: 'CWE-916',
          title: 'Password storage without strong KDF',
          description: `${filePath} stores passwords without bcrypt/argon2/scrypt`,
          impact: 'Stored passwords can be cracked using rainbow tables or brute force',
          evidence: { file: filePath },
          fix: {
            description: 'Use argon2id or bcrypt with appropriate cost factors',
            effort: 'sprint',
            automated: false,
          },
          references: [
            'https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html',
          ],
        });
      }
    }
  }

  if (!hasPasswordStorage) return { passed: 1, total: 1 };
  return { passed: issues === 0 ? 1 : 0, total: 1 };
}

export async function runAuthSessionLayer(
  files: Map<string, string>,
  _stackTags: Set<string>,
  _projectRoot: string,
): Promise<LayerResult> {
  const findings: SecureFinding[] = [];

  const checks = [
    checkPasswordPolicy(files, findings),
    checkBruteForce(files, findings),
    checkAccountEnumeration(files, findings),
    checkSessionConfig(files, findings),
    checkOAuth(files, findings),
    checkMFA(files, findings),
    checkPasswordStorage(files, findings),
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
