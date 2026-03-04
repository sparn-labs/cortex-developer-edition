/**
 * Layer 4 — Cryptographic Failures (10%)
 * OWASP A02:2025 — Cryptographic Failures
 */

import type { LayerResult, SecureFinding } from '../types.js';
import { getLayerName, getLayerWeight } from '../types.js';

const LAYER = 4;
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

function checkWeakHashing(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;

    const weakPatterns = [
      { pattern: /createHash\s*\(\s*['"]md5['"]\s*\)/gi, name: 'MD5' },
      { pattern: /createHash\s*\(\s*['"]sha1['"]\s*\)/gi, name: 'SHA1' },
      { pattern: /\bMD5\s*\(/g, name: 'MD5 function' },
      { pattern: /\bSHA1\s*\(/g, name: 'SHA1 function' },
    ];

    for (const { pattern, name } of weakPatterns) {
      const match = pattern.exec(content);
      if (match) {
        total++;
        issues++;
        findings.push({
          id: 'SEC-CR-001',
          severity: 'medium',
          layer: LAYER,
          layerName: NAME,
          owasp: 'A02:2025',
          cwe: 'CWE-328',
          title: `Weak hash algorithm: ${name}`,
          description: `${filePath} uses ${name} which is cryptographically broken`,
          impact: 'Hash collisions can be exploited for forgery or bypass',
          evidence: {
            file: filePath,
            line: getLineNumber(content, match.index),
            snippet: match[0],
          },
          fix: {
            description: 'Use SHA-256 or stronger for security purposes',
            codeBefore: `createHash('md5')`,
            codeAfter: `createHash('sha256')`,
            effort: 'immediate',
            automated: true,
          },
          references: ['https://cwe.mitre.org/data/definitions/328.html'],
        });
      }
    }
  }

  return { passed: Math.max(1, total) - issues, total: Math.max(total, 1) };
}

function checkHardcodedSecrets(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  const secretPatterns = [
    { pattern: /['"](?:sk|pk)[-_](?:live|test)[-_][a-zA-Z0-9]{20,}['"]/g, name: 'Stripe API key' },
    { pattern: /['"]AIza[0-9A-Za-z_-]{35}['"]/g, name: 'Google API key' },
    { pattern: /['"]gh[ps]_[A-Za-z0-9]{36,}['"]/g, name: 'GitHub token' },
    { pattern: /['"]AKIA[0-9A-Z]{16}['"]/g, name: 'AWS Access Key' },
    { pattern: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g, name: 'Private key' },
    {
      pattern: /(?:password|secret|api_key|apikey|auth_token)\s*[:=]\s*['"][^'"]{8,}['"]/gi,
      name: 'Hardcoded credential',
    },
  ];

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath) || filePath.endsWith('.md')) continue;

    for (const { pattern, name } of secretPatterns) {
      const regex = new RegExp(pattern.source, pattern.flags);
      const match = regex.exec(content);
      if (match) {
        total++;
        issues++;
        findings.push({
          id: 'SEC-CR-002',
          severity: 'critical',
          layer: LAYER,
          layerName: NAME,
          owasp: 'A02:2025',
          cwe: 'CWE-798',
          cvss: 9.8,
          title: `Hardcoded secret: ${name}`,
          description: `${filePath} contains a hardcoded ${name}`,
          impact: 'Secrets in source code are exposed to anyone with repo access',
          evidence: { file: filePath, line: getLineNumber(content, match.index) },
          fix: {
            description: 'Move secrets to environment variables or a secrets manager',
            effort: 'immediate',
            automated: false,
          },
          references: ['https://cwe.mitre.org/data/definitions/798.html'],
        });
      }
    }
  }

  return { passed: Math.max(1, total) - issues, total: Math.max(total, 1) };
}

function checkWeakPasswordHashing(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;

    // Check if file handles password hashing
    const passwordContext = /(?:password|passwd|pwd).*(?:hash|encrypt|digest)/gi;
    if (!passwordContext.test(content)) continue;

    total++;
    const strongHash = /(?:bcrypt|argon2|pbkdf2|scrypt)/i;
    if (!strongHash.test(content)) {
      issues++;
      findings.push({
        id: 'SEC-CR-003',
        severity: 'high',
        layer: LAYER,
        layerName: NAME,
        owasp: 'A02:2025',
        cwe: 'CWE-916',
        title: 'Password hashing without bcrypt/argon2/scrypt',
        description: `${filePath} hashes passwords without a proper KDF`,
        impact: 'Passwords can be cracked rapidly with rainbow tables or brute force',
        evidence: { file: filePath },
        fix: {
          description: 'Use bcrypt, argon2, or scrypt for password hashing',
          effort: 'sprint',
          automated: false,
        },
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html',
        ],
      });
    }
  }

  return { passed: Math.max(1, total) - issues, total: Math.max(total, 1) };
}

function checkHardcodedKeys(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;

    // Hardcoded encryption keys or IVs
    const keyPattern =
      /(?:encryption_key|secret_key|ENCRYPTION_KEY|iv|IV)\s*[:=]\s*(?:Buffer\.from\s*\()?['"][a-fA-F0-9]{16,}['"]/g;
    const match = keyPattern.exec(content);

    if (match) {
      total++;
      issues++;
      findings.push({
        id: 'SEC-CR-004',
        severity: 'critical',
        layer: LAYER,
        layerName: NAME,
        owasp: 'A02:2025',
        cwe: 'CWE-321',
        title: 'Hardcoded encryption key or IV',
        description: `${filePath} contains a hardcoded encryption key or initialization vector`,
        impact: 'Anyone with source code access can decrypt protected data',
        evidence: { file: filePath, line: getLineNumber(content, match.index) },
        fix: {
          description: 'Load encryption keys from environment variables or KMS',
          effort: 'sprint',
          automated: false,
        },
        references: ['https://cwe.mitre.org/data/definitions/321.html'],
      });
    }
  }

  return { passed: Math.max(1, total) - issues, total: Math.max(total, 1) };
}

function checkInsecureRandom(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;

    // Math.random used in security context — check nearby lines, not whole file
    const mathRandom = /Math\.random\s*\(\s*\)/g;
    const match = mathRandom.exec(content);

    if (match) {
      // Check ~5 lines around Math.random() for security-related context
      const contextStart = Math.max(0, match.index - 300);
      const contextEnd = Math.min(content.length, match.index + 300);
      const nearbyContent = content.substring(contextStart, contextEnd);
      const securityContext =
        /(?:token|secret|password|key|nonce|salt|session|csrf|otp|generateId|generateToken|randomString)/i;
      if (!securityContext.test(nearbyContent)) continue;
    }

    if (match) {
      total++;
      issues++;
      findings.push({
        id: 'SEC-CR-005',
        severity: 'high',
        layer: LAYER,
        layerName: NAME,
        owasp: 'A02:2025',
        cwe: 'CWE-338',
        title: 'Math.random() used in security context',
        description: `${filePath} uses Math.random() which is not cryptographically secure`,
        impact: 'Generated values are predictable and can be guessed by attackers',
        evidence: {
          file: filePath,
          line: getLineNumber(content, match.index),
          snippet: 'Math.random()',
        },
        fix: {
          description: 'Use crypto.randomUUID() or crypto.randomBytes() instead',
          codeBefore: 'Math.random()',
          codeAfter: "crypto.randomUUID()\n// or: crypto.randomBytes(32).toString('hex')",
          effort: 'immediate',
          automated: true,
        },
        references: ['https://cwe.mitre.org/data/definitions/338.html'],
      });
    }
  }

  return { passed: Math.max(1, total) - issues, total: Math.max(total, 1) };
}

function checkEncryptionAtRest(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  const sensitivePatterns =
    /(?:ssn|social.?security|credit.?card|card.?number|cvv|dob|date.?of.?birth)/i;
  let hasSensitiveData = false;
  let hasEncryption = false;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;
    if (sensitivePatterns.test(content)) hasSensitiveData = true;
    if (/(?:encrypt|cipher|aes|createCipheriv)/i.test(content)) hasEncryption = true;
  }

  if (hasSensitiveData && !hasEncryption) {
    findings.push({
      id: 'SEC-CR-006',
      severity: 'medium',
      layer: LAYER,
      layerName: NAME,
      owasp: 'A02:2025',
      cwe: 'CWE-311',
      title: 'Sensitive data without encryption at rest',
      description: 'Sensitive data patterns found (SSN, credit card, etc.) without encryption',
      impact: 'Data breach would expose plaintext sensitive information',
      evidence: { file: 'multiple files' },
      fix: {
        description: 'Encrypt sensitive data fields before storage',
        effort: 'quarter',
        automated: false,
      },
      references: ['https://cwe.mitre.org/data/definitions/311.html'],
    });
    return { passed: 0, total: 1 };
  }

  return { passed: 1, total: 1 };
}

function checkPQCReadiness(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let rsaCount = 0;
  let ecdsaCount = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;
    if (/RSA|rsa-/i.test(content)) rsaCount++;
    if (/ECDSA|EC\s*\(|secp256k1|P-256/i.test(content)) ecdsaCount++;
  }

  if (rsaCount > 0 || ecdsaCount > 0) {
    findings.push({
      id: 'SEC-CR-007',
      severity: 'info',
      layer: LAYER,
      layerName: NAME,
      owasp: 'A02:2025',
      title: `PQC inventory: ${rsaCount} RSA, ${ecdsaCount} ECDSA usages`,
      description:
        'Classical cryptography usage that will need migration to post-quantum algorithms',
      impact: 'Quantum computers may break RSA/ECDSA in the future',
      evidence: { file: 'multiple files' },
      fix: {
        description: 'Plan migration to NIST post-quantum standards (ML-KEM, ML-DSA)',
        effort: 'quarter',
        automated: false,
      },
      references: ['https://csrc.nist.gov/projects/post-quantum-cryptography'],
    });
    return { passed: 0, total: 1 };
  }

  return { passed: 1, total: 1 };
}

export async function runCryptographyLayer(
  files: Map<string, string>,
  _stackTags: Set<string>,
  _projectRoot: string,
): Promise<LayerResult> {
  const findings: SecureFinding[] = [];

  const checks = [
    checkWeakHashing(files, findings),
    checkHardcodedSecrets(files, findings),
    checkWeakPasswordHashing(files, findings),
    checkHardcodedKeys(files, findings),
    checkInsecureRandom(files, findings),
    checkEncryptionAtRest(files, findings),
    checkPQCReadiness(files, findings),
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
