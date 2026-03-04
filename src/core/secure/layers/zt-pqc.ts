/**
 * Layer 11 (Bonus) — Zero Trust & Post-Quantum Readiness (2%)
 */

import type { LayerResult, SecureFinding } from '../types.js';
import { getLayerName, getLayerWeight } from '../types.js';

const LAYER = 11;
const WEIGHT = getLayerWeight(LAYER);
const NAME = getLayerName(LAYER);

function isTestFile(path: string): boolean {
  return /\.(test|spec)\.|__tests__|\/tests\/|\/fixtures\/|benchmarks\/|\.bench\./i.test(path);
}

function isSecureFile(path: string): boolean {
  return /secure\/|layers\//.test(path) && path.endsWith('.ts');
}

function isNonCodeFile(path: string): boolean {
  return /\.md$|\.txt$|\.ya?ml$|\/docs?\//i.test(path);
}

function checkLeastPrivilege(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath) || isNonCodeFile(filePath)) continue;

    // Overly broad permissions — concrete patterns only, not generic keywords
    const broadPerms =
      /(?:chmod\s+777|0o777|permissions?\s*[:=]\s*['"]?\*['"]?|AllowAll|role\s*[:=]\s*['"]admin['"]\s*\/\*)/gi;
    const match = broadPerms.exec(content);

    if (match) {
      total++;
      issues++;
      findings.push({
        id: 'SEC-ZT-001',
        severity: 'medium',
        layer: LAYER,
        layerName: NAME,
        owasp: 'A01:2025',
        cwe: 'CWE-250',
        title: 'Overly broad permissions pattern',
        description: `${filePath} uses wildcard or excessive permissions`,
        impact: 'Violates Zero Trust principle of least privilege',
        evidence: { file: filePath, snippet: match[0] },
        fix: {
          description: 'Apply principle of least privilege — grant minimum required permissions',
          effort: 'sprint',
          automated: false,
        },
        references: ['https://csrc.nist.gov/publications/detail/sp/800-207/final'],
      });
    }
  }

  return { passed: Math.max(1, total) - issues, total: Math.max(total, 1) };
}

function checkMicrosegmentation(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  const allContent = [...files.values()].join('\n');

  // Check for service-to-service authentication
  const hasServiceAuth =
    /(?:mTLS|mutual.?TLS|service.?token|service.?account|internal.?auth|api.?gateway|mesh|istio|linkerd)/i.test(
      allContent,
    );
  const hasMultipleServices =
    /(?:microservice|service.?url|api.?endpoint|upstream|backend.?url)/i.test(allContent);

  if (hasMultipleServices && !hasServiceAuth) {
    findings.push({
      id: 'SEC-ZT-002',
      severity: 'info',
      layer: LAYER,
      layerName: NAME,
      owasp: 'A01:2025',
      cwe: 'CWE-284',
      title: 'No service-to-service authentication detected',
      description: 'Multi-service patterns found without mTLS or service mesh authentication',
      impact: 'Internal services trust each other implicitly — lateral movement risk',
      evidence: { file: 'service configuration' },
      fix: {
        description: 'Implement mTLS or service mesh for service-to-service authentication',
        effort: 'quarter',
        automated: false,
      },
      references: ['https://csrc.nist.gov/publications/detail/sp/800-207/final'],
    });
    return { passed: 0, total: 1 };
  }

  return { passed: 1, total: 1 };
}

function checkPQCInventory(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  let rsaCount = 0;
  let ecdsaCount = 0;
  let ecdhCount = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isSecureFile(filePath)) continue;
    if (/\bRSA\b|rsa-pkcs1|RSA-OAEP/i.test(content)) rsaCount++;
    if (/\bECDSA\b|secp256k1|P-256|prime256v1/i.test(content)) ecdsaCount++;
    if (/\bECDH\b|X25519|Curve25519/i.test(content)) ecdhCount++;
  }

  const total = rsaCount + ecdsaCount + ecdhCount;
  if (total > 0) {
    findings.push({
      id: 'SEC-ZT-003',
      severity: 'info',
      layer: LAYER,
      layerName: NAME,
      owasp: 'A02:2025',
      title: `PQC crypto inventory: ${rsaCount} RSA, ${ecdsaCount} ECDSA, ${ecdhCount} ECDH`,
      description: `${total} files use classical cryptography that needs post-quantum migration planning`,
      impact: 'Quantum computers may break these algorithms (NIST PQC transition by 2035)',
      evidence: { file: 'multiple files' },
      fix: {
        description: 'Create crypto migration plan to NIST PQC standards (ML-KEM, ML-DSA, SLH-DSA)',
        effort: 'quarter',
        automated: false,
      },
      references: ['https://csrc.nist.gov/projects/post-quantum-cryptography'],
    });
    return { passed: 0, total: 1 };
  }

  return { passed: 1, total: 1 };
}

function checkCryptoAgility(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  const allContent = [...files.values()].join('\n');

  // Check for crypto abstraction layers
  const hasCryptoAbstraction =
    /(?:CryptoProvider|CryptoService|crypto.?adapter|crypto.?factory|abstract.*crypt|interface.*crypt)/i.test(
      allContent,
    );
  const usesCrypto = /(?:createHash|createCipheriv|sign|verify|encrypt|decrypt)/i.test(allContent);

  if (usesCrypto && !hasCryptoAbstraction) {
    findings.push({
      id: 'SEC-ZT-004',
      severity: 'info',
      layer: LAYER,
      layerName: NAME,
      owasp: 'A02:2025',
      title: 'No crypto agility — direct crypto API usage',
      description: 'Cryptographic operations call Node.js crypto directly without abstraction',
      impact: 'Algorithm migration (e.g., to PQC) requires touching every call site',
      evidence: { file: 'project-wide' },
      fix: {
        description: 'Wrap crypto operations in an abstraction layer for algorithm agility',
        effort: 'quarter',
        automated: false,
      },
      references: ['https://www.nist.gov/cryptography'],
    });
    return { passed: 0, total: 1 };
  }

  return { passed: 1, total: 1 };
}

export async function runZTPQCLayer(
  files: Map<string, string>,
  _stackTags: Set<string>,
  _projectRoot: string,
): Promise<LayerResult> {
  const findings: SecureFinding[] = [];

  const checks = [
    checkLeastPrivilege(files, findings),
    checkMicrosegmentation(files, findings),
    checkPQCInventory(files, findings),
    checkCryptoAgility(files, findings),
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
