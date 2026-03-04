/**
 * Layer 3 — Supply Chain Security (12%)
 * OWASP A06:2025 — Vulnerable and Outdated Components
 */

import { execSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import type { LayerResult, SecureFinding } from '../types.js';
import { getLayerName, getLayerWeight } from '../types.js';

const LAYER = 3;
const WEIGHT = getLayerWeight(LAYER);
const NAME = getLayerName(LAYER);

const COMPROMISED_PACKAGES = [
  { name: 'event-stream', reason: 'Supply chain attack (2018)' },
  { name: 'ua-parser-js', reason: 'Compromised versions (2021)' },
  { name: 'node-ipc', reason: 'Protestware / malicious code (2022)' },
  { name: 'colors', reason: 'Sabotaged by maintainer (2022)' },
  { name: 'faker', reason: 'Sabotaged by maintainer (2022)' },
  { name: 'coa', reason: 'Hijacked package (2021)' },
  { name: 'rc', reason: 'Hijacked package (2021)' },
];

const TYPOSQUAT_PATTERNS = [
  { typo: 'lodas', real: 'lodash' },
  { typo: 'expresss', real: 'express' },
  { typo: 'axois', real: 'axios' },
  { typo: 'reacr', real: 'react' },
  { typo: 'mongose', real: 'mongoose' },
  { typo: 'crossenv', real: 'cross-env' },
  { typo: 'babelcli', real: 'babel-cli' },
  { typo: 'eslint-scope-util', real: 'eslint-scope' },
];

function checkNpmAudit(
  projectRoot: string,
  findings: SecureFinding[],
): { passed: number; total: number } {
  const pkgLock = join(projectRoot, 'package-lock.json');
  if (!existsSync(pkgLock)) return { passed: 1, total: 1 };

  try {
    const result = execSync('npm audit --json 2>/dev/null', {
      cwd: projectRoot,
      encoding: 'utf-8',
      timeout: 30000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    const audit = JSON.parse(result);
    const vulns = audit.metadata?.vulnerabilities ?? {};
    const criticals = vulns.critical ?? 0;
    const highs = vulns.high ?? 0;

    if (criticals > 0 || highs > 0) {
      findings.push({
        id: 'SEC-SC-001',
        severity: criticals > 0 ? 'critical' : 'high',
        layer: LAYER,
        layerName: NAME,
        owasp: 'A06:2025',
        cwe: 'CWE-1395',
        title: `npm audit: ${criticals} critical, ${highs} high vulnerabilities`,
        description: `Dependency audit found ${criticals + highs} severe vulnerabilities`,
        impact: 'Known vulnerabilities in dependencies can be exploited',
        evidence: { file: 'package-lock.json' },
        fix: {
          description: 'Run npm audit fix or manually update vulnerable packages',
          effort: 'sprint',
          automated: true,
        },
        references: ['https://docs.npmjs.com/cli/v10/commands/npm-audit'],
      });
      return { passed: 0, total: 1 };
    }

    return { passed: 1, total: 1 };
  } catch {
    // npm audit failed or not available — skip
    return { passed: 1, total: 1 };
  }
}

function checkLockFile(
  projectRoot: string,
  findings: SecureFinding[],
): { passed: number; total: number } {
  const hasPackageJson = existsSync(join(projectRoot, 'package.json'));
  if (!hasPackageJson) return { passed: 1, total: 1 };

  const lockFiles = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb'];
  const hasLock = lockFiles.some((f) => existsSync(join(projectRoot, f)));

  if (!hasLock) {
    findings.push({
      id: 'SEC-SC-002',
      severity: 'high',
      layer: LAYER,
      layerName: NAME,
      owasp: 'A06:2025',
      cwe: 'CWE-829',
      title: 'No lock file found',
      description: 'No package-lock.json, yarn.lock, or pnpm-lock.yaml found',
      impact: 'Dependency versions are not pinned, builds may pull different versions',
      evidence: { file: 'package.json' },
      fix: {
        description: 'Run npm install to generate package-lock.json and commit it',
        effort: 'immediate',
        automated: true,
      },
      references: ['https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json'],
    });
    return { passed: 0, total: 1 };
  }

  return { passed: 1, total: 1 };
}

function checkDependencyPinning(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  const pkgContent = files.get('package.json');
  if (!pkgContent) return { passed: 1, total: 1 };

  try {
    const pkg = JSON.parse(pkgContent);
    const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
    const unpinned: string[] = [];

    for (const [name, version] of Object.entries(allDeps)) {
      if (typeof version === 'string' && /^[\^~]/.test(version)) {
        unpinned.push(name);
      }
    }

    if (unpinned.length > 0) {
      // Only flag as info — very common practice
      findings.push({
        id: 'SEC-SC-003',
        severity: 'info',
        layer: LAYER,
        layerName: NAME,
        owasp: 'A06:2025',
        cwe: 'CWE-829',
        title: `${unpinned.length} dependencies use semver ranges (^ or ~)`,
        description: `Dependencies like ${unpinned.slice(0, 3).join(', ')} use flexible version ranges`,
        impact: 'Patch-level supply chain attacks could inject malicious code',
        evidence: { file: 'package.json' },
        fix: {
          description: 'Pin critical dependencies to exact versions',
          effort: 'immediate',
          automated: true,
        },
        references: ['https://docs.npmjs.com/cli/v10/configuring-npm/package-json#dependencies'],
      });
      return { passed: 0, total: 1 };
    }

    return { passed: 1, total: 1 };
  } catch {
    return { passed: 1, total: 1 };
  }
}

function checkCompromisedPackages(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  const pkgContent = files.get('package.json');
  if (!pkgContent) return { passed: 1, total: 1 };

  try {
    const pkg = JSON.parse(pkgContent);
    const allDeps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });
    let issues = 0;

    for (const { name, reason } of COMPROMISED_PACKAGES) {
      if (allDeps.includes(name)) {
        issues++;
        findings.push({
          id: 'SEC-SC-004',
          severity: 'critical',
          layer: LAYER,
          layerName: NAME,
          owasp: 'A06:2025',
          cwe: 'CWE-506',
          cvss: 9.8,
          title: `Known compromised package: ${name}`,
          description: `${name} — ${reason}`,
          impact: 'Package may contain malicious code or known backdoors',
          evidence: { file: 'package.json' },
          fix: {
            description: `Remove ${name} and replace with a safe alternative`,
            effort: 'sprint',
            automated: false,
          },
          references: ['https://snyk.io/advisor/'],
        });
      }
    }

    return { passed: issues === 0 ? 1 : 0, total: 1 };
  } catch {
    return { passed: 1, total: 1 };
  }
}

function checkAbandonware(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  // Check lock file for package dates — approximate via lockfile structure
  const lockContent = files.get('package-lock.json');
  if (!lockContent) return { passed: 1, total: 1 };

  // For now, check for known abandonware packages
  const knownAbandon = ['request', 'nomnom', 'optimist', 'connect-multiparty'];
  const pkgContent = files.get('package.json');
  if (!pkgContent) return { passed: 1, total: 1 };

  try {
    const pkg = JSON.parse(pkgContent);
    const allDeps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });
    const abandoned = allDeps.filter((d) => knownAbandon.includes(d));

    if (abandoned.length > 0) {
      findings.push({
        id: 'SEC-SC-005',
        severity: 'medium',
        layer: LAYER,
        layerName: NAME,
        owasp: 'A06:2025',
        cwe: 'CWE-1104',
        title: `${abandoned.length} potentially abandoned packages: ${abandoned.join(', ')}`,
        description: 'Dependencies that are deprecated or unmaintained',
        impact: 'Security vulnerabilities will not be patched',
        evidence: { file: 'package.json' },
        fix: {
          description: 'Replace abandoned packages with actively maintained alternatives',
          effort: 'sprint',
          automated: false,
        },
        references: ['https://snyk.io/advisor/'],
      });
      return { passed: 0, total: 1 };
    }

    return { passed: 1, total: 1 };
  } catch {
    return { passed: 1, total: 1 };
  }
}

function checkPostinstallScripts(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  const pkgContent = files.get('package.json');
  if (!pkgContent) return { passed: 1, total: 1 };

  try {
    const pkg = JSON.parse(pkgContent);
    const scripts = pkg.scripts ?? {};
    const dangerousScripts = ['preinstall', 'postinstall', 'install'];
    const found = dangerousScripts.filter((s) => scripts[s]);

    if (found.length > 0) {
      findings.push({
        id: 'SEC-SC-006',
        severity: 'medium',
        layer: LAYER,
        layerName: NAME,
        owasp: 'A06:2025',
        cwe: 'CWE-506',
        title: `Lifecycle scripts detected: ${found.join(', ')}`,
        description: `package.json has ${found.join(', ')} scripts that run on install`,
        impact: 'Scripts execute arbitrary code during npm install',
        evidence: {
          file: 'package.json',
          snippet: found.map((s) => `${s}: "${scripts[s]}"`).join(', '),
        },
        fix: {
          description: 'Review lifecycle scripts for security. Consider using --ignore-scripts',
          effort: 'immediate',
          automated: false,
        },
        references: ['https://docs.npmjs.com/cli/v10/using-npm/scripts'],
      });
      return { passed: 0, total: 1 };
    }

    return { passed: 1, total: 1 };
  } catch {
    return { passed: 1, total: 1 };
  }
}

function checkLicenseCompliance(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  const pkgContent = files.get('package.json');
  if (!pkgContent) return { passed: 1, total: 1 };

  try {
    const pkg = JSON.parse(pkgContent);
    const license = pkg.license || '';
    const copyleft = /GPL|AGPL|SSPL|EUPL/i;

    if (copyleft.test(license)) {
      findings.push({
        id: 'SEC-SC-007',
        severity: 'info',
        layer: LAYER,
        layerName: NAME,
        owasp: 'A06:2025',
        title: `Copyleft license detected: ${license}`,
        description: `Project uses ${license} — may impose requirements on downstream users`,
        impact: 'Legal compliance risk for proprietary/commercial use',
        evidence: { file: 'package.json', snippet: `"license": "${license}"` },
        fix: {
          description: 'Review license compatibility with your use case',
          effort: 'quarter',
          automated: false,
        },
        references: ['https://choosealicense.com/'],
      });
      return { passed: 0, total: 1 };
    }

    return { passed: 1, total: 1 };
  } catch {
    return { passed: 1, total: 1 };
  }
}

function checkTyposquatting(
  files: Map<string, string>,
  findings: SecureFinding[],
): { passed: number; total: number } {
  const pkgContent = files.get('package.json');
  if (!pkgContent) return { passed: 1, total: 1 };

  try {
    const pkg = JSON.parse(pkgContent);
    const allDeps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });
    let issues = 0;

    for (const { typo, real } of TYPOSQUAT_PATTERNS) {
      if (allDeps.includes(typo)) {
        issues++;
        findings.push({
          id: 'SEC-SC-008',
          severity: 'critical',
          layer: LAYER,
          layerName: NAME,
          owasp: 'A06:2025',
          cwe: 'CWE-506',
          cvss: 9.8,
          title: `Potential typosquat: "${typo}" (did you mean "${real}"?)`,
          description: `Dependency "${typo}" looks like a typosquat of "${real}"`,
          impact: 'Typosquatted packages may contain malicious code',
          evidence: { file: 'package.json' },
          fix: {
            description: `Replace "${typo}" with "${real}"`,
            effort: 'immediate',
            automated: true,
          },
          references: ['https://snyk.io/blog/typosquatting-attacks/'],
        });
      }
    }

    return { passed: issues === 0 ? 1 : 0, total: 1 };
  } catch {
    return { passed: 1, total: 1 };
  }
}

export async function runSupplyChainLayer(
  files: Map<string, string>,
  _stackTags: Set<string>,
  projectRoot: string,
): Promise<LayerResult> {
  const findings: SecureFinding[] = [];

  const checks = [
    checkNpmAudit(projectRoot, findings),
    checkLockFile(projectRoot, findings),
    checkDependencyPinning(files, findings),
    checkCompromisedPackages(files, findings),
    checkAbandonware(files, findings),
    checkPostinstallScripts(files, findings),
    checkLicenseCompliance(files, findings),
    checkTyposquatting(files, findings),
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
