/**
 * Secure audit engine — orchestrates all layers, computes score, builds report.
 */

import { resolve } from 'node:path';
import { buildAnalysisContext, getProjectName } from '../analyzers/context-builder.js';
import { runAccessControlLayer } from './layers/access-control.js';
import { runAuthSessionLayer } from './layers/auth-session.js';
import { runCryptographyLayer } from './layers/cryptography.js';
import { runDataIntegrityLayer } from './layers/data-integrity.js';
import { runExceptionsLayer } from './layers/exceptions.js';
import { runInjectionLayer } from './layers/injection.js';
import { runLoggingLayer } from './layers/logging.js';
import { runMisconfigurationLayer } from './layers/misconfiguration.js';
import { runSecureDesignLayer } from './layers/secure-design.js';
import { runSupplyChainLayer } from './layers/supply-chain.js';
import { runZTPQCLayer } from './layers/zt-pqc.js';
import { computeSecureScore } from './scorer.js';
import type {
  AttackSurface,
  ComplianceMatrix,
  LayerResult,
  RemediationRoadmap,
  SecureAuditOptions,
  SecureFinding,
  SecureReport,
} from './types.js';

type LayerRunner = (
  files: Map<string, string>,
  stackTags: Set<string>,
  projectRoot: string,
) => Promise<LayerResult>;

const ALL_LAYERS: Array<{ layer: number; run: LayerRunner }> = [
  { layer: 1, run: runAccessControlLayer },
  { layer: 2, run: runMisconfigurationLayer },
  { layer: 3, run: runSupplyChainLayer },
  { layer: 4, run: runCryptographyLayer },
  { layer: 5, run: runInjectionLayer },
  { layer: 6, run: runSecureDesignLayer },
  { layer: 7, run: runAuthSessionLayer },
  { layer: 8, run: runDataIntegrityLayer },
  { layer: 9, run: runLoggingLayer },
  { layer: 10, run: runExceptionsLayer },
  { layer: 11, run: runZTPQCLayer },
];

function parseLayerFilter(filter?: string): Set<number> | null {
  if (!filter) return null;
  const nums = filter
    .split(',')
    .map((s) => Number.parseInt(s.trim(), 10))
    .filter((n) => !Number.isNaN(n));
  return nums.length > 0 ? new Set(nums) : null;
}

function buildComplianceMatrix(
  findings: SecureFinding[],
  framework = 'owasp-top10',
): ComplianceMatrix {
  const owaspControls = [
    { id: 'A01:2025', desc: 'Broken Access Control' },
    { id: 'A02:2025', desc: 'Cryptographic Failures' },
    { id: 'A03:2025', desc: 'Injection' },
    { id: 'A04:2025', desc: 'Insecure Design' },
    { id: 'A05:2025', desc: 'Security Misconfiguration' },
    { id: 'A06:2025', desc: 'Vulnerable and Outdated Components' },
    { id: 'A07:2025', desc: 'Identification and Authentication Failures' },
    { id: 'A08:2025', desc: 'Software and Data Integrity Failures' },
    { id: 'A09:2025', desc: 'Security Logging and Monitoring Failures' },
    { id: 'A10:2025', desc: 'Server-Side Request Forgery' },
  ];

  const items = owaspControls.map((ctrl) => {
    const related = findings.filter((f) => f.owasp === ctrl.id);
    const criticalOrHigh = related.filter(
      (f) => f.severity === 'critical' || f.severity === 'high',
    );

    let status: 'pass' | 'fail' | 'partial' | 'n/a';
    if (related.length === 0) {
      status = 'pass';
    } else if (criticalOrHigh.length > 0) {
      status = 'fail';
    } else {
      status = 'partial';
    }

    return {
      control: ctrl.id,
      description: ctrl.desc,
      status,
      findings: related.map((f) => f.id),
    };
  });

  const passCount = items.filter((i) => i.status === 'pass').length;
  const passRate = Math.round((passCount / items.length) * 100);

  return { framework, items, passRate };
}

function buildAttackSurface(files: Map<string, string>): AttackSurface {
  let totalEndpoints = 0;
  let authenticatedEndpoints = 0;
  let rateLimitedEndpoints = 0;
  let inputPoints = 0;
  let cryptoUsages = 0;

  const allContent = [...files.values()].join('\n');

  // Count endpoints
  const routePattern = /(?:app|router)\.(get|post|put|patch|delete)\s*\(/gi;
  const routeMatches = allContent.match(routePattern);
  totalEndpoints = routeMatches?.length ?? 0;

  // Auth patterns
  if (/(?:auth|authenticate|authorize|requireAuth|protect|guard|jwt)/i.test(allContent)) {
    authenticatedEndpoints = Math.round(totalEndpoints * 0.7); // Estimate
  }

  // Rate limiting
  if (/(?:rate.?limit|throttle)/i.test(allContent)) {
    rateLimitedEndpoints = totalEndpoints; // Assumes global middleware
  }

  // Input points (forms, file uploads, query params)
  const inputPatterns = allContent.match(
    /(?:req\.body|req\.query|req\.params|req\.files|formData)/gi,
  );
  inputPoints = inputPatterns?.length ?? 0;

  // Crypto usages
  const cryptoPatterns = allContent.match(
    /(?:createHash|createCipheriv|sign|verify|bcrypt|argon2)/gi,
  );
  cryptoUsages = cryptoPatterns?.length ?? 0;

  // External deps
  const pkgContent = files.get('package.json');
  let externalDependencies = 0;
  if (pkgContent) {
    try {
      const pkg = JSON.parse(pkgContent);
      externalDependencies = Object.keys(pkg.dependencies ?? {}).length;
    } catch {
      /* ignore */
    }
  }

  // Public files
  let publicFiles = 0;
  for (const filePath of files.keys()) {
    if (/public\/|static\/|assets\//.test(filePath)) publicFiles++;
  }

  return {
    totalEndpoints,
    authenticatedEndpoints,
    unauthenticatedEndpoints: totalEndpoints - authenticatedEndpoints,
    rateLimitedEndpoints,
    publicFiles,
    externalDependencies,
    cryptoUsages,
    inputPoints,
  };
}

function buildRemediationRoadmap(findings: SecureFinding[]): RemediationRoadmap {
  const immediate: SecureFinding[] = [];
  const sprint: SecureFinding[] = [];
  const quarter: SecureFinding[] = [];

  // Sort by severity then effort
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sorted = [...findings].sort(
    (a, b) => severityOrder[a.severity] - severityOrder[b.severity],
  );

  for (const f of sorted) {
    if (f.fix.effort === 'immediate') immediate.push(f);
    else if (f.fix.effort === 'sprint') sprint.push(f);
    else quarter.push(f);
  }

  const toItem = (f: SecureFinding) => ({
    findingId: f.id,
    title: f.title,
    severity: f.severity,
    effort: f.fix.effort,
    automated: f.fix.automated,
    description: f.fix.description,
  });

  return {
    immediate: immediate.map(toItem),
    sprint: sprint.map(toItem),
    quarter: quarter.map(toItem),
    totalFindings: findings.length,
    automatable: findings.filter((f) => f.fix.automated).length,
  };
}

export async function runSecureAudit(options: SecureAuditOptions): Promise<SecureReport> {
  const projectRoot = resolve(options.path);

  // 1. Build AnalysisContext (reuse existing context-builder)
  const context = await buildAnalysisContext(projectRoot);

  // 2. Filter layers
  const layerFilter = parseLayerFilter(options.layer);
  let layers = ALL_LAYERS;
  if (layerFilter) {
    layers = layers.filter((l) => layerFilter.has(l.layer));
  }

  // 3. Quick mode — only critical-severity layers (1, 3, 4, 5)
  if (options.quick) {
    layers = layers.filter((l) => [1, 3, 4, 5].includes(l.layer));
  }

  // 4. Run layers
  const layerResults: LayerResult[] = [];
  for (const { run } of layers) {
    const result = await run(context.files, context.stackTags, projectRoot);
    layerResults.push(result);
  }

  // 5. Collect all findings
  const allFindings = layerResults.flatMap((r) => r.findings);

  // 6. Compute score
  const scoring = computeSecureScore(layerResults, allFindings);

  // 7. Build compliance matrix
  const compliance = buildComplianceMatrix(allFindings, options.compliance);

  // 8. Build attack surface
  const attackSurface = buildAttackSurface(context.files);

  // 9. Build remediation roadmap
  const remediationRoadmap = buildRemediationRoadmap(allFindings);

  // 10. Build report
  const projectName = getProjectName(projectRoot);

  return {
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    project: {
      name: projectName,
      path: projectRoot,
      stack: [...context.stackTags],
    },
    score: {
      global: scoring.global,
      grade: scoring.grade,
      layers: scoring.layers,
    },
    findings: allFindings,
    compliance,
    attackSurface,
    remediationRoadmap,
  };
}
