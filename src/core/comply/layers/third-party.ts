/**
 * Layer 7 — Third-Party & Vendor Compliance (8%)
 * Checks analytics, social login, payment processors, ad SDKs, PII sharing.
 */

import type { ComplianceFramework, ComplyFinding, ComplyLayerResult } from '../types.js';
import { getComplyLayerName, getComplyLayerWeight } from '../types.js';

const LAYER = 7;
const WEIGHT = getComplyLayerWeight(LAYER);
const NAME = getComplyLayerName(LAYER);

function isTestFile(path: string): boolean {
  return /\.(test|spec)\.|__tests__|\/tests\/|\/fixtures\/|benchmarks\/|\.bench\./i.test(path);
}

function isNonCodeFile(path: string): boolean {
  return /\.(md|txt|json|ya?ml|lock|svg|png|jpg|ico|woff|eot|ttf)$/i.test(path);
}

function getLineNumber(content: string, index: number): number {
  return content.substring(0, index).split('\n').length;
}

/** Heuristic: check if match at index is inside a regex literal or pattern definition. */
function isPatternContext(content: string, index: number): boolean {
  const ls = content.lastIndexOf('\n', index - 1) + 1;
  const le = content.indexOf('\n', index);
  const line = content.substring(ls, le === -1 ? content.length : le);
  const col = index - ls;
  const before = line.substring(0, col);
  const slashes = before.match(/(?<!\\)\//g);
  if (slashes && slashes.length % 2 === 1) return true;
  if (/(?:new\s+RegExp\s*\(|(?:pattern|regex)\s*[:=]\s*\/)/i.test(line)) return true;
  return false;
}

function checkAnalyticsWithoutConsent(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isNonCodeFile(filePath)) continue;

    const analyticsPattern =
      /(?:google.?analytics|gtag|ga\(|segment\.identify|segment\.track|mixpanel\.track|amplitude\.track|plausible|matomo|umami|posthog)\b/i;
    const match = analyticsPattern.exec(content);
    if (!match) continue;

    total++;
    const hasConsentGate =
      /(?:consent|hasConsent|cookieConsent|isConsented|gdpr|optIn)\s*(?:[&|?:=]|\.)/i.test(content);

    if (!hasConsentGate) {
      issues++;
      findings.push({
        id: 'CMP-TP-001',
        severity: 'high',
        layer: LAYER,
        layerName: NAME,
        regulation: [
          { framework: 'gdpr', article: 'Art. 6(1)(a)', title: 'Consent' },
          { framework: 'ccpa', article: '§1798.120', title: 'Right to Opt-Out' },
        ],
        title: 'Analytics service without consent gate',
        description: `${filePath} initializes analytics without checking for user consent`,
        impact: 'Analytics services collecting user behavior data require prior consent under GDPR',
        evidence: { file: filePath, line: getLineNumber(content, match.index), snippet: match[0] },
        fix: {
          description:
            'Gate analytics initialization behind consent check. Use privacy-friendly alternatives (Plausible, Umami)',
          effort: 'sprint',
          automated: false,
        },
        references: ['https://gdpr-info.eu/art-6-gdpr/'],
      });
    }
  }

  return { passed: total === 0 ? 1 : total - issues, total: Math.max(total, 1) };
}

function checkSocialLogin(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isNonCodeFile(filePath)) continue;

    const socialPattern =
      /(?:google.?auth|facebook.?login|fb.?login|oauth.*(?:google|facebook|github|apple|twitter)|passport.*(?:google|facebook)|socialLogin|social.?auth|next.?auth.*provider)/i;
    const match = socialPattern.exec(content);
    if (!match) continue;

    total++;
    // Check for scope limitation
    const hasMinimalScope =
      /(?:scope\s*[:=]\s*['"](?:email|profile|openid)['"]|requestedScopes|minimal.?scope)/i.test(
        content,
      );

    if (!hasMinimalScope) {
      issues++;
      findings.push({
        id: 'CMP-TP-002',
        severity: 'medium',
        layer: LAYER,
        layerName: NAME,
        regulation: [{ framework: 'gdpr', article: 'Art. 5(1)(c)', title: 'Data Minimisation' }],
        title: 'Social login integration — data sharing review needed',
        description: `${filePath} implements social login without visible scope limitation`,
        impact:
          'Social login providers may share more data than necessary. Apply data minimization principle',
        evidence: { file: filePath, snippet: match[0] },
        fix: {
          description:
            'Limit OAuth scopes to minimum required (email, profile). Document data received from social providers',
          effort: 'immediate',
          automated: false,
        },
        references: ['https://gdpr-info.eu/art-5-gdpr/'],
      });
    }
  }

  return { passed: total === 0 ? 1 : total - issues, total: Math.max(total, 1) };
}

function checkPaymentProcessor(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isNonCodeFile(filePath)) continue;

    const paymentPattern = /(?:stripe|paypal|braintree|square|adyen|mollie|razorpay)\b/i;
    const match = paymentPattern.exec(content);
    if (!match) continue;
    if (isPatternContext(content, match.index)) continue;

    total++;
    // Payment processors are generally compliant — just note for DPA
    const hasDPA = /(?:dpa|data.?processing|agreement|terms)\b/i.test(content);
    if (!hasDPA) {
      issues++;
      findings.push({
        id: 'CMP-TP-003',
        severity: 'low',
        layer: LAYER,
        layerName: NAME,
        regulation: [{ framework: 'gdpr', article: 'Art. 28', title: 'Processor' }],
        title: 'Payment processor integration — DPA needed',
        description: `${filePath} integrates a payment processor. Ensure Data Processing Agreement is in place`,
        impact: 'GDPR Art. 28 requires a formal Data Processing Agreement with all data processors',
        evidence: { file: filePath, snippet: match[0] },
        fix: {
          description: 'Verify DPA is signed with the payment processor and on file',
          effort: 'immediate',
          automated: false,
        },
        references: ['https://gdpr-info.eu/art-28-gdpr/'],
      });
    }
  }

  return { passed: total === 0 ? 1 : total - issues, total: Math.max(total, 1) };
}

function checkAdvertisingSDK(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isNonCodeFile(filePath)) continue;

    const adPattern =
      /(?:google.?ads|adsense|admob|facebook.?pixel|fbq|doubleclick|ad.?network|interstitial.?ad|rewarded.?ad|banner.?ad)\b/i;
    const match = adPattern.exec(content);
    if (!match) continue;

    total++;
    const hasConsentGate =
      /(?:consent|hasConsent|gdpr|optIn|personalization)\s*(?:[&|?:=]|\.)/i.test(content);

    if (!hasConsentGate) {
      issues++;
      findings.push({
        id: 'CMP-TP-004',
        severity: 'high',
        layer: LAYER,
        layerName: NAME,
        regulation: [
          { framework: 'gdpr', article: 'Art. 6(1)(a)', title: 'Consent' },
          { framework: 'ccpa', article: '§1798.120', title: 'Right to Opt-Out of Sale' },
        ],
        title: 'Advertising SDK without consent gate',
        description: `${filePath} loads advertising SDK without consent verification`,
        impact:
          'Ad SDKs collect behavioral data and may constitute "sale" of personal information under CCPA',
        evidence: { file: filePath, line: getLineNumber(content, match.index), snippet: match[0] },
        fix: {
          description:
            'Gate ad SDK initialization behind explicit consent. Implement CCPA opt-out for data sale',
          effort: 'sprint',
          automated: false,
        },
        references: ['https://gdpr-info.eu/art-6-gdpr/'],
      });
    }
  }

  return { passed: total === 0 ? 1 : total - issues, total: Math.max(total, 1) };
}

function checkPIIToThirdParty(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isNonCodeFile(filePath)) continue;

    // Detect API calls sending PII fields
    const apiCallWithPII =
      /(?:fetch|axios|http|request)\s*\([^)]*(?:email|name|phone|address|userId|user_id)\b/gi;
    const match = apiCallWithPII.exec(content);
    if (!match) continue;

    total++;
    // Check if it's to a third-party (not internal)
    const isExternal = /(?:https?:\/\/(?!localhost|127\.0\.0\.1)|api\.\w+\.com|\.io\/api)\b/i.test(
      content,
    );

    if (isExternal) {
      issues++;
      findings.push({
        id: 'CMP-TP-005',
        severity: 'medium',
        layer: LAYER,
        layerName: NAME,
        regulation: [
          { framework: 'gdpr', article: 'Art. 28', title: 'Processor' },
          { framework: 'gdpr', article: 'Art. 44', title: 'Transfer to Third Countries' },
        ],
        title: 'PII sent to third-party APIs',
        description: `${filePath} sends personal data to external API endpoints`,
        impact:
          'Sharing PII with third parties requires DPA, legal basis, and privacy policy disclosure',
        evidence: {
          file: filePath,
          line: getLineNumber(content, match.index),
          snippet: match[0].substring(0, 80),
        },
        fix: {
          description:
            'Ensure DPA is in place with the third party. Document the data sharing in privacy policy',
          effort: 'sprint',
          automated: false,
        },
        references: ['https://gdpr-info.eu/art-28-gdpr/'],
      });
    }
  }

  return { passed: total === 0 ? 1 : total - issues, total: Math.max(total, 1) };
}

function checkDataProcessingAgreement(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  const allContent = [...files.values()].join('\n');

  const usesThirdParty =
    /(?:stripe|paypal|twilio|sendgrid|mailgun|mailchimp|intercom|zendesk|sentry|datadog|newrelic|segment|mixpanel)\b/i.test(
      allContent,
    );
  if (!usesThirdParty) return { passed: 1, total: 1 };

  const hasDPA = /(?:dpa|data.?processing.?agreement|sub.?processor|processor.?agreement)\b/i.test(
    allContent,
  );

  if (hasDPA) return { passed: 1, total: 1 };

  findings.push({
    id: 'CMP-TP-006',
    severity: 'info',
    layer: LAYER,
    layerName: NAME,
    regulation: [{ framework: 'gdpr', article: 'Art. 28', title: 'Processor' }],
    title: 'No data processing agreement indicators',
    description: 'Application uses third-party services but no DPA references found in codebase',
    impact: 'GDPR Art. 28 requires a DPA with every third-party processor handling personal data',
    evidence: { file: 'project root' },
    fix: {
      description: 'Maintain a vendor register with DPA status for each third-party service',
      effort: 'quarter',
      automated: false,
    },
    references: ['https://gdpr-info.eu/art-28-gdpr/'],
  });

  return { passed: 0, total: 1 };
}

export async function runThirdPartyLayer(
  files: Map<string, string>,
  _stackTags: Set<string>,
  _projectRoot: string,
  _frameworks: Set<ComplianceFramework>,
): Promise<ComplyLayerResult> {
  const findings: ComplyFinding[] = [];

  const checks = [
    checkAnalyticsWithoutConsent(files, findings),
    checkSocialLogin(files, findings),
    checkPaymentProcessor(files, findings),
    checkAdvertisingSDK(files, findings),
    checkPIIToThirdParty(files, findings),
    checkDataProcessingAgreement(files, findings),
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
