/**
 * Layer 2 — Consent & Notice (18%)
 * Checks for consent mechanisms, privacy policies, cookie banners.
 */

import type { ComplianceFramework, ComplyFinding, ComplyLayerResult } from '../types.js';
import { getComplyLayerName, getComplyLayerWeight } from '../types.js';

const LAYER = 2;
const WEIGHT = getComplyLayerWeight(LAYER);
const NAME = getComplyLayerName(LAYER);

function isTestFile(path: string): boolean {
  return /\.(test|spec)\.|__tests__|\/tests\/|\/fixtures\/|benchmarks\/|\.bench\./i.test(path);
}

function isNonCodeFile(path: string): boolean {
  return /\.(md|txt|json|ya?ml|lock|svg|png|jpg|ico|woff|eot|ttf)$/i.test(path);
}

function checkPrivacyPolicy(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  const privacyFiles = [...files.keys()].filter((f) =>
    /privacy|datenschutz|politique.?de.?confidentialit/i.test(f),
  );

  const hasPrivacyContent = [...files.values()].some((content) =>
    /privacy.?policy|data.?protection.?policy|politique.?de.?confidentialit/i.test(content),
  );

  if (privacyFiles.length > 0 || hasPrivacyContent) {
    return { passed: 1, total: 1 };
  }

  findings.push({
    id: 'CMP-CN-001',
    severity: 'high',
    layer: LAYER,
    layerName: NAME,
    regulation: [
      { framework: 'gdpr', article: 'Art. 13', title: 'Information to be Provided' },
      { framework: 'ccpa', article: '§1798.130', title: 'Notice Requirements' },
    ],
    title: 'No privacy policy file detected',
    description: 'No privacy policy file or privacy policy content found in the project',
    impact:
      'GDPR Art. 13/14 and CCPA §1798.130 require a published privacy policy before data collection',
    evidence: { file: 'project root' },
    fix: {
      description:
        'Create a privacy policy document covering data collection, use, sharing, retention, and user rights',
      effort: 'sprint',
      automated: false,
    },
    references: ['https://gdpr-info.eu/art-13-gdpr/'],
  });

  return { passed: 0, total: 1 };
}

function checkCookieConsent(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  const allContent = [...files.values()].join('\n');

  // Check for cookie usage
  const usesCookies =
    /(?:cookie|setCookie|set-cookie|document\.cookie|cookie.?parser|js-cookie|cookies-next)/i.test(
      allContent,
    );
  if (!usesCookies) return { passed: 1, total: 1 };

  // Check for consent mechanism
  const hasConsentMechanism =
    /(?:cookie.?consent|cookie.?banner|cookie.?notice|cookiebot|onetrust|quantcast|consent.?manager|tarteaucitron)/i.test(
      allContent,
    );

  if (hasConsentMechanism) {
    return { passed: 1, total: 1 };
  }

  findings.push({
    id: 'CMP-CN-002',
    severity: 'high',
    layer: LAYER,
    layerName: NAME,
    regulation: [{ framework: 'gdpr', article: 'Art. 7', title: 'Conditions for Consent' }],
    title: 'Cookies used without consent mechanism',
    description: 'Application uses cookies but no cookie consent mechanism was detected',
    impact: 'EU ePrivacy Directive requires informed consent before setting non-essential cookies',
    evidence: { file: 'multiple files' },
    fix: {
      description:
        'Implement a cookie consent banner that blocks non-essential cookies until user consents',
      effort: 'sprint',
      automated: false,
    },
    references: ['https://gdpr-info.eu/art-7-gdpr/'],
  });

  return { passed: 0, total: 1 };
}

function checkCookieBanner(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  const allContent = [...files.values()].join('\n');

  const usesCookies = /(?:cookie|setCookie|document\.cookie)/i.test(allContent);
  if (!usesCookies) return { passed: 1, total: 1 };

  const hasBanner =
    /(?:cookie.?banner|cookie.?popup|cookie.?modal|cookie.?dialog|consent.?banner|consent.?popup|CookieBanner|CookieConsent)/i.test(
      allContent,
    );

  if (hasBanner) return { passed: 1, total: 1 };

  findings.push({
    id: 'CMP-CN-003',
    severity: 'medium',
    layer: LAYER,
    layerName: NAME,
    regulation: [{ framework: 'gdpr', article: 'Art. 7', title: 'Conditions for Consent' }],
    title: 'No cookie banner/popup implementation',
    description: 'Application uses cookies but no visible cookie banner UI component found',
    impact: 'Users must be informed about cookie usage and given the option to accept or reject',
    evidence: { file: 'project root' },
    fix: {
      description: 'Create a cookie banner component that appears on first visit',
      effort: 'sprint',
      automated: false,
    },
    references: ['https://gdpr-info.eu/art-7-gdpr/'],
  });

  return { passed: 0, total: 1 };
}

function checkDataCollectionConsent(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  const allContent = [...files.values()].join('\n');

  // Check if the app collects data (forms, sign-up)
  const collectsData =
    /(?:signup|sign.?up|register|createAccount|create.?account|onboarding)\b/i.test(allContent);
  if (!collectsData) return { passed: 1, total: 1 };

  total = 1;
  const hasConsentPatterns =
    /(?:consent|agree|acceptTerms|accept.?terms|checkbox.*(?:privacy|terms)|opt.?in|I\s+agree)/i.test(
      allContent,
    );

  if (!hasConsentPatterns) {
    issues++;
    findings.push({
      id: 'CMP-CN-004',
      severity: 'high',
      layer: LAYER,
      layerName: NAME,
      regulation: [
        { framework: 'gdpr', article: 'Art. 6(1)(a)', title: 'Consent as Legal Basis' },
        { framework: 'gdpr', article: 'Art. 7', title: 'Conditions for Consent' },
      ],
      title: 'Data collection without consent pattern',
      description:
        'Application collects user data (signup/register) without visible consent/opt-in patterns',
      impact: 'Processing personal data without valid consent violates GDPR Art. 6(1)(a)',
      evidence: { file: 'multiple files' },
      fix: {
        description:
          'Add explicit consent checkbox with privacy policy link to signup/registration forms',
        effort: 'sprint',
        automated: false,
      },
      references: ['https://gdpr-info.eu/art-6-gdpr/', 'https://gdpr-info.eu/art-7-gdpr/'],
    });
  }

  return { passed: total === 0 ? 1 : total - issues, total: Math.max(total, 1) };
}

function checkTrackingWithoutConsent(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isNonCodeFile(filePath)) continue;

    const trackingPattern =
      /(?:gtag|google.?analytics|ga\(|fbq\(|_paq|hotjar|mixpanel|segment\.track|amplitude)/i;
    const match = trackingPattern.exec(content);
    if (!match) continue;

    total++;
    const hasConsentGate =
      /(?:consent|hasConsent|cookieConsent|isConsented|gdpr|optIn)\s*(?:[&|?:=(]|\.)/i.test(
        content,
      );

    if (!hasConsentGate) {
      issues++;
      findings.push({
        id: 'CMP-CN-005',
        severity: 'critical',
        layer: LAYER,
        layerName: NAME,
        regulation: [
          { framework: 'gdpr', article: 'Art. 6(1)(a)', title: 'Consent' },
          { framework: 'ccpa', article: '§1798.120', title: 'Right to Opt-Out' },
        ],
        title: 'Third-party tracking loaded without consent gate',
        description: `${filePath} loads tracking scripts without checking for user consent first`,
        impact:
          'Loading tracking scripts before consent violates GDPR and can trigger CCPA opt-out requirements',
        evidence: { file: filePath, snippet: match[0] },
        fix: {
          description:
            'Gate tracking script initialization behind consent check. Only load after user opts in',
          effort: 'sprint',
          automated: false,
        },
        references: ['https://gdpr-info.eu/art-6-gdpr/'],
      });
    }
  }

  return { passed: total === 0 ? 1 : total - issues, total: Math.max(total, 1) };
}

function checkTermsOfService(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  const tosFiles = [...files.keys()].filter((f) => /terms|tos|conditions|cgu/i.test(f));

  const hasTosContent = [...files.values()].some((content) =>
    /terms\s+(?:of\s+)?(?:service|use)|conditions\s+(?:g[ée]n[ée]rales|of\s+use)/i.test(content),
  );

  if (tosFiles.length > 0 || hasTosContent) {
    return { passed: 1, total: 1 };
  }

  findings.push({
    id: 'CMP-CN-006',
    severity: 'low',
    layer: LAYER,
    layerName: NAME,
    regulation: [{ framework: 'soc2', article: 'CC2.2', title: 'Communication of Policies' }],
    title: 'No terms of service file detected',
    description: 'No terms of service document found in the project',
    impact: 'Terms of service define the legal relationship with users and limit liability',
    evidence: { file: 'project root' },
    fix: { description: 'Create a terms of service document', effort: 'quarter', automated: false },
    references: [],
  });

  return { passed: 0, total: 1 };
}

function checkChildrenData(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  const allContent = [...files.values()].join('\n');

  const handlesChildren =
    /(?:child|minor|under.?13|under.?16|parental.?consent|coppa|age.?gate|age.?check)\b/i.test(
      allContent,
    );
  if (!handlesChildren) return { passed: 1, total: 1 };

  const hasAgeVerification =
    /(?:age.?verif|verify.?age|age.?gate|date.?of.?birth.*verif|checkAge|isMinor)\b/i.test(
      allContent,
    );

  if (hasAgeVerification) return { passed: 1, total: 1 };

  findings.push({
    id: 'CMP-CN-007',
    severity: 'medium',
    layer: LAYER,
    layerName: NAME,
    regulation: [{ framework: 'gdpr', article: 'Art. 8', title: "Child's Consent" }],
    title: 'Children data handling without age verification',
    description: "Application references children's data but lacks age verification mechanism",
    impact:
      'GDPR Art. 8 requires parental consent for children under 16. COPPA requires it for under 13',
    evidence: { file: 'multiple files' },
    fix: {
      description: 'Implement age verification and parental consent flows for minors',
      effort: 'quarter',
      automated: false,
    },
    references: ['https://gdpr-info.eu/art-8-gdpr/'],
  });

  return { passed: 0, total: 1 };
}

export async function runConsentNoticeLayer(
  files: Map<string, string>,
  _stackTags: Set<string>,
  _projectRoot: string,
  _frameworks: Set<ComplianceFramework>,
): Promise<ComplyLayerResult> {
  const findings: ComplyFinding[] = [];

  const checks = [
    checkPrivacyPolicy(files, findings),
    checkCookieConsent(files, findings),
    checkCookieBanner(files, findings),
    checkDataCollectionConsent(files, findings),
    checkTrackingWithoutConsent(files, findings),
    checkTermsOfService(files, findings),
    checkChildrenData(files, findings),
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
