/**
 * Layer 1 — Personal Data Handling (20%)
 * Detects PII collection patterns across codebase.
 */

import type { ComplianceFramework, ComplyFinding, ComplyLayerResult } from '../types.js';
import { getComplyLayerName, getComplyLayerWeight } from '../types.js';

const LAYER = 1;
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

function checkEmailCollection(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isNonCodeFile(filePath)) continue;

    const pattern = /(?:email|e-mail|emailAddress|user_email|userEmail)\s*[:=]/gi;
    const match = pattern.exec(content);
    if (!match) continue;

    total++;
    // Check if there's consent or privacy notice reference nearby
    if (!/(?:consent|gdpr|privacy|optIn|opt_in)/i.test(content)) {
      issues++;
      findings.push({
        id: 'CMP-PD-001',
        severity: 'medium',
        layer: LAYER,
        layerName: NAME,
        regulation: [
          { framework: 'gdpr', article: 'Art. 6', title: 'Lawfulness of Processing' },
          { framework: 'ccpa', article: '§1798.100', title: 'Right to Know' },
        ],
        title: 'Email address collection without consent reference',
        description: `${filePath} collects email addresses without visible consent/privacy patterns`,
        impact:
          'Email collection without legal basis may violate GDPR Art. 6 and CCPA disclosure requirements',
        evidence: { file: filePath, line: getLineNumber(content, match.index), snippet: match[0] },
        fix: {
          description: 'Add consent mechanism before collecting email addresses',
          effort: 'sprint',
          automated: false,
        },
        references: ['https://gdpr-info.eu/art-6-gdpr/'],
      });
    }
  }

  return { passed: total === 0 ? 1 : total - issues, total: Math.max(total, 1) };
}

function checkNameFields(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isNonCodeFile(filePath)) continue;

    const pattern =
      /(?:firstName|first_name|lastName|last_name|fullName|full_name|displayName)\s*[:=]/gi;
    const match = pattern.exec(content);
    if (!match) continue;

    total++;
    if (!/(?:consent|gdpr|privacy|purpose)/i.test(content)) {
      issues++;
      findings.push({
        id: 'CMP-PD-002',
        severity: 'low',
        layer: LAYER,
        layerName: NAME,
        regulation: [{ framework: 'gdpr', article: 'Art. 5(1)(b)', title: 'Purpose Limitation' }],
        title: 'Name field collection detected',
        description: `${filePath} collects personal name fields`,
        impact: 'Name data is PII subject to purpose limitation and data minimization requirements',
        evidence: { file: filePath, line: getLineNumber(content, match.index), snippet: match[0] },
        fix: {
          description: 'Document the purpose for name collection and add to privacy policy',
          effort: 'sprint',
          automated: false,
        },
        references: ['https://gdpr-info.eu/art-5-gdpr/'],
      });
    }
  }

  return { passed: total === 0 ? 1 : total - issues, total: Math.max(total, 1) };
}

function checkPhoneNumbers(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isNonCodeFile(filePath)) continue;

    const pattern = /(?:phone|phoneNumber|phone_number|telephone|mobile|cellPhone)\s*[:=]/gi;
    const match = pattern.exec(content);
    if (!match) continue;

    total++;
    if (!/(?:consent|gdpr|privacy)/i.test(content)) {
      issues++;
      findings.push({
        id: 'CMP-PD-003',
        severity: 'medium',
        layer: LAYER,
        layerName: NAME,
        regulation: [
          { framework: 'gdpr', article: 'Art. 6', title: 'Lawfulness of Processing' },
          { framework: 'ccpa', article: '§1798.100', title: 'Right to Know' },
        ],
        title: 'Phone number collection detected',
        description: `${filePath} collects phone numbers without visible consent patterns`,
        impact: 'Phone numbers are PII requiring explicit legal basis for collection',
        evidence: { file: filePath, line: getLineNumber(content, match.index), snippet: match[0] },
        fix: {
          description: 'Add consent mechanism for phone number collection',
          effort: 'sprint',
          automated: false,
        },
        references: ['https://gdpr-info.eu/art-6-gdpr/'],
      });
    }
  }

  return { passed: total === 0 ? 1 : total - issues, total: Math.max(total, 1) };
}

function checkPhysicalAddress(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isNonCodeFile(filePath)) continue;

    const pattern =
      /(?:streetAddress|street_address|postalCode|postal_code|zipCode|zip_code|homeAddress|billingAddress|shippingAddress)\s*[:=]/gi;
    const match = pattern.exec(content);
    if (!match) continue;

    total++;
    if (!/(?:consent|gdpr|privacy)/i.test(content)) {
      issues++;
      findings.push({
        id: 'CMP-PD-004',
        severity: 'medium',
        layer: LAYER,
        layerName: NAME,
        regulation: [{ framework: 'gdpr', article: 'Art. 6', title: 'Lawfulness of Processing' }],
        title: 'Physical address collection detected',
        description: `${filePath} collects physical address data`,
        impact: 'Physical addresses are PII requiring purpose limitation and minimization',
        evidence: { file: filePath, line: getLineNumber(content, match.index), snippet: match[0] },
        fix: {
          description: 'Document purpose for address collection and ensure data minimization',
          effort: 'sprint',
          automated: false,
        },
        references: ['https://gdpr-info.eu/art-5-gdpr/'],
      });
    }
  }

  return { passed: total === 0 ? 1 : total - issues, total: Math.max(total, 1) };
}

function checkSSNNationalID(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isNonCodeFile(filePath)) continue;

    const pattern =
      /(?:ssn|socialSecurity|social_security|nationalId|national_id|taxId|tax_id|nin|passport_number|passportNumber)\s*[:=]/gi;
    const match = pattern.exec(content);
    if (!match) continue;

    total++;
    issues++;
    findings.push({
      id: 'CMP-PD-005',
      severity: 'critical',
      layer: LAYER,
      layerName: NAME,
      regulation: [
        { framework: 'gdpr', article: 'Art. 87', title: 'Processing of National ID Number' },
        { framework: 'ccpa', article: '§1798.81.5', title: 'Personal Information Security' },
        { framework: 'hipaa', article: '§164.514', title: 'De-identification Standard' },
      ],
      title: 'SSN/National ID collection — high-risk PII',
      description: `${filePath} collects government-issued identification numbers`,
      impact:
        'SSN/National ID is highest-risk PII. Breach triggers mandatory notification and severe penalties',
      evidence: { file: filePath, line: getLineNumber(content, match.index), snippet: match[0] },
      fix: {
        description:
          'Evaluate necessity. If required, encrypt at rest, restrict access, implement audit logging',
        effort: 'sprint',
        automated: false,
      },
      references: ['https://gdpr-info.eu/art-87-gdpr/'],
    });
  }

  return { passed: total === 0 ? 1 : total - issues, total: Math.max(total, 1) };
}

function checkDateOfBirth(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isNonCodeFile(filePath)) continue;

    const pattern = /(?:dateOfBirth|date_of_birth|dob|birthDate|birth_date|birthday)\s*[:=]/gi;
    const match = pattern.exec(content);
    if (!match) continue;

    total++;
    if (!/(?:age.?verif|consent|gdpr)/i.test(content)) {
      issues++;
      findings.push({
        id: 'CMP-PD-006',
        severity: 'medium',
        layer: LAYER,
        layerName: NAME,
        regulation: [
          { framework: 'gdpr', article: 'Art. 8', title: 'Conditions for Child Consent' },
        ],
        title: 'Date of birth collection detected',
        description: `${filePath} collects date of birth data`,
        impact:
          'DOB combined with name creates identity risk. Also triggers COPPA if minors are served',
        evidence: { file: filePath, line: getLineNumber(content, match.index), snippet: match[0] },
        fix: {
          description:
            'Consider collecting age range instead of exact DOB. Add age verification if serving minors',
          effort: 'sprint',
          automated: false,
        },
        references: ['https://gdpr-info.eu/art-8-gdpr/'],
      });
    }
  }

  return { passed: total === 0 ? 1 : total - issues, total: Math.max(total, 1) };
}

function checkIPAddressLogging(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isNonCodeFile(filePath)) continue;

    const pattern =
      /(?:ip_address|ipAddress|clientIp|client_ip|remoteAddress|x-forwarded-for)\s*[:=]|(?:req\.ip|request\.ip)\b/gi;
    const match = pattern.exec(content);
    if (!match) continue;

    total++;
    // Check for storage/logging (not just reading)
    if (/(?:save|store|log|insert|write|persist|database|db\.|\.create)/i.test(content)) {
      issues++;
      findings.push({
        id: 'CMP-PD-007',
        severity: 'medium',
        layer: LAYER,
        layerName: NAME,
        regulation: [
          { framework: 'gdpr', article: 'Art. 4(1)', title: 'Definition of Personal Data' },
        ],
        title: 'IP address logging/storage detected',
        description: `${filePath} stores or logs IP addresses — classified as personal data under GDPR`,
        impact:
          'IP addresses are personal data under GDPR. Storage requires legal basis and retention limits',
        evidence: { file: filePath, line: getLineNumber(content, match.index), snippet: match[0] },
        fix: {
          description:
            'Anonymize or truncate IP addresses before storage. Add retention policy for IP logs',
          effort: 'sprint',
          automated: false,
        },
        references: ['https://gdpr-info.eu/art-4-gdpr/'],
      });
    }
  }

  return { passed: total === 0 ? 1 : total - issues, total: Math.max(total, 1) };
}

function checkGeolocation(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isNonCodeFile(filePath)) continue;

    const pattern =
      /(?:geolocation|navigator\.geolocation|latitude|longitude|geoip|geo_ip|locationData|userLocation)\b/gi;
    const match = pattern.exec(content);
    if (!match) continue;

    total++;
    if (!/(?:consent|permission|opt.?in)/i.test(content)) {
      issues++;
      findings.push({
        id: 'CMP-PD-008',
        severity: 'high',
        layer: LAYER,
        layerName: NAME,
        regulation: [
          { framework: 'gdpr', article: 'Art. 9', title: 'Processing of Special Categories' },
          { framework: 'ccpa', article: '§1798.140(o)', title: 'Geolocation Data' },
        ],
        title: 'Geolocation data collection without consent',
        description: `${filePath} collects geolocation data without visible consent mechanism`,
        impact:
          'Precise geolocation is sensitive data under CCPA and may require explicit consent under GDPR',
        evidence: { file: filePath, line: getLineNumber(content, match.index), snippet: match[0] },
        fix: {
          description:
            'Implement explicit consent before collecting geolocation. Consider using approximate location',
          effort: 'sprint',
          automated: false,
        },
        references: ['https://gdpr-info.eu/art-9-gdpr/'],
      });
    }
  }

  return { passed: total === 0 ? 1 : total - issues, total: Math.max(total, 1) };
}

function checkBiometricData(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isNonCodeFile(filePath)) continue;

    const pattern =
      /(?:biometric|fingerprint|faceId|face_id|faceRecognition|voicePrint|retina|iris.?scan)\s*[.:=({[]/gi;
    const match = pattern.exec(content);
    if (!match) continue;

    // "fingerprint" alone is commonly used for code hashing — require biometric context
    if (
      /^fingerprint/i.test(match[0]) &&
      !/(?:biometric|faceId|face_id|retina|iris|voice.?print|face.?recognition)\b/i.test(content)
    ) {
      continue;
    }

    total++;
    issues++;
    findings.push({
      id: 'CMP-PD-009',
      severity: 'critical',
      layer: LAYER,
      layerName: NAME,
      regulation: [
        { framework: 'gdpr', article: 'Art. 9', title: 'Special Categories of Data' },
        { framework: 'ccpa', article: '§1798.140(b)', title: 'Biometric Information' },
        { framework: 'hipaa', article: '§164.312', title: 'Technical Safeguards' },
      ],
      title: 'Biometric data processing detected',
      description: `${filePath} processes biometric data — special category under GDPR Art. 9`,
      impact:
        'Biometric data requires explicit consent and is subject to the highest protection standards',
      evidence: { file: filePath, line: getLineNumber(content, match.index), snippet: match[0] },
      fix: {
        description:
          'Ensure explicit consent, implement strong encryption, conduct DPIA (Data Protection Impact Assessment)',
        effort: 'quarter',
        automated: false,
      },
      references: ['https://gdpr-info.eu/art-9-gdpr/'],
    });
  }

  return { passed: total === 0 ? 1 : total - issues, total: Math.max(total, 1) };
}

function checkSensitiveCategories(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isNonCodeFile(filePath)) continue;

    const pattern =
      /(?:healthData|health_data|medicalRecord|medical_record|diagnosis|prescription|religion|religious|ethnicity|ethnic|politicalOpinion|political_opinion|sexualOrientation|sexual_orientation|tradeUnion|trade_union)\s*[:=]/gi;
    const match = pattern.exec(content);
    if (!match) continue;

    total++;
    issues++;
    findings.push({
      id: 'CMP-PD-010',
      severity: 'critical',
      layer: LAYER,
      layerName: NAME,
      regulation: [
        { framework: 'gdpr', article: 'Art. 9', title: 'Special Categories of Data' },
        { framework: 'hipaa', article: '§164.502', title: 'Uses and Disclosures of PHI' },
      ],
      title: 'Sensitive category data processing',
      description: `${filePath} processes special category data (health, religion, political, etc.)`,
      impact:
        'Special category data is prohibited from processing without explicit consent or legal exemption',
      evidence: { file: filePath, line: getLineNumber(content, match.index), snippet: match[0] },
      fix: {
        description:
          'Conduct DPIA. Ensure Art. 9(2) exemption applies. Implement explicit consent flow',
        effort: 'quarter',
        automated: false,
      },
      references: ['https://gdpr-info.eu/art-9-gdpr/'],
    });
  }

  return { passed: total === 0 ? 1 : total - issues, total: Math.max(total, 1) };
}

function checkFinancialData(
  files: Map<string, string>,
  findings: ComplyFinding[],
): { passed: number; total: number } {
  let total = 0;
  let issues = 0;

  for (const [filePath, content] of files) {
    if (isTestFile(filePath) || isNonCodeFile(filePath)) continue;

    const pattern =
      /(?:creditCard|credit_card|cardNumber|card_number|bankAccount|bank_account|iban|routingNumber|routing_number|cvv|cvc)\s*[:=]/gi;
    const match = pattern.exec(content);
    if (!match) continue;

    total++;
    if (!/(?:stripe|paypal|braintree|square|adyen|encrypt|tokenize|pci)/i.test(content)) {
      issues++;
      findings.push({
        id: 'CMP-PD-011',
        severity: 'high',
        layer: LAYER,
        layerName: NAME,
        regulation: [
          { framework: 'gdpr', article: 'Art. 32', title: 'Security of Processing' },
          { framework: 'soc2', article: 'CC6.1', title: 'Logical and Physical Access Controls' },
        ],
        title: 'Financial data collection without payment processor',
        description: `${filePath} handles financial data directly without a certified payment processor`,
        impact:
          'Direct handling of financial data creates PCI-DSS scope and increases breach liability',
        evidence: { file: filePath, line: getLineNumber(content, match.index), snippet: match[0] },
        fix: {
          description:
            'Use a PCI-compliant payment processor (Stripe, etc.) instead of handling card data directly',
          effort: 'sprint',
          automated: false,
        },
        references: ['https://gdpr-info.eu/art-32-gdpr/'],
      });
    }
  }

  return { passed: total === 0 ? 1 : total - issues, total: Math.max(total, 1) };
}

export async function runPersonalDataLayer(
  files: Map<string, string>,
  _stackTags: Set<string>,
  _projectRoot: string,
  _frameworks: Set<ComplianceFramework>,
): Promise<ComplyLayerResult> {
  const findings: ComplyFinding[] = [];

  const checks = [
    checkEmailCollection(files, findings),
    checkNameFields(files, findings),
    checkPhoneNumbers(files, findings),
    checkPhysicalAddress(files, findings),
    checkSSNNationalID(files, findings),
    checkDateOfBirth(files, findings),
    checkIPAddressLogging(files, findings),
    checkGeolocation(files, findings),
    checkBiometricData(files, findings),
    checkSensitiveCategories(files, findings),
    checkFinancialData(files, findings),
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
