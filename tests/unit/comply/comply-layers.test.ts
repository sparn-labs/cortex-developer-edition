/**
 * Comply Layers Tests — synthetic file maps with positive and negative cases
 */

import { describe, expect, it } from 'vitest';
import { runBreachResponseLayer } from '../../../src/core/comply/layers/breach-response.js';
import { runConsentNoticeLayer } from '../../../src/core/comply/layers/consent-notice.js';
import { runCrossBorderLayer } from '../../../src/core/comply/layers/cross-border.js';
import { runDataMinimizationLayer } from '../../../src/core/comply/layers/data-minimization.js';
import { runDataProtectionLayer } from '../../../src/core/comply/layers/data-protection.js';
import { runDataRightsLayer } from '../../../src/core/comply/layers/data-rights.js';
import { runPersonalDataLayer } from '../../../src/core/comply/layers/personal-data.js';
import { runThirdPartyLayer } from '../../../src/core/comply/layers/third-party.js';
import type { ComplianceFramework } from '../../../src/core/comply/types.js';

const emptyStack = new Set<string>();
const allFrameworks = new Set<ComplianceFramework>(['all']);

describe('Layer 1 — Personal Data Handling', () => {
  it('should detect email collection without consent', async () => {
    const files = new Map([
      ['src/user.ts', 'const email = req.body.email;\ndb.save({ email: email });'],
    ]);

    const result = await runPersonalDataLayer(files, emptyStack, '/tmp', allFrameworks);
    expect(result.findings.some((f) => f.id === 'CMP-PD-001')).toBe(true);
  });

  it('should not flag email collection with consent reference', async () => {
    const files = new Map([
      [
        'src/user.ts',
        'const email = req.body.email;\n// consent obtained via opt-in form\nif (consent) { db.save({ email }); }',
      ],
    ]);

    const result = await runPersonalDataLayer(files, emptyStack, '/tmp', allFrameworks);
    expect(result.findings.some((f) => f.id === 'CMP-PD-001')).toBe(false);
  });

  it('should detect SSN collection as critical', async () => {
    const files = new Map([['src/kyc.ts', 'const ssn = form.ssn;\ndb.insert({ ssn: ssn });']]);

    const result = await runPersonalDataLayer(files, emptyStack, '/tmp', allFrameworks);
    const ssnFinding = result.findings.find((f) => f.id === 'CMP-PD-005');
    expect(ssnFinding).toBeDefined();
    expect(ssnFinding?.severity).toBe('critical');
  });

  it('should detect biometric data as critical', async () => {
    const files = new Map([['src/auth.ts', 'const biometric = await scanner.getBiometricData();']]);

    const result = await runPersonalDataLayer(files, emptyStack, '/tmp', allFrameworks);
    expect(result.findings.some((f) => f.id === 'CMP-PD-009' && f.severity === 'critical')).toBe(
      true,
    );
  });

  it('should detect financial data without payment processor', async () => {
    const files = new Map([
      ['src/payment.ts', 'const creditCard = req.body.creditCard;\ndb.save({ creditCard });'],
    ]);

    const result = await runPersonalDataLayer(files, emptyStack, '/tmp', allFrameworks);
    expect(result.findings.some((f) => f.id === 'CMP-PD-011')).toBe(true);
  });

  it('should not flag financial data with Stripe', async () => {
    const files = new Map([
      [
        'src/payment.ts',
        'import stripe from "stripe";\nconst creditCard = req.body.creditCard;\nstripe.paymentIntents.create({});',
      ],
    ]);

    const result = await runPersonalDataLayer(files, emptyStack, '/tmp', allFrameworks);
    expect(result.findings.some((f) => f.id === 'CMP-PD-011')).toBe(false);
  });

  it('should skip test files', async () => {
    const files = new Map([
      ['src/user.test.ts', 'const ssn = "123-45-6789";\nexpect(validate(ssn)).toBe(true);'],
    ]);

    const result = await runPersonalDataLayer(files, emptyStack, '/tmp', allFrameworks);
    expect(result.findings).toHaveLength(0);
  });

  it('should return correct layer metadata', async () => {
    const result = await runPersonalDataLayer(new Map(), emptyStack, '/tmp', allFrameworks);
    expect(result.layer).toBe(1);
    expect(result.name).toBe('Personal Data Handling');
    expect(result.weight).toBe(20);
  });
});

describe('Layer 2 — Consent & Notice', () => {
  it('should detect missing privacy policy', async () => {
    const files = new Map([['src/app.ts', 'const app = express();']]);

    const result = await runConsentNoticeLayer(files, emptyStack, '/tmp', allFrameworks);
    expect(result.findings.some((f) => f.id === 'CMP-CN-001')).toBe(true);
  });

  it('should pass when privacy policy file exists', async () => {
    const files = new Map([['privacy-policy.md', '# Privacy Policy\n\nWe collect data...']]);

    const result = await runConsentNoticeLayer(files, emptyStack, '/tmp', allFrameworks);
    expect(result.findings.some((f) => f.id === 'CMP-CN-001')).toBe(false);
  });

  it('should detect tracking without consent gate', async () => {
    const files = new Map([
      ['src/analytics.ts', 'gtag("config", "GA_ID");\ngtag("event", "page_view");'],
    ]);

    const result = await runConsentNoticeLayer(files, emptyStack, '/tmp', allFrameworks);
    expect(result.findings.some((f) => f.id === 'CMP-CN-005')).toBe(true);
  });

  it('should pass tracking with consent gate', async () => {
    const files = new Map([
      ['src/analytics.ts', 'if (hasConsent("analytics")) { gtag("config", "GA_ID"); }'],
    ]);

    const result = await runConsentNoticeLayer(files, emptyStack, '/tmp', allFrameworks);
    expect(result.findings.some((f) => f.id === 'CMP-CN-005')).toBe(false);
  });

  it('should detect data collection without consent in signup', async () => {
    const files = new Map([
      [
        'src/auth.ts',
        'async function signup(req) { const { email, name } = req.body; db.create({ email, name }); }',
      ],
    ]);

    const result = await runConsentNoticeLayer(files, emptyStack, '/tmp', allFrameworks);
    expect(result.findings.some((f) => f.id === 'CMP-CN-004')).toBe(true);
  });
});

describe('Layer 3 — Data Subject Rights', () => {
  it('should detect missing data deletion when auth exists', async () => {
    const files = new Map([
      ['src/auth.ts', 'async function login(email, password) { return jwt.sign({ email }); }'],
      ['src/user.ts', 'async function getProfile(id) { return db.findById(id); }'],
    ]);

    const result = await runDataRightsLayer(files, emptyStack, '/tmp', allFrameworks);
    expect(result.findings.some((f) => f.id === 'CMP-DR-002')).toBe(true);
  });

  it('should detect missing data export when auth exists', async () => {
    const files = new Map([['src/auth.ts', 'app.post("/signup", handler);']]);

    const result = await runDataRightsLayer(files, emptyStack, '/tmp', allFrameworks);
    expect(result.findings.some((f) => f.id === 'CMP-DR-001')).toBe(true);
  });

  it('should pass when deletion endpoint exists', async () => {
    const files = new Map([
      ['src/auth.ts', 'app.post("/login", handler);'],
      ['src/account.ts', 'async function deleteAccount(userId) { await db.deleteUser(userId); }'],
    ]);

    const result = await runDataRightsLayer(files, emptyStack, '/tmp', allFrameworks);
    expect(result.findings.some((f) => f.id === 'CMP-DR-002')).toBe(false);
  });

  it('should not flag when no auth patterns exist', async () => {
    const files = new Map([
      ['src/utils.ts', 'export function formatDate(d: Date) { return d.toISOString(); }'],
    ]);

    const result = await runDataRightsLayer(files, emptyStack, '/tmp', allFrameworks);
    expect(result.findings).toHaveLength(0);
  });

  it('should check CCPA opt-out only when ccpa framework selected', async () => {
    const files = new Map([
      ['src/auth.ts', 'async function signup(data) { return db.create(data); }'],
      ['src/analytics.ts', 'segment.track("event", data); // third party sharing'],
    ]);

    const ccpaOnly = new Set<ComplianceFramework>(['ccpa']);
    const result = await runDataRightsLayer(files, emptyStack, '/tmp', ccpaOnly);
    expect(result.findings.some((f) => f.id === 'CMP-DR-006')).toBe(true);
  });
});

describe('Layer 4 — Data Minimization & Retention', () => {
  it('should detect PII in log statements', async () => {
    const files = new Map([
      [
        'src/debug.ts',
        'console.log("User email:", user.email);\nlogger.info("Password reset for:", password);',
      ],
    ]);

    const result = await runDataMinimizationLayer(files, emptyStack, '/tmp', allFrameworks);
    expect(result.findings.some((f) => f.id === 'CMP-DM-006')).toBe(true);
  });

  it('should detect missing retention policy', async () => {
    const files = new Map([
      [
        'src/db.ts',
        'import { PrismaClient } from "@prisma/client";\nconst prisma = new PrismaClient();',
      ],
    ]);

    const result = await runDataMinimizationLayer(files, emptyStack, '/tmp', allFrameworks);
    expect(result.findings.some((f) => f.id === 'CMP-DM-002')).toBe(true);
  });
});

describe('Layer 5 — Cross-Border Data Transfers', () => {
  it('should detect non-EU cloud region for GDPR', async () => {
    const files = new Map([
      ['src/config.ts', 'const region = "us-east-1";\nexport const AWS_REGION = region;'],
    ]);

    const result = await runCrossBorderLayer(files, emptyStack, '/tmp', allFrameworks);
    expect(result.findings.some((f) => f.id === 'CMP-CB-001')).toBe(true);
  });

  it('should skip region check when GDPR not selected', async () => {
    const files = new Map([
      ['src/config.ts', 'const region = "us-east-1";\nexport const AWS_REGION = region;'],
    ]);

    const hipaaOnly = new Set<ComplianceFramework>(['hipaa']);
    const result = await runCrossBorderLayer(files, emptyStack, '/tmp', hipaaOnly);
    expect(result.findings.some((f) => f.id === 'CMP-CB-001')).toBe(false);
  });
});

describe('Layer 6 — Data Protection & Encryption', () => {
  it('should detect TLS validation disabled', async () => {
    const files = new Map([
      ['src/api.ts', 'const agent = new https.Agent({ rejectUnauthorized: false });'],
    ]);

    const result = await runDataProtectionLayer(files, emptyStack, '/tmp', allFrameworks);
    const finding = result.findings.find((f) => f.id === 'CMP-DP-006');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('critical');
  });

  it('should detect non-HTTPS connections', async () => {
    const files = new Map([
      ['src/api.ts', 'fetch("http://api.example.com/data");\nconsole.log("done");'],
    ]);

    const result = await runDataProtectionLayer(files, emptyStack, '/tmp', allFrameworks);
    expect(result.findings.some((f) => f.id === 'CMP-DP-002')).toBe(true);
  });

  it('should not flag localhost HTTP', async () => {
    const files = new Map([['src/dev.ts', 'fetch("http://localhost:3000/api/test");']]);

    const result = await runDataProtectionLayer(files, emptyStack, '/tmp', allFrameworks);
    expect(result.findings.some((f) => f.id === 'CMP-DP-002')).toBe(false);
  });
});

describe('Layer 7 — Third-Party & Vendor Compliance', () => {
  it('should detect analytics without consent gate', async () => {
    const files = new Map([
      ['src/tracking.ts', 'mixpanel.track("page_view", { page: window.location.href });'],
    ]);

    const result = await runThirdPartyLayer(files, emptyStack, '/tmp', allFrameworks);
    expect(result.findings.some((f) => f.id === 'CMP-TP-001')).toBe(true);
  });

  it('should detect advertising SDK without consent', async () => {
    const files = new Map([
      ['src/ads.ts', 'import { AdMob } from "@admob";\nAdMob.showInterstitial();'],
    ]);

    const result = await runThirdPartyLayer(files, emptyStack, '/tmp', allFrameworks);
    expect(result.findings.some((f) => f.id === 'CMP-TP-004')).toBe(true);
  });
});

describe('Layer 8 — Breach & Incident Response', () => {
  it('should detect missing incident response plan', async () => {
    const files = new Map([['src/app.ts', 'const app = express();\napp.listen(3000);']]);

    const result = await runBreachResponseLayer(files, emptyStack, '/tmp', allFrameworks);
    expect(result.findings.some((f) => f.id === 'CMP-BR-001')).toBe(true);
  });

  it('should pass when incident response file exists', async () => {
    const files = new Map([
      ['docs/incident-response.md', '# Incident Response Plan\n\n1. Detect\n2. Contain\n3. Notify'],
    ]);

    const result = await runBreachResponseLayer(files, emptyStack, '/tmp', allFrameworks);
    expect(result.findings.some((f) => f.id === 'CMP-BR-001')).toBe(false);
  });

  it('should detect missing audit trail when auth exists', async () => {
    const files = new Map([
      ['src/auth.ts', 'async function login(email, pw) { return jwt.sign({ email }); }'],
    ]);

    const result = await runBreachResponseLayer(files, emptyStack, '/tmp', allFrameworks);
    expect(result.findings.some((f) => f.id === 'CMP-BR-004')).toBe(true);
  });

  it('should check DPO only for GDPR', async () => {
    const files = new Map([['src/app.ts', 'const app = express();']]);

    const hipaaOnly = new Set<ComplianceFramework>(['hipaa']);
    const result = await runBreachResponseLayer(files, emptyStack, '/tmp', hipaaOnly);
    expect(result.findings.some((f) => f.id === 'CMP-BR-005')).toBe(false);
  });
});
