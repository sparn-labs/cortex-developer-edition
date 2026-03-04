import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { runAccessControlLayer } from '../../../src/core/secure/layers/access-control.js';
import { runAuthSessionLayer } from '../../../src/core/secure/layers/auth-session.js';
import { runCryptographyLayer } from '../../../src/core/secure/layers/cryptography.js';
import { runExceptionsLayer } from '../../../src/core/secure/layers/exceptions.js';
import { runInjectionLayer } from '../../../src/core/secure/layers/injection.js';
import { runLoggingLayer } from '../../../src/core/secure/layers/logging.js';
import { runMisconfigurationLayer } from '../../../src/core/secure/layers/misconfiguration.js';
import { runSecureDesignLayer } from '../../../src/core/secure/layers/secure-design.js';
import { runSupplyChainLayer } from '../../../src/core/secure/layers/supply-chain.js';

const tmpDir = join(process.cwd(), '.test-secure-layers-tmp');

function setup(): void {
  rmSync(tmpDir, { recursive: true, force: true });
  mkdirSync(join(tmpDir, 'src'), { recursive: true });
}

function buildFiles(fileContents: Record<string, string>): Map<string, string> {
  const files = new Map<string, string>();
  for (const [path, content] of Object.entries(fileContents)) {
    files.set(path, content);
    const fullPath = join(tmpDir, path);
    mkdirSync(dirname(fullPath), { recursive: true });
    writeFileSync(fullPath, content);
  }
  return files;
}

describe('Security Layers', () => {
  beforeEach(setup);
  afterEach(() => rmSync(tmpDir, { recursive: true, force: true }));

  describe('Layer 1 — Access Control', () => {
    it('should detect routes without auth middleware', async () => {
      const files = buildFiles({
        'src/server.ts': `
          app.get('/api/users', async (req, res) => { res.json([]); });
          app.post('/api/data', async (req, res) => { res.json({}); });
        `,
      });

      const result = await runAccessControlLayer(files, new Set(['typescript']), tmpDir);

      const finding = result.findings.find((f) => f.id === 'SEC-AC-001');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('high');
      expect(finding?.owasp).toBe('A01:2025');
    });

    it('should not flag routes with auth middleware', async () => {
      const files = buildFiles({
        'src/server.ts': `
          import { authenticate } from './middleware';
          app.get('/api/users', authenticate, async (req, res) => { res.json([]); });
        `,
      });

      const result = await runAccessControlLayer(files, new Set(['typescript']), tmpDir);
      const finding = result.findings.find((f) => f.id === 'SEC-AC-001');
      expect(finding).toBeUndefined();
    });

    it('should detect CORS wildcard', async () => {
      const files = buildFiles({
        'src/app.ts': `res.setHeader('Access-Control-Allow-Origin', '*');`,
      });

      const result = await runAccessControlLayer(files, new Set(['typescript']), tmpDir);
      const finding = result.findings.find((f) => f.id === 'SEC-AC-003');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('medium');
    });

    it('should detect IDOR patterns', async () => {
      const files = buildFiles({
        'src/controller.ts': `
          const userId = req.params.userId;
          const data = await db.find({ userId });
        `,
      });

      const result = await runAccessControlLayer(files, new Set(['typescript']), tmpDir);
      const finding = result.findings.find((f) => f.id === 'SEC-AC-002');
      expect(finding).toBeDefined();
    });
  });

  describe('Layer 2 — Misconfiguration', () => {
    it('should detect missing security headers when no helmet', async () => {
      const files = buildFiles({
        'src/app.ts': `const app = express(); app.listen(3000);`,
      });

      const result = await runMisconfigurationLayer(files, new Set(), tmpDir);
      const finding = result.findings.find((f) => f.id === 'SEC-MC-001');
      expect(finding).toBeDefined();
    });

    it('should not flag when helmet is used', async () => {
      const files = buildFiles({
        'src/app.ts': `import helmet from 'helmet'; app.use(helmet());`,
      });

      const result = await runMisconfigurationLayer(files, new Set(), tmpDir);
      const finding = result.findings.find((f) => f.id === 'SEC-MC-001');
      expect(finding).toBeUndefined();
    });
  });

  describe('Layer 3 — Supply Chain', () => {
    it('should detect compromised packages', async () => {
      const files = buildFiles({
        'package.json': JSON.stringify({
          dependencies: { 'event-stream': '4.0.0', express: '4.18.0' },
        }),
      });

      const result = await runSupplyChainLayer(files, new Set(), tmpDir);
      const finding = result.findings.find((f) => f.id === 'SEC-SC-004');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('critical');
    });

    it('should detect typosquatting', async () => {
      const files = buildFiles({
        'package.json': JSON.stringify({
          dependencies: { lodas: '1.0.0' },
        }),
      });

      const result = await runSupplyChainLayer(files, new Set(), tmpDir);
      const finding = result.findings.find((f) => f.id === 'SEC-SC-008');
      expect(finding).toBeDefined();
      expect(finding?.title).toContain('lodas');
    });

    it('should detect unpinned dependencies', async () => {
      const files = buildFiles({
        'package.json': JSON.stringify({
          dependencies: { express: '^4.18.0', react: '~18.0.0' },
        }),
      });

      const result = await runSupplyChainLayer(files, new Set(), tmpDir);
      const finding = result.findings.find((f) => f.id === 'SEC-SC-003');
      expect(finding).toBeDefined();
    });
  });

  describe('Layer 4 — Cryptography', () => {
    it('should detect weak hashing (MD5)', async () => {
      const files = buildFiles({
        'src/hash.ts': `const hash = createHash('md5').update(data).digest('hex');`,
      });

      const result = await runCryptographyLayer(files, new Set(), tmpDir);
      const finding = result.findings.find((f) => f.id === 'SEC-CR-001');
      expect(finding).toBeDefined();
      expect(finding?.title).toContain('MD5');
    });

    it('should detect hardcoded secrets', async () => {
      const files = buildFiles({
        'src/config.ts': `const api_key = 'sk-live-abcdefghijklmnopqrstuvwx';`,
      });

      const result = await runCryptographyLayer(files, new Set(), tmpDir);
      const finding = result.findings.find((f) => f.id === 'SEC-CR-002');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('critical');
    });

    it('should detect Math.random in security context', async () => {
      const files = buildFiles({
        'src/token.ts': `function generateToken() { return Math.random().toString(36); }`,
      });

      const result = await runCryptographyLayer(files, new Set(), tmpDir);
      const finding = result.findings.find((f) => f.id === 'SEC-CR-005');
      expect(finding).toBeDefined();
    });
  });

  describe('Layer 5 — Injection', () => {
    it('should detect SQL injection via template literals', async () => {
      const files = buildFiles({
        // biome-ignore lint/suspicious/noTemplateCurlyInString: test fixture for SQL injection detection
        'src/db.ts': 'const result = db.query(`SELECT * FROM users WHERE id = ${userId}`);',
      });

      const result = await runInjectionLayer(files, new Set(), tmpDir);
      const finding = result.findings.find((f) => f.id === 'SEC-INJ-001');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('critical');
    });

    it('should not flag SQL with prepared statements', async () => {
      const files = buildFiles({
        'src/db.ts': `const stmt = db.prepare('SELECT * FROM users WHERE id = ?'); stmt.run(userId);`,
      });

      const result = await runInjectionLayer(files, new Set(), tmpDir);
      const finding = result.findings.find((f) => f.id === 'SEC-INJ-001');
      expect(finding).toBeUndefined();
    });

    it('should detect XSS via dangerouslySetInnerHTML', async () => {
      const files = buildFiles({
        'src/component.tsx': `<div dangerouslySetInnerHTML={{ __html: userInput }} />`,
      });

      const result = await runInjectionLayer(files, new Set(['react']), tmpDir);
      const finding = result.findings.find((f) => f.id === 'SEC-INJ-002');
      expect(finding).toBeDefined();
    });

    it('should detect eval() usage', async () => {
      const files = buildFiles({
        'src/compute.ts': `const result = eval(userExpression);`,
      });

      const result = await runInjectionLayer(files, new Set(), tmpDir);
      const finding = result.findings.find((f) => f.id === 'SEC-INJ-003');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('critical');
    });
  });

  describe('Layer 6 — Secure Design', () => {
    it('should detect missing rate limiting', async () => {
      const files = buildFiles({
        'src/server.ts': `app.get('/api/data', handler); app.post('/api/save', handler);`,
      });

      const result = await runSecureDesignLayer(files, new Set(), tmpDir);
      const finding = result.findings.find((f) => f.id === 'SEC-SD-001');
      expect(finding).toBeDefined();
    });

    it('should detect missing input validation', async () => {
      const files = buildFiles({
        'src/server.ts': `app.post('/api/create', (req, res) => { db.create(req.body); });`,
      });

      const result = await runSecureDesignLayer(files, new Set(), tmpDir);
      const finding = result.findings.find((f) => f.id === 'SEC-SD-002');
      expect(finding).toBeDefined();
    });

    it('should detect missing error boundaries in React', async () => {
      const files = buildFiles({
        'src/App.tsx': `export default function App() { return <div>Hello</div>; }`,
      });

      const result = await runSecureDesignLayer(files, new Set(['react']), tmpDir);
      const finding = result.findings.find((f) => f.id === 'SEC-SD-003');
      expect(finding).toBeDefined();
    });
  });

  describe('Layer 7 — Auth & Session', () => {
    it('should detect account enumeration', async () => {
      const files = buildFiles({
        'src/auth.ts': `
          if (!user) throw new Error('User not found');
          if (!bcrypt.compare(pass, user.hash)) throw new Error('Wrong password');
        `,
      });

      const result = await runAuthSessionLayer(files, new Set(), tmpDir);
      const finding = result.findings.find((f) => f.id === 'SEC-AS-003');
      expect(finding).toBeDefined();
    });
  });

  describe('Layer 9 — Logging', () => {
    it('should detect sensitive data in logs', async () => {
      const files = buildFiles({
        'src/auth.ts': `console.log('Login attempt:', { password: req.body.password });`,
      });

      const result = await runLoggingLayer(files, new Set(), tmpDir);
      const finding = result.findings.find((f) => f.id === 'SEC-LOG-003');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('high');
    });
  });

  describe('Layer 10 — Exceptions', () => {
    it('should detect stack trace leaks', async () => {
      const files = buildFiles({
        'src/handler.ts': `catch (err) { res.json({ error: err.stack }); }`,
      });

      const result = await runExceptionsLayer(files, new Set(), tmpDir);
      const finding = result.findings.find((f) => f.id === 'SEC-EX-002');
      expect(finding).toBeDefined();
    });
  });
});
