/**
 * Debt Tracker Tests
 */

import { mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createDebtTracker } from '../../src/core/debt-tracker.js';

describe('Debt Tracker', () => {
  const tmpDir = join(process.cwd(), '.test-debt-tmp');
  const dbPath = join(tmpDir, 'debt.db');

  beforeEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    mkdirSync(tmpDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('add', () => {
    it('should add a new debt item', async () => {
      const tracker = createDebtTracker(dbPath);

      const debt = await tracker.add({
        description: 'Refactor auth middleware',
        repayment_date: Date.now() + 7 * 24 * 60 * 60 * 1000,
        severity: 'P1',
        token_cost: 5000,
        files_affected: ['src/auth.ts', 'src/middleware.ts'],
      });

      expect(debt.id).toBeDefined();
      expect(debt.description).toBe('Refactor auth middleware');
      expect(debt.severity).toBe('P1');
      expect(debt.token_cost).toBe(5000);
      expect(debt.status).toBe('open');
      expect(debt.files_affected).toEqual(['src/auth.ts', 'src/middleware.ts']);

      await tracker.close();
    });

    it('should assign unique IDs', async () => {
      const tracker = createDebtTracker(dbPath);

      const d1 = await tracker.add({
        description: 'Debt 1',
        repayment_date: Date.now() + 86400000,
        severity: 'P1',
        token_cost: 0,
        files_affected: [],
      });

      const d2 = await tracker.add({
        description: 'Debt 2',
        repayment_date: Date.now() + 86400000,
        severity: 'P2',
        token_cost: 0,
        files_affected: [],
      });

      expect(d1.id).not.toBe(d2.id);

      await tracker.close();
    });
  });

  describe('get', () => {
    it('should retrieve a debt by ID', async () => {
      const tracker = createDebtTracker(dbPath);

      const created = await tracker.add({
        description: 'Get test',
        repayment_date: Date.now() + 86400000,
        severity: 'P0',
        token_cost: 1000,
        files_affected: ['src/test.ts'],
      });

      const fetched = await tracker.get(created.id);

      expect(fetched).not.toBeNull();
      expect(fetched?.description).toBe('Get test');
      expect(fetched?.severity).toBe('P0');
      expect(fetched?.files_affected).toEqual(['src/test.ts']);

      await tracker.close();
    });

    it('should return null for non-existent ID', async () => {
      const tracker = createDebtTracker(dbPath);

      const result = await tracker.get('nonexistent');
      expect(result).toBeNull();

      await tracker.close();
    });
  });

  describe('list', () => {
    it('should list all debts', async () => {
      const tracker = createDebtTracker(dbPath);

      await tracker.add({
        description: 'D1',
        repayment_date: Date.now() + 86400000,
        severity: 'P0',
        token_cost: 0,
        files_affected: [],
      });
      await tracker.add({
        description: 'D2',
        repayment_date: Date.now() + 86400000,
        severity: 'P1',
        token_cost: 0,
        files_affected: [],
      });
      await tracker.add({
        description: 'D3',
        repayment_date: Date.now() + 86400000,
        severity: 'P2',
        token_cost: 0,
        files_affected: [],
      });

      const debts = await tracker.list();
      expect(debts).toHaveLength(3);

      await tracker.close();
    });

    it('should filter by severity', async () => {
      const tracker = createDebtTracker(dbPath);

      await tracker.add({
        description: 'Critical',
        repayment_date: Date.now() + 86400000,
        severity: 'P0',
        token_cost: 0,
        files_affected: [],
      });
      await tracker.add({
        description: 'Normal',
        repayment_date: Date.now() + 86400000,
        severity: 'P1',
        token_cost: 0,
        files_affected: [],
      });

      const p0 = await tracker.list({ severity: 'P0' });
      expect(p0).toHaveLength(1);
      expect(p0[0]?.description).toBe('Critical');

      await tracker.close();
    });

    it('should filter overdue debts', async () => {
      const tracker = createDebtTracker(dbPath);

      // Past date = overdue
      await tracker.add({
        description: 'Overdue',
        repayment_date: Date.now() - 86400000,
        severity: 'P1',
        token_cost: 0,
        files_affected: [],
      });
      // Future date = not overdue
      await tracker.add({
        description: 'On time',
        repayment_date: Date.now() + 86400000 * 30,
        severity: 'P1',
        token_cost: 0,
        files_affected: [],
      });

      const overdue = await tracker.list({ overdue: true });
      expect(overdue).toHaveLength(1);
      expect(overdue[0]?.description).toBe('Overdue');

      await tracker.close();
    });

    it('should filter by status', async () => {
      const tracker = createDebtTracker(dbPath);

      const d1 = await tracker.add({
        description: 'Open',
        repayment_date: Date.now() + 86400000,
        severity: 'P1',
        token_cost: 0,
        files_affected: [],
      });
      await tracker.add({
        description: 'Also Open',
        repayment_date: Date.now() + 86400000,
        severity: 'P1',
        token_cost: 0,
        files_affected: [],
      });
      await tracker.resolve(d1.id);

      const open = await tracker.list({ status: 'open' });
      expect(open).toHaveLength(1);
      expect(open[0]?.description).toBe('Also Open');

      await tracker.close();
    });

    it('should sort by severity then repayment date', async () => {
      const tracker = createDebtTracker(dbPath);

      await tracker.add({
        description: 'P2 Later',
        repayment_date: Date.now() + 86400000 * 30,
        severity: 'P2',
        token_cost: 0,
        files_affected: [],
      });
      await tracker.add({
        description: 'P0 Soon',
        repayment_date: Date.now() + 86400000,
        severity: 'P0',
        token_cost: 0,
        files_affected: [],
      });
      await tracker.add({
        description: 'P1 Mid',
        repayment_date: Date.now() + 86400000 * 7,
        severity: 'P1',
        token_cost: 0,
        files_affected: [],
      });

      const debts = await tracker.list();
      expect(debts[0]?.severity).toBe('P0');
      expect(debts[1]?.severity).toBe('P1');
      expect(debts[2]?.severity).toBe('P2');

      await tracker.close();
    });
  });

  describe('resolve', () => {
    it('should throw when resolving non-existent ID', async () => {
      const tracker = createDebtTracker(dbPath);

      await expect(tracker.resolve('nonexistent')).rejects.toThrow('Debt not found: nonexistent');

      await tracker.close();
    });

    it('should mark debt as resolved', async () => {
      const tracker = createDebtTracker(dbPath);

      const debt = await tracker.add({
        description: 'Resolve me',
        repayment_date: Date.now() + 86400000,
        severity: 'P1',
        token_cost: 1000,
        files_affected: [],
      });

      await tracker.resolve(debt.id, 800);

      const resolved = await tracker.get(debt.id);
      expect(resolved?.status).toBe('resolved');
      expect(resolved?.resolution_tokens).toBe(800);
      expect(resolved?.resolved_at).toBeGreaterThan(0);

      await tracker.close();
    });
  });

  describe('start', () => {
    it('should throw when starting non-existent ID', async () => {
      const tracker = createDebtTracker(dbPath);

      await expect(tracker.start('nonexistent')).rejects.toThrow('Debt not found: nonexistent');

      await tracker.close();
    });

    it('should mark debt as in_progress', async () => {
      const tracker = createDebtTracker(dbPath);

      const debt = await tracker.add({
        description: 'Start me',
        repayment_date: Date.now() + 86400000,
        severity: 'P1',
        token_cost: 0,
        files_affected: [],
      });

      await tracker.start(debt.id);

      const started = await tracker.get(debt.id);
      expect(started?.status).toBe('in_progress');

      await tracker.close();
    });
  });

  describe('remove', () => {
    it('should delete a debt item', async () => {
      const tracker = createDebtTracker(dbPath);

      const debt = await tracker.add({
        description: 'Delete me',
        repayment_date: Date.now() + 86400000,
        severity: 'P2',
        token_cost: 0,
        files_affected: [],
      });

      await tracker.remove(debt.id);

      const fetched = await tracker.get(debt.id);
      expect(fetched).toBeNull();

      await tracker.close();
    });
  });

  describe('stats', () => {
    it('should calculate correct statistics', async () => {
      const tracker = createDebtTracker(dbPath);

      const d1 = await tracker.add({
        description: 'D1',
        repayment_date: Date.now() + 86400000 * 30,
        severity: 'P1',
        token_cost: 1000,
        files_affected: [],
      });
      await tracker.add({
        description: 'D2',
        repayment_date: Date.now() - 86400000,
        severity: 'P0',
        token_cost: 2000,
        files_affected: [],
      });
      const d3 = await tracker.add({
        description: 'D3',
        repayment_date: Date.now() + 86400000 * 30,
        severity: 'P2',
        token_cost: 500,
        files_affected: [],
      });

      await tracker.resolve(d1.id, 900);
      await tracker.start(d3.id);

      const stats = await tracker.stats();

      expect(stats.total).toBe(3);
      expect(stats.open).toBe(1); // D2 still open
      expect(stats.in_progress).toBe(1); // D3
      expect(stats.resolved).toBe(1); // D1
      expect(stats.overdue).toBe(1); // D2
      expect(stats.totalTokenCost).toBe(3500);

      await tracker.close();
    });

    it('should calculate repayment rate', async () => {
      const tracker = createDebtTracker(dbPath);

      // Resolved on time (repayment_date in future when resolved)
      const d1 = await tracker.add({
        description: 'On time',
        repayment_date: Date.now() + 86400000 * 365,
        severity: 'P1',
        token_cost: 100,
        files_affected: [],
      });
      await tracker.resolve(d1.id);

      const stats = await tracker.stats();
      expect(stats.repaymentRate).toBe(1); // 100% on time

      await tracker.close();
    });

    it('should handle empty database', async () => {
      const tracker = createDebtTracker(dbPath);

      const stats = await tracker.stats();
      expect(stats.total).toBe(0);
      expect(stats.repaymentRate).toBe(0);

      await tracker.close();
    });
  });

  describe('getCritical', () => {
    it('should return only unresolved P0 debts', async () => {
      const tracker = createDebtTracker(dbPath);

      await tracker.add({
        description: 'P0 Open',
        repayment_date: Date.now() + 86400000,
        severity: 'P0',
        token_cost: 0,
        files_affected: [],
      });
      const d2 = await tracker.add({
        description: 'P0 Resolved',
        repayment_date: Date.now() + 86400000,
        severity: 'P0',
        token_cost: 0,
        files_affected: [],
      });
      await tracker.add({
        description: 'P1 Open',
        repayment_date: Date.now() + 86400000,
        severity: 'P1',
        token_cost: 0,
        files_affected: [],
      });

      await tracker.resolve(d2.id);

      const critical = await tracker.getCritical();
      expect(critical).toHaveLength(1);
      expect(critical[0]?.description).toBe('P0 Open');

      await tracker.close();
    });
  });
});
