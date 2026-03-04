/**
 * Security & Bug Fix Validation Tests
 *
 * Tests for the critical fixes applied during the v1.3 audit.
 */

import { mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createBudgetPruner } from '../../src/core/budget-pruner.js';
import { createDebtTracker } from '../../src/core/debt-tracker.js';
import { createWorkflowPlanner } from '../../src/core/workflow-planner.js';
import type { MemoryEntry } from '../../src/types/memory.js';

function makeEntry(content: string, overrides: Partial<MemoryEntry> = {}): MemoryEntry {
  return {
    id: `test-${Math.random().toString(36).slice(2)}`,
    content,
    hash: `hash-${Math.random().toString(36).slice(2)}`,
    timestamp: Date.now(),
    score: 0.5,
    ttl: 86400,
    state: 'active',
    accessCount: 0,
    tags: [],
    metadata: {},
    isBTSP: false,
    ...overrides,
  };
}

describe('Path Traversal Prevention', () => {
  const tmpDir = join(process.cwd(), '.test-security-tmp');

  beforeEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    mkdirSync(join(tmpDir, '.cortex'), { recursive: true });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should sanitize plan IDs with path separators', async () => {
    const planner = createWorkflowPlanner(tmpDir);
    // The ID gets sanitized (path chars stripped), so it resolves safely to null
    const result = await planner.loadPlan('../../../etc/passwd');
    expect(result).toBeNull();
  });

  it('should sanitize plan IDs with backslashes', async () => {
    const planner = createWorkflowPlanner(tmpDir);
    // The ID gets sanitized (backslashes stripped), so it resolves safely to null
    const result = await planner.loadPlan('..\\..\\etc\\passwd');
    expect(result).toBeNull();
  });

  it('should reject empty plan IDs after sanitization', async () => {
    const planner = createWorkflowPlanner(tmpDir);
    await expect(planner.loadPlan('../../..')).rejects.toThrow('Invalid plan ID');
  });

  it('should allow valid plan IDs', async () => {
    const planner = createWorkflowPlanner(tmpDir);
    const result = await planner.loadPlan('abc123');
    // Non-existent but valid ID should return null, not throw
    expect(result).toBeNull();
  });
});

describe('Verify does not destroy in-progress plans', () => {
  const tmpDir = join(process.cwd(), '.test-verify-tmp');

  beforeEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    mkdirSync(join(tmpDir, '.cortex'), { recursive: true });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should not mark plan as failed when steps are still pending', async () => {
    const planner = createWorkflowPlanner(tmpDir);

    const plan = await planner.createPlan(
      'In progress test',
      [],
      [],
      [
        {
          order: 1,
          action: 'read' as const,
          target: 'file1',
          description: 'Read file',
          dependencies: [],
          estimated_tokens: 100,
        },
        {
          order: 2,
          action: 'write' as const,
          target: 'file2',
          description: 'Write file',
          dependencies: [1],
          estimated_tokens: 200,
        },
      ],
    );

    // Complete step 1, leave step 2 pending
    await planner.updateStep(plan.id, 1, 'completed');

    const result = await planner.verify(plan.id);

    // Verify should report incomplete but NOT mark as failed
    expect(result.success).toBe(false);
    expect(result.stepsCompleted).toBe(1);

    // Plan should still be in original status, not 'failed'
    const loaded = await planner.loadPlan(plan.id);
    expect(loaded?.status).not.toBe('failed');
  });

  it('should mark plan as completed when all steps done', async () => {
    const planner = createWorkflowPlanner(tmpDir);

    const plan = await planner.createPlan(
      'Complete test',
      [],
      [],
      [
        {
          order: 1,
          action: 'test' as const,
          target: 'tests',
          description: 'Run tests',
          dependencies: [],
          estimated_tokens: 100,
        },
      ],
    );

    await planner.updateStep(plan.id, 1, 'completed');
    await planner.verify(plan.id);

    const loaded = await planner.loadPlan(plan.id);
    expect(loaded?.status).toBe('completed');
  });

  it('should mark plan as failed only when all steps are terminal', async () => {
    const planner = createWorkflowPlanner(tmpDir);

    const plan = await planner.createPlan(
      'Failed test',
      [],
      [],
      [
        {
          order: 1,
          action: 'test' as const,
          target: 'tests',
          description: 'Run tests',
          dependencies: [],
          estimated_tokens: 100,
        },
        {
          order: 2,
          action: 'verify' as const,
          target: 'results',
          description: 'Verify',
          dependencies: [1],
          estimated_tokens: 50,
        },
      ],
    );

    await planner.updateStep(plan.id, 1, 'completed');
    await planner.updateStep(plan.id, 2, 'failed');
    await planner.verify(plan.id);

    const loaded = await planner.loadPlan(plan.id);
    expect(loaded?.status).toBe('failed');
  });
});

describe('Debt Tracker - resolutionTokens edge cases', () => {
  const tmpDir = join(process.cwd(), `.test-debt-resolution-${process.pid}`);
  const dbPath = join(tmpDir, 'debt.db');
  let tracker: Awaited<ReturnType<typeof createDebtTracker>> | null = null;

  beforeEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    mkdirSync(tmpDir, { recursive: true });
  });

  afterEach(async () => {
    if (tracker) {
      await tracker.close();
      tracker = null;
    }
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should store resolutionTokens=0 correctly (not as null)', async () => {
    tracker = createDebtTracker(dbPath);

    const debt = await tracker.add({
      description: 'Test debt',
      repayment_date: Date.now() + 86400000,
      severity: 'P1',
      token_cost: 1000,
      files_affected: ['src/test.ts'],
    });

    // Resolve with exactly 0 tokens
    await tracker.resolve(debt.id, 0);

    const loaded = await tracker.get(debt.id);
    expect(loaded?.status).toBe('resolved');
    expect(loaded?.resolution_tokens).toBe(0);
    expect(loaded?.resolved_at).toBeDefined();
  });

  it('should store resolutionTokens=undefined as null', async () => {
    tracker = createDebtTracker(dbPath);

    const debt = await tracker.add({
      description: 'Test debt 2',
      repayment_date: Date.now() + 86400000,
      severity: 'P2',
      token_cost: 500,
      files_affected: [],
    });

    await tracker.resolve(debt.id);

    const loaded = await tracker.get(debt.id);
    expect(loaded?.status).toBe('resolved');
    // SQLite NULL maps to JS null
    expect(loaded?.resolution_tokens).toBeNull();
  });
});

describe('Budget Pruner - BTSP budget guard', () => {
  it('should not let BTSP entries exceed budget', () => {
    const pruner = createBudgetPruner({
      tokenBudget: 100,
      decay: { defaultTTL: 24, decayThreshold: 0.95 },
      states: { activeThreshold: 0.7, readyThreshold: 0.3 },
    });

    // Create many large BTSP entries that would exceed budget
    const entries: MemoryEntry[] = [];
    for (let i = 0; i < 10; i++) {
      entries.push(
        makeEntry('x '.repeat(50), {
          isBTSP: true,
          score: 0.9,
        }),
      );
    }

    const result = pruner.pruneToFit(entries, 100);

    // Total kept tokens should not exceed budget
    expect(result.prunedTokens).toBeLessThanOrEqual(100);
    // Some entries should have been removed
    expect(result.removed.length).toBeGreaterThan(0);
  });

  it('should always keep at least one BTSP entry', () => {
    const pruner = createBudgetPruner({
      tokenBudget: 10, // Very small budget
      decay: { defaultTTL: 24, decayThreshold: 0.95 },
      states: { activeThreshold: 0.7, readyThreshold: 0.3 },
    });

    const entries = [
      makeEntry('a very long btsp entry that exceeds the budget on its own', {
        isBTSP: true,
        score: 0.9,
      }),
    ];

    const result = pruner.pruneToFit(entries);

    // Should still keep the one BTSP entry even if it exceeds budget
    expect(result.kept.length).toBe(1);
  });

  it('should reserve space for regular entries alongside BTSP', () => {
    const pruner = createBudgetPruner({
      tokenBudget: 200,
      decay: { defaultTTL: 24, decayThreshold: 0.95 },
      states: { activeThreshold: 0.7, readyThreshold: 0.3 },
    });

    // Mix of BTSP and regular entries
    const entries = [
      makeEntry('btsp important error message', { isBTSP: true, score: 0.9 }),
      makeEntry('regular context about the project', { isBTSP: false, score: 0.8 }),
      makeEntry('another regular entry with code', { isBTSP: false, score: 0.7 }),
    ];

    const result = pruner.pruneToFit(entries);

    // Should keep both BTSP and some regular entries
    const keptBtsp = result.kept.filter((e) => e.isBTSP);
    const keptRegular = result.kept.filter((e) => !e.isBTSP);

    expect(keptBtsp.length).toBeGreaterThanOrEqual(1);
    expect(keptRegular.length).toBeGreaterThanOrEqual(1);
  });
});
