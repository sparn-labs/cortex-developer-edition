/**
 * Integration Tests - Plan/Exec/Verify workflow
 */

import { mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createWorkflowPlanner } from '../../src/core/workflow-planner.js';

describe('Plan/Exec/Verify Workflow', () => {
  const tmpDir = join(process.cwd(), '.test-pev-tmp');

  beforeEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    mkdirSync(join(tmpDir, '.cortex'), { recursive: true });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should complete full plan -> exec -> verify lifecycle', async () => {
    const planner = createWorkflowPlanner(tmpDir);

    // Step 1: Create plan
    const plan = await planner.createPlan(
      'Add JWT auth to /api/users endpoint',
      ['src/api/users.ts', 'src/middleware/auth.ts'],
      ['handleAuth', 'jwt.verify'],
      [
        {
          order: 1,
          action: 'search',
          target: 'handleAuth',
          description: 'Find auth handler',
          dependencies: [],
          estimated_tokens: 500,
        },
        {
          order: 2,
          action: 'read',
          target: 'src/api/users.ts',
          description: 'Read users endpoint',
          dependencies: [],
          estimated_tokens: 1000,
        },
        {
          order: 3,
          action: 'read',
          target: 'src/middleware/auth.ts',
          description: 'Read auth middleware',
          dependencies: [],
          estimated_tokens: 800,
        },
        {
          order: 4,
          action: 'write',
          target: 'src/api/users.ts',
          description: 'Add auth to endpoint',
          dependencies: [2, 3],
          estimated_tokens: 600,
        },
        {
          order: 5,
          action: 'test',
          target: 'tests/api.test.ts',
          description: 'Run API tests',
          dependencies: [4],
          estimated_tokens: 300,
        },
        {
          order: 6,
          action: 'verify',
          target: 'all',
          description: 'Final verification',
          dependencies: [5],
          estimated_tokens: 200,
        },
      ],
      { planning: 500, estimated_execution: 3400, max_file_reads: 3 },
    );

    expect(plan.status).toBe('draft');
    expect(plan.steps).toHaveLength(6);

    // Step 2: Start execution
    const constraints = await planner.startExec(plan.id);

    expect(constraints.maxFileReads).toBe(3);
    expect(constraints.tokenBudget).toBe(3400);
    expect(constraints.allowReplan).toBe(false);

    // Verify plan is now executing
    const execPlan = await planner.loadPlan(plan.id);
    expect(execPlan?.status).toBe('executing');

    // Step 3: Execute steps (simulate)
    await planner.updateStep(plan.id, 1, 'completed', 'Found in auth.ts:15');
    await planner.updateStep(plan.id, 2, 'completed', 'Read 45 lines');
    await planner.updateStep(plan.id, 3, 'completed', 'Read 30 lines');
    await planner.updateStep(plan.id, 4, 'completed', 'Added auth middleware');
    await planner.updateStep(plan.id, 5, 'completed', 'All 12 tests pass');
    await planner.updateStep(plan.id, 6, 'completed', 'Verified');

    // Step 4: Verify
    const verification = await planner.verify(plan.id);

    expect(verification.success).toBe(true);
    expect(verification.stepsCompleted).toBe(6);
    expect(verification.stepsFailed).toBe(0);
    expect(verification.totalSteps).toBe(6);
    expect(verification.details).toHaveLength(6);

    // Plan should be marked completed
    const finalPlan = await planner.loadPlan(plan.id);
    expect(finalPlan?.status).toBe('completed');
  });

  it('should handle partial failure in workflow', async () => {
    const planner = createWorkflowPlanner(tmpDir);

    const plan = await planner.createPlan(
      'Failing task',
      ['src/broken.ts'],
      [],
      [
        {
          order: 1,
          action: 'read',
          target: 'src/broken.ts',
          description: 'Read file',
          dependencies: [],
          estimated_tokens: 500,
        },
        {
          order: 2,
          action: 'write',
          target: 'src/broken.ts',
          description: 'Fix file',
          dependencies: [1],
          estimated_tokens: 300,
        },
        {
          order: 3,
          action: 'test',
          target: 'tests',
          description: 'Run tests',
          dependencies: [2],
          estimated_tokens: 200,
        },
      ],
    );

    await planner.startExec(plan.id);

    // Step 1 succeeds, step 2 fails
    await planner.updateStep(plan.id, 1, 'completed');
    await planner.updateStep(plan.id, 2, 'failed', 'Syntax error');
    await planner.updateStep(plan.id, 3, 'skipped');

    const verification = await planner.verify(plan.id);

    expect(verification.success).toBe(false);
    expect(verification.stepsCompleted).toBe(1);
    expect(verification.stepsFailed).toBe(1);
    expect(verification.stepsSkipped).toBe(1);

    const finalPlan = await planner.loadPlan(plan.id);
    expect(finalPlan?.status).toBe('failed');
  });

  it('should track multiple plans independently', async () => {
    const planner = createWorkflowPlanner(tmpDir);

    const plan1 = await planner.createPlan(
      'Task A',
      [],
      [],
      [
        {
          order: 1,
          action: 'read',
          target: 'a.ts',
          description: 'Read A',
          dependencies: [],
          estimated_tokens: 100,
        },
      ],
    );

    const plan2 = await planner.createPlan(
      'Task B',
      [],
      [],
      [
        {
          order: 1,
          action: 'write',
          target: 'b.ts',
          description: 'Write B',
          dependencies: [],
          estimated_tokens: 200,
        },
      ],
    );

    // Complete plan1
    await planner.updateStep(plan1.id, 1, 'completed');
    const v1 = await planner.verify(plan1.id);
    expect(v1.success).toBe(true);

    // Plan2 should still be draft
    const loaded2 = await planner.loadPlan(plan2.id);
    expect(loaded2?.status).toBe('draft');
    expect(loaded2?.steps[0]?.status).toBe('pending');

    // List should show both
    const all = await planner.listPlans();
    expect(all).toHaveLength(2);
  });

  it('should enforce token budget tracking', async () => {
    const planner = createWorkflowPlanner(tmpDir);

    const plan = await planner.createPlan(
      'Budget test',
      [],
      [],
      [
        {
          order: 1,
          action: 'read',
          target: 'file1',
          description: 'Read 1',
          dependencies: [],
          estimated_tokens: 2000,
        },
        {
          order: 2,
          action: 'read',
          target: 'file2',
          description: 'Read 2',
          dependencies: [],
          estimated_tokens: 3000,
        },
      ],
      { planning: 500, estimated_execution: 5000, max_file_reads: 2 },
    );

    await planner.startExec(plan.id);
    await planner.updateStep(plan.id, 1, 'completed');
    await planner.updateStep(plan.id, 2, 'completed');

    const verification = await planner.verify(plan.id);

    expect(verification.tokensBudgeted).toBe(5000);
    expect(verification.tokensUsed).toBe(5000);
    expect(verification.success).toBe(true);
  });
});
