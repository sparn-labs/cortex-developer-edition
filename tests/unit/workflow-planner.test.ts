/**
 * Workflow Planner Tests
 */

import { mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createWorkflowPlanner } from '../../src/core/workflow-planner.js';

describe('Workflow Planner', () => {
  const tmpDir = join(process.cwd(), '.test-planner-tmp');

  beforeEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    mkdirSync(join(tmpDir, '.cortex'), { recursive: true });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('createPlan', () => {
    it('should create a plan with unique ID', async () => {
      const planner = createWorkflowPlanner(tmpDir);

      const plan = await planner.createPlan(
        'Add auth to API',
        ['src/api.ts'],
        ['handleAuth'],
        [
          {
            order: 1,
            action: 'read',
            target: 'src/api.ts',
            description: 'Read API file',
            dependencies: [],
            estimated_tokens: 1000,
          },
          {
            order: 2,
            action: 'write',
            target: 'src/api.ts',
            description: 'Add auth middleware',
            dependencies: [1],
            estimated_tokens: 500,
          },
        ],
      );

      expect(plan.id).toBeDefined();
      expect(plan.id.length).toBeGreaterThan(0);
      expect(plan.task_description).toBe('Add auth to API');
      expect(plan.steps).toHaveLength(2);
      expect(plan.status).toBe('draft');
    });

    it('should set all steps to pending status', async () => {
      const planner = createWorkflowPlanner(tmpDir);

      const plan = await planner.createPlan(
        'Test task',
        [],
        [],
        [
          {
            order: 1,
            action: 'search',
            target: 'query',
            description: 'Search',
            dependencies: [],
            estimated_tokens: 100,
          },
          {
            order: 2,
            action: 'read',
            target: 'file',
            description: 'Read',
            dependencies: [1],
            estimated_tokens: 200,
          },
        ],
      );

      for (const step of plan.steps) {
        expect(step.status).toBe('pending');
      }
    });

    it('should store files_needed and search_queries', async () => {
      const planner = createWorkflowPlanner(tmpDir);

      const plan = await planner.createPlan(
        'Refactor',
        ['src/a.ts', 'src/b.ts'],
        ['handleError', 'validateInput'],
        [],
      );

      expect(plan.files_needed).toEqual(['src/a.ts', 'src/b.ts']);
      expect(plan.search_queries).toEqual(['handleError', 'validateInput']);
    });

    it('should store token budget', async () => {
      const planner = createWorkflowPlanner(tmpDir);

      const plan = await planner.createPlan('Task', [], [], [], {
        planning: 1000,
        estimated_execution: 5000,
        max_file_reads: 10,
      });

      expect(plan.token_budget.planning).toBe(1000);
      expect(plan.token_budget.estimated_execution).toBe(5000);
      expect(plan.token_budget.max_file_reads).toBe(10);
    });
  });

  describe('loadPlan', () => {
    it('should load a saved plan', async () => {
      const planner = createWorkflowPlanner(tmpDir);

      const created = await planner.createPlan(
        'Load test',
        [],
        [],
        [
          {
            order: 1,
            action: 'test',
            target: 'tests',
            description: 'Run tests',
            dependencies: [],
            estimated_tokens: 300,
          },
        ],
      );

      const loaded = await planner.loadPlan(created.id);

      expect(loaded).not.toBeNull();
      expect(loaded?.id).toBe(created.id);
      expect(loaded?.task_description).toBe('Load test');
      expect(loaded?.steps).toHaveLength(1);
    });

    it('should return null for non-existent plan', async () => {
      const planner = createWorkflowPlanner(tmpDir);

      const result = await planner.loadPlan('nonexistent');
      expect(result).toBeNull();
    });
  });

  describe('listPlans', () => {
    it('should list all plans sorted by creation time', async () => {
      const planner = createWorkflowPlanner(tmpDir);

      await planner.createPlan('Plan A', [], [], []);
      // Small delay to ensure different timestamp
      await new Promise((resolve) => setTimeout(resolve, 10));
      await planner.createPlan('Plan B', [], [], []);

      const plans = await planner.listPlans();

      expect(plans).toHaveLength(2);
      // Most recent first
      expect(plans[0]?.task).toBe('Plan B');
      expect(plans[1]?.task).toBe('Plan A');
    });

    it('should return empty array for no plans', async () => {
      const planner = createWorkflowPlanner(tmpDir);
      const plans = await planner.listPlans();
      expect(plans).toHaveLength(0);
    });
  });

  describe('updateStep', () => {
    it('should update step status', async () => {
      const planner = createWorkflowPlanner(tmpDir);

      const plan = await planner.createPlan(
        'Step test',
        [],
        [],
        [
          {
            order: 1,
            action: 'read',
            target: 'file',
            description: 'Read',
            dependencies: [],
            estimated_tokens: 100,
          },
        ],
      );

      await planner.updateStep(plan.id, 1, 'completed', 'Done');

      const loaded = await planner.loadPlan(plan.id);
      expect(loaded?.steps[0]?.status).toBe('completed');
      expect(loaded?.steps[0]?.result).toBe('Done');
    });

    it('should throw for non-existent plan', async () => {
      const planner = createWorkflowPlanner(tmpDir);

      await expect(planner.updateStep('bad', 1, 'completed')).rejects.toThrow();
    });

    it('should throw for non-existent step', async () => {
      const planner = createWorkflowPlanner(tmpDir);

      const plan = await planner.createPlan(
        'Step test',
        [],
        [],
        [
          {
            order: 1,
            action: 'read',
            target: 'file',
            description: 'Read',
            dependencies: [],
            estimated_tokens: 100,
          },
        ],
      );

      await expect(planner.updateStep(plan.id, 99, 'completed')).rejects.toThrow();
    });
  });

  describe('startExec', () => {
    it('should set plan status to executing', async () => {
      const planner = createWorkflowPlanner(tmpDir);

      const plan = await planner.createPlan('Exec test', [], [], [], {
        planning: 0,
        estimated_execution: 5000,
        max_file_reads: 3,
      });

      const constraints = await planner.startExec(plan.id);

      expect(constraints.maxFileReads).toBe(3);
      expect(constraints.tokenBudget).toBe(5000);
      expect(constraints.allowReplan).toBe(false);

      const loaded = await planner.loadPlan(plan.id);
      expect(loaded?.status).toBe('executing');
    });

    it('should throw for non-existent plan', async () => {
      const planner = createWorkflowPlanner(tmpDir);
      await expect(planner.startExec('bad')).rejects.toThrow();
    });
  });

  describe('verify', () => {
    it('should report success when all steps completed', async () => {
      const planner = createWorkflowPlanner(tmpDir);

      const plan = await planner.createPlan(
        'Verify test',
        [],
        [],
        [
          {
            order: 1,
            action: 'read',
            target: 'file',
            description: 'Read',
            dependencies: [],
            estimated_tokens: 100,
          },
          {
            order: 2,
            action: 'test',
            target: 'tests',
            description: 'Test',
            dependencies: [1],
            estimated_tokens: 200,
          },
        ],
      );

      await planner.updateStep(plan.id, 1, 'completed');
      await planner.updateStep(plan.id, 2, 'completed');

      const result = await planner.verify(plan.id);

      expect(result.success).toBe(true);
      expect(result.stepsCompleted).toBe(2);
      expect(result.stepsFailed).toBe(0);
      expect(result.totalSteps).toBe(2);
    });

    it('should report failure when steps failed', async () => {
      const planner = createWorkflowPlanner(tmpDir);

      const plan = await planner.createPlan(
        'Fail test',
        [],
        [],
        [
          {
            order: 1,
            action: 'read',
            target: 'file',
            description: 'Read',
            dependencies: [],
            estimated_tokens: 100,
          },
          {
            order: 2,
            action: 'test',
            target: 'tests',
            description: 'Test',
            dependencies: [1],
            estimated_tokens: 200,
          },
        ],
      );

      await planner.updateStep(plan.id, 1, 'completed');
      await planner.updateStep(plan.id, 2, 'failed');

      const result = await planner.verify(plan.id);

      expect(result.success).toBe(false);
      expect(result.stepsCompleted).toBe(1);
      expect(result.stepsFailed).toBe(1);
    });

    it('should include step details in verification', async () => {
      const planner = createWorkflowPlanner(tmpDir);

      const plan = await planner.createPlan(
        'Details test',
        [],
        [],
        [
          {
            order: 1,
            action: 'search',
            target: 'query',
            description: 'Search',
            dependencies: [],
            estimated_tokens: 50,
          },
        ],
      );

      const result = await planner.verify(plan.id);

      expect(result.details).toHaveLength(1);
      expect(result.details[0]?.action).toBe('search');
      expect(result.details[0]?.status).toBe('pending');
    });

    it('should update plan status to completed or failed', async () => {
      const planner = createWorkflowPlanner(tmpDir);

      const plan = await planner.createPlan(
        'Status test',
        [],
        [],
        [
          {
            order: 1,
            action: 'test',
            target: 'tests',
            description: 'Test',
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
  });

  describe('getPlansDir', () => {
    it('should return the plans directory path', () => {
      const planner = createWorkflowPlanner(tmpDir);
      const dir = planner.getPlansDir();
      expect(dir).toContain('.cortex');
      expect(dir).toContain('plans');
    });
  });
});
