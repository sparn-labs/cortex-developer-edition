/**
 * Workflow Planner - Plan/Exec/Verify separation
 *
 * Separates AI agent workflows into discrete phases:
 * - Planning: Identify files needed, search queries, and steps
 * - Execution: Apply constraints (max reads, token budget)
 * - Verification: Check step completion and run tests
 *
 * Reduces token waste by preventing re-planning loops.
 */

import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export interface CortexPlan {
  id: string;
  created_at: number;
  task_description: string;
  steps: PlanStep[];
  token_budget: {
    planning: number;
    estimated_execution: number;
    max_file_reads: number;
  };
  files_needed: string[];
  search_queries: string[];
  status: 'draft' | 'ready' | 'executing' | 'completed' | 'failed';
}

export interface PlanStep {
  order: number;
  action: 'read' | 'write' | 'search' | 'test' | 'verify';
  target: string;
  description: string;
  dependencies: number[];
  estimated_tokens: number;
  status: 'pending' | 'in_progress' | 'completed' | 'skipped' | 'failed';
  result?: string;
}

export interface PlanExecConstraints {
  maxFileReads: number;
  tokenBudget: number;
  allowReplan: boolean;
}

export interface PlanVerifyResult {
  planId: string;
  stepsCompleted: number;
  stepsFailed: number;
  stepsSkipped: number;
  totalSteps: number;
  tokensBudgeted: number;
  tokensUsed: number;
  success: boolean;
  details: Array<{
    step: number;
    action: string;
    target: string;
    status: string;
  }>;
}

export interface WorkflowPlanner {
  /** Create a new plan */
  createPlan(
    taskDescription: string,
    filesNeeded: string[],
    searchQueries: string[],
    steps: Omit<PlanStep, 'status' | 'result'>[],
    tokenBudget?: { planning: number; estimated_execution: number; max_file_reads: number },
  ): Promise<CortexPlan>;

  /** Load an existing plan */
  loadPlan(planId: string): Promise<CortexPlan | null>;

  /** List all plans */
  listPlans(): Promise<Array<{ id: string; task: string; status: string; created: number }>>;

  /** Update a plan step status */
  updateStep(
    planId: string,
    stepOrder: number,
    status: PlanStep['status'],
    result?: string,
  ): Promise<void>;

  /** Start execution of a plan */
  startExec(planId: string): Promise<PlanExecConstraints>;

  /** Verify plan completion */
  verify(planId: string): Promise<PlanVerifyResult>;

  /** Get the plans directory */
  getPlansDir(): string;
}

/**
 * Create a workflow planner
 */
export function createWorkflowPlanner(projectRoot: string): WorkflowPlanner {
  const plansDir = join(projectRoot, '.cortex', 'plans');

  // Ensure plans directory exists
  if (!existsSync(plansDir)) {
    mkdirSync(plansDir, { recursive: true });
  }

  function sanitizeId(id: string): string {
    // Strip path separators and traversal sequences to prevent path injection
    return id.replace(/[/\\:.]/g, '').replace(/\.\./g, '');
  }

  function planPath(planId: string): string {
    const safeId = sanitizeId(planId);
    if (!safeId) throw new Error('Invalid plan ID');
    return join(plansDir, `plan-${safeId}.json`);
  }

  async function createPlan(
    taskDescription: string,
    filesNeeded: string[],
    searchQueries: string[],
    steps: Omit<PlanStep, 'status' | 'result'>[],
    tokenBudget = { planning: 0, estimated_execution: 0, max_file_reads: 5 },
  ): Promise<CortexPlan> {
    const id = randomUUID().split('-')[0] || 'plan';

    const plan: CortexPlan = {
      id,
      created_at: Date.now(),
      task_description: taskDescription,
      steps: steps.map((s) => ({ ...s, status: 'pending' as const })),
      token_budget: tokenBudget,
      files_needed: filesNeeded,
      search_queries: searchQueries,
      status: 'draft',
    };

    writeFileSync(planPath(id), JSON.stringify(plan, null, 2), 'utf-8');
    return plan;
  }

  async function loadPlan(planId: string): Promise<CortexPlan | null> {
    const path = planPath(planId);
    if (!existsSync(path)) return null;

    try {
      return JSON.parse(readFileSync(path, 'utf-8')) as CortexPlan;
    } catch {
      return null;
    }
  }

  async function listPlans(): Promise<
    Array<{ id: string; task: string; status: string; created: number }>
  > {
    if (!existsSync(plansDir)) return [];

    const files = readdirSync(plansDir).filter((f) => f.startsWith('plan-') && f.endsWith('.json'));

    const plans: Array<{ id: string; task: string; status: string; created: number }> = [];

    for (const file of files) {
      try {
        const plan = JSON.parse(readFileSync(join(plansDir, file), 'utf-8')) as CortexPlan;
        plans.push({
          id: plan.id,
          task: plan.task_description,
          status: plan.status,
          created: plan.created_at,
        });
      } catch {
        // Skip corrupt plan files
      }
    }

    return plans.sort((a, b) => b.created - a.created);
  }

  async function updateStep(
    planId: string,
    stepOrder: number,
    status: PlanStep['status'],
    result?: string,
  ): Promise<void> {
    const plan = await loadPlan(planId);
    if (!plan) throw new Error(`Plan ${planId} not found`);

    const step = plan.steps.find((s) => s.order === stepOrder);
    if (!step) throw new Error(`Step ${stepOrder} not found in plan ${planId}`);

    step.status = status;
    if (result !== undefined) {
      step.result = result;
    }

    writeFileSync(planPath(planId), JSON.stringify(plan, null, 2), 'utf-8');
  }

  async function startExec(planId: string): Promise<PlanExecConstraints> {
    const plan = await loadPlan(planId);
    if (!plan) throw new Error(`Plan ${planId} not found`);

    plan.status = 'executing';
    writeFileSync(planPath(planId), JSON.stringify(plan, null, 2), 'utf-8');

    return {
      maxFileReads: plan.token_budget.max_file_reads,
      tokenBudget: plan.token_budget.estimated_execution,
      allowReplan: false,
    };
  }

  async function verify(planId: string): Promise<PlanVerifyResult> {
    const plan = await loadPlan(planId);
    if (!plan) throw new Error(`Plan ${planId} not found`);

    let stepsCompleted = 0;
    let stepsFailed = 0;
    let stepsSkipped = 0;
    let tokensUsed = 0;

    const details: PlanVerifyResult['details'] = [];

    for (const step of plan.steps) {
      switch (step.status) {
        case 'completed':
          stepsCompleted++;
          tokensUsed += step.estimated_tokens;
          break;
        case 'failed':
          stepsFailed++;
          break;
        case 'skipped':
          stepsSkipped++;
          break;
        default:
          // pending or in_progress = not done yet
          break;
      }

      details.push({
        step: step.order,
        action: step.action,
        target: step.target,
        status: step.status,
      });
    }

    const totalSteps = plan.steps.length;
    const success = stepsFailed === 0 && stepsCompleted === totalSteps;

    // Update plan status - only mark completed/failed if no steps are still pending/in_progress
    const hasInProgress = plan.steps.some(
      (s) => s.status === 'pending' || s.status === 'in_progress',
    );
    if (!hasInProgress) {
      plan.status = success ? 'completed' : 'failed';
      writeFileSync(planPath(planId), JSON.stringify(plan, null, 2), 'utf-8');
    }

    return {
      planId,
      stepsCompleted,
      stepsFailed,
      stepsSkipped,
      totalSteps,
      tokensBudgeted: plan.token_budget.estimated_execution,
      tokensUsed,
      success,
      details,
    };
  }

  function getPlansDir(): string {
    return plansDir;
  }

  return {
    createPlan,
    loadPlan,
    listPlans,
    updateStep,
    startExec,
    verify,
    getPlansDir,
  };
}
