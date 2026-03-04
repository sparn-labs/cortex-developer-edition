/**
 * Plan Command - Create execution plans
 */

import { resolve } from 'node:path';
import type { CortexPlan, PlanStep } from '../../core/workflow-planner.js';
import { createWorkflowPlanner } from '../../core/workflow-planner.js';

export interface PlanCommandOptions {
  task: string;
  files?: string[];
  searches?: string[];
  maxReads?: number;
  json?: boolean;
}

export interface PlanCommandResult {
  plan: CortexPlan;
  json?: string;
  message: string;
}

export async function planCommand(options: PlanCommandOptions): Promise<PlanCommandResult> {
  const projectRoot = resolve(process.cwd());
  const planner = createWorkflowPlanner(projectRoot);

  // Generate steps from task description
  const steps: Omit<PlanStep, 'status' | 'result'>[] = [];
  let order = 1;

  // Add search steps
  if (options.searches) {
    for (const query of options.searches) {
      steps.push({
        order: order++,
        action: 'search',
        target: query,
        description: `Search for: ${query}`,
        dependencies: [],
        estimated_tokens: 500,
      });
    }
  }

  // Add file read steps
  if (options.files) {
    for (const file of options.files) {
      steps.push({
        order: order++,
        action: 'read',
        target: file,
        description: `Read file: ${file}`,
        dependencies: [],
        estimated_tokens: 1000,
      });
    }
  }

  // Add verify step
  steps.push({
    order: order++,
    action: 'verify',
    target: 'tests',
    description: 'Run tests to verify changes',
    dependencies: steps.map((s) => s.order),
    estimated_tokens: 200,
  });

  const plan = await planner.createPlan(
    options.task,
    options.files || [],
    options.searches || [],
    steps,
    {
      planning: 0,
      estimated_execution: steps.reduce((sum, s) => sum + s.estimated_tokens, 0),
      max_file_reads: options.maxReads || 5,
    },
  );

  const result: PlanCommandResult = {
    plan,
    message: `Plan ${plan.id} created with ${plan.steps.length} steps`,
  };

  if (options.json) {
    result.json = JSON.stringify(plan, null, 2);
  }

  return result;
}

export interface PlanListResult {
  plans: Array<{ id: string; task: string; status: string; created: number }>;
  json?: string;
}

export async function planListCommand(options: { json?: boolean }): Promise<PlanListResult> {
  const projectRoot = resolve(process.cwd());
  const planner = createWorkflowPlanner(projectRoot);

  const plans = await planner.listPlans();

  const result: PlanListResult = { plans };

  if (options.json) {
    result.json = JSON.stringify(plans, null, 2);
  }

  return result;
}
