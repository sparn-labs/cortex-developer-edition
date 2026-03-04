/**
 * Exec Command - Execute a plan with constraints
 */

import { resolve } from 'node:path';
import type { CortexPlan, PlanExecConstraints } from '../../core/workflow-planner.js';
import { createWorkflowPlanner } from '../../core/workflow-planner.js';

export interface ExecCommandOptions {
  planId: string;
  json?: boolean;
}

export interface ExecCommandResult {
  plan: CortexPlan;
  constraints: PlanExecConstraints;
  json?: string;
  message: string;
}

export async function execCommand(options: ExecCommandOptions): Promise<ExecCommandResult> {
  const projectRoot = resolve(process.cwd());
  const planner = createWorkflowPlanner(projectRoot);

  const plan = await planner.loadPlan(options.planId);
  if (!plan) {
    throw new Error(`Plan ${options.planId} not found`);
  }

  const constraints = await planner.startExec(options.planId);

  // Reload plan to get updated status
  const updatedPlan = (await planner.loadPlan(options.planId)) || plan;

  const result: ExecCommandResult = {
    plan: updatedPlan,
    constraints,
    message: `Executing plan ${options.planId}: max ${constraints.maxFileReads} reads, ${constraints.tokenBudget} token budget`,
  };

  if (options.json) {
    result.json = JSON.stringify({ plan: updatedPlan, constraints }, null, 2);
  }

  return result;
}
