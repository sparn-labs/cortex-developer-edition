/**
 * Verify Command - Verify plan completion
 */

import { resolve } from 'node:path';
import type { PlanVerifyResult } from '../../core/workflow-planner.js';
import { createWorkflowPlanner } from '../../core/workflow-planner.js';

export interface VerifyCommandOptions {
  planId: string;
  json?: boolean;
}

export interface VerifyCommandResult {
  verification: PlanVerifyResult;
  json?: string;
  message: string;
}

export async function verifyCommand(options: VerifyCommandOptions): Promise<VerifyCommandResult> {
  const projectRoot = resolve(process.cwd());
  const planner = createWorkflowPlanner(projectRoot);

  const plan = await planner.loadPlan(options.planId);
  if (!plan) {
    throw new Error(`Plan ${options.planId} not found`);
  }

  const verification = await planner.verify(options.planId);

  const status = verification.success ? 'PASSED' : 'FAILED';
  const message = `Plan ${options.planId} verification: ${status} (${verification.stepsCompleted}/${verification.totalSteps} steps completed)`;

  const result: VerifyCommandResult = {
    verification,
    message,
  };

  if (options.json) {
    result.json = JSON.stringify(verification, null, 2);
  }

  return result;
}
