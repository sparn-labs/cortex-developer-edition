/**
 * Relay Command - Proxy CLI commands through optimization
 */

import { spawn } from 'node:child_process';
import { createGenericAdapter } from '../../adapters/generic.js';
import type { KVMemory } from '../../core/kv-memory.js';
import { DEFAULT_CONFIG } from '../../types/config.js';

export interface RelayCommandOptions {
  /** Command to execute */
  command: string;
  /** Command arguments */
  args: string[];
  /** Memory store instance */
  memory: KVMemory;
  /** Silent mode (suppress summary) */
  silent?: boolean;
}

export interface RelayCommandResult {
  /** Exit code from proxied command */
  exitCode: number;
  /** Original command output */
  originalOutput: string;
  /** Optimized output */
  optimizedOutput: string;
  /** Original token count */
  tokensBefore: number;
  /** Optimized token count */
  tokensAfter: number;
  /** Token reduction percentage */
  reduction: number;
  /** One-line summary (if not silent) */
  summary?: string;
}

/**
 * Execute a command and optimize its output
 * @param options - Command options
 * @returns Relay result
 */
export async function relayCommand(options: RelayCommandOptions): Promise<RelayCommandResult> {
  const { command, args, memory, silent = false } = options;

  // Execute child process and capture output
  const { stdout, stderr, exitCode } = await executeCommand(command, args);

  // Combine stdout and stderr
  const originalOutput = stdout + stderr;

  // Optimize the output
  const adapter = createGenericAdapter(memory, DEFAULT_CONFIG);
  const optimizationResult = await adapter.optimize(originalOutput, {
    dryRun: true, // Don't save relay outputs to memory
    verbose: false,
  });

  const result: RelayCommandResult = {
    exitCode,
    originalOutput,
    optimizedOutput: optimizationResult.optimizedContext,
    tokensBefore: optimizationResult.tokensBefore,
    tokensAfter: optimizationResult.tokensAfter,
    reduction: optimizationResult.reduction,
  };

  // Generate summary if not silent
  if (!silent && result.tokensBefore > 0) {
    const reductionPct = (result.reduction * 100).toFixed(1);
    result.summary = `📊 ${result.tokensBefore} → ${result.tokensAfter} tokens (${reductionPct}% reduction)`;
  }

  return result;
}

/**
 * Execute a command and capture its output
 * @param command - Command to execute
 * @param args - Command arguments
 * @returns Command output and exit code
 */
function executeCommand(
  command: string,
  args: string[],
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve) => {
    const child = spawn(command, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';

    child.stdout?.on('data', (data) => {
      stdout += data.toString();
    });

    child.stderr?.on('data', (data) => {
      stderr += data.toString();
    });

    child.on('close', (code) => {
      resolve({
        stdout,
        stderr,
        exitCode: code ?? 0,
      });
    });

    child.on('error', (error) => {
      resolve({
        stdout,
        stderr: error.message,
        exitCode: 1,
      });
    });
  });
}
