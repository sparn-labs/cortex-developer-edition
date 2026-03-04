/**
 * Optimize Command - Apply multi-stage optimization to context
 */

import { readFile, writeFile } from 'node:fs/promises';
import { createGenericAdapter } from '../../adapters/generic.js';
import type { KVMemory } from '../../core/kv-memory.js';
import type { OptimizationResult } from '../../types/adapter.js';
import { DEFAULT_CONFIG } from '../../types/config.js';

export interface OptimizeCommandOptions {
  /** Input context (if not provided, reads from stdin) */
  input?: string;
  /** Input file path */
  inputFile?: string;
  /** Output file path (if not provided, writes to stdout) */
  outputFile?: string;
  /** Memory store instance */
  memory: KVMemory;
  /** Dry run mode (don't save to memory) */
  dryRun?: boolean;
  /** Verbose mode (show per-entry details) */
  verbose?: boolean;
}

export interface OptimizeCommandResult extends OptimizationResult {
  output: string;
  outputFile?: string;
}

/**
 * Execute the optimize command
 * @param options - Command options
 * @returns Optimization result
 */
export async function optimizeCommand(
  options: OptimizeCommandOptions,
): Promise<OptimizeCommandResult> {
  const { memory, dryRun = false, verbose = false } = options;

  // Read input from file or direct input
  let input: string;
  if (options.inputFile) {
    input = await readFile(options.inputFile, 'utf-8');
  } else if (options.input) {
    input = options.input;
  } else {
    throw new Error('No input provided. Use --input or --input-file');
  }

  // Create adapter and optimize
  const adapter = createGenericAdapter(memory, DEFAULT_CONFIG);
  const result = await adapter.optimize(input, { dryRun, verbose });

  // Write output to file or return
  if (options.outputFile) {
    await writeFile(options.outputFile, result.optimizedContext, 'utf-8');
  }

  return {
    ...result,
    output: result.optimizedContext,
    outputFile: options.outputFile,
  };
}
