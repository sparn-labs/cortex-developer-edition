/**
 * Progress indicators for long-running operations.
 * Uses ora spinners with branded colors.
 */

import ora, { type Ora } from 'ora';
import { brainPink, neuralCyan, synapseViolet } from './colors.js';

/**
 * Create a spinner for optimization operations.
 *
 * @param text - Initial spinner text
 * @returns Ora spinner instance
 */
export function createOptimizeSpinner(text: string): Ora {
  return ora({
    text,
    color: 'cyan',
    spinner: 'dots12',
  });
}

/**
 * Create a spinner for memory consolidation.
 *
 * @param text - Initial spinner text
 * @returns Ora spinner instance
 */
export function createConsolidateSpinner(text: string): Ora {
  return ora({
    text,
    color: 'magenta',
    spinner: 'material',
  });
}

/**
 * Create a spinner for stats generation.
 *
 * @param text - Initial spinner text
 * @returns Ora spinner instance
 */
export function createStatsSpinner(text: string): Ora {
  return ora({
    text,
    color: 'yellow',
    spinner: 'bouncingBar',
  });
}

/**
 * Create a spinner for initialization.
 *
 * @param text - Initial spinner text
 * @returns Ora spinner instance
 */
export function createInitSpinner(text: string): Ora {
  return ora({
    text,
    color: 'green',
    spinner: 'star',
  });
}

/**
 * Show token savings with visual impact.
 * Displays before → after with percentage and celebratory message.
 *
 * @param tokensBefore - Tokens before optimization
 * @param tokensAfter - Tokens after optimization
 * @param reduction - Reduction percentage (0.0-1.0)
 */
export function showTokenSavings(
  tokensBefore: number,
  tokensAfter: number,
  reduction: number,
): void {
  const saved = tokensBefore - tokensAfter;
  const reductionPercent = (reduction * 100).toFixed(1);

  console.log(`\n${brainPink('━'.repeat(60))}`);
  console.log(neuralCyan('  📊 Token Optimization Results'));
  console.log(brainPink('━'.repeat(60)));

  // Before → After
  console.log(`  ${synapseViolet('Before:')}  ${tokensBefore.toLocaleString()} tokens`);
  console.log(`  ${neuralCyan('After:')}   ${tokensAfter.toLocaleString()} tokens`);
  console.log(brainPink('  ↓'.repeat(30)));

  // Savings
  console.log(`  ${brainPink('Saved:')}   ${saved.toLocaleString()} tokens (${reductionPercent}%)`);

  // Progress bar
  const barLength = 40;
  const savedBars = Math.floor(reduction * barLength);
  const keptBars = barLength - savedBars;
  const progressBar = neuralCyan('█'.repeat(keptBars)) + brainPink('░'.repeat(savedBars));
  console.log(`  [${progressBar}] ${reductionPercent}% reduced`);

  // Celebratory message
  if (reduction >= 0.9) {
    console.log(`\n  ${brainPink('✨ OUTSTANDING!')} Mind-blowing 90%+ reduction!`);
  } else if (reduction >= 0.7) {
    console.log(`\n  ${neuralCyan('🎉 EXCELLENT!')} Strong 70%+ token savings!`);
  } else if (reduction >= 0.5) {
    console.log(`\n  ${synapseViolet('👍 GOOD!')} Solid 50%+ optimization!`);
  } else if (reduction > 0) {
    console.log(`\n  ${neuralCyan('✓')} Tokens optimized successfully!`);
  }

  console.log(`${brainPink('━'.repeat(60))}\n`);
}

/**
 * Show consolidation summary with visual impact.
 *
 * @param entriesBefore - Entries before consolidation
 * @param entriesAfter - Entries after consolidation
 * @param decayed - Decayed entries removed
 * @param duplicates - Duplicate entries merged
 * @param durationMs - Duration in milliseconds
 */
export function showConsolidationSummary(
  entriesBefore: number,
  entriesAfter: number,
  decayed: number,
  duplicates: number,
  durationMs: number,
): void {
  const removed = entriesBefore - entriesAfter;
  const compressionRatio = entriesBefore > 0 ? ((removed / entriesBefore) * 100).toFixed(1) : '0.0';

  console.log(`\n${brainPink('━'.repeat(60))}`);
  console.log(neuralCyan('  🧹 Memory Consolidation Complete'));
  console.log(brainPink('━'.repeat(60)));

  // Before → After
  console.log(`  ${synapseViolet('Before:')}     ${entriesBefore.toLocaleString()} entries`);
  console.log(`  ${neuralCyan('After:')}      ${entriesAfter.toLocaleString()} entries`);
  console.log(brainPink('  ↓'.repeat(30)));

  // Details
  console.log(`  ${brainPink('Decayed:')}    ${decayed.toLocaleString()} removed`);
  console.log(`  ${brainPink('Duplicates:')} ${duplicates.toLocaleString()} merged`);
  console.log(`  ${neuralCyan('Total:')}      ${removed.toLocaleString()} entries freed`);
  console.log(`  ${synapseViolet('Time:')}       ${durationMs}ms`);

  // Progress bar
  const barLength = 40;
  const compressionBars = Math.floor((removed / entriesBefore) * barLength);
  const keptBars = barLength - compressionBars;
  const progressBar = neuralCyan('█'.repeat(keptBars)) + brainPink('░'.repeat(compressionBars));
  console.log(`  [${progressBar}] ${compressionRatio}% compressed`);

  // Celebratory message
  if (removed > 0) {
    console.log(`\n  ${brainPink('✨')} Memory optimized and ready for peak performance!`);
  } else {
    console.log(`\n  ${neuralCyan('✓')} Memory already optimal!`);
  }

  console.log(`${brainPink('━'.repeat(60))}\n`);
}

/**
 * Show initialization success with branded message.
 *
 * @param message - Success message
 */
export function showInitSuccess(message: string): void {
  console.log(`\n${brainPink('━'.repeat(60))}`);
  console.log(brainPink('  🧠 Cortex Initialized Successfully!'));
  console.log(brainPink('━'.repeat(60)));
  console.log(`  ${neuralCyan(message)}`);
  console.log(`${brainPink('━'.repeat(60))}\n`);
}
