/**
 * Interactive Command - Conversational configuration and exploration
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { confirm, input, number, select } from '@inquirer/prompts';
import { load as parseYAML, dump as stringifyYAML } from 'js-yaml';
import type { KVMemory } from '../../core/kv-memory.js';
import { getMetrics } from '../../core/metrics.js';
import type { CortexConfig } from '../../types/config.js';
import { brainPink, dim, errorRed, neuralCyan, synapseViolet } from '../ui/colors.js';

export interface InteractiveCommandOptions {
  /** Memory store instance */
  memory: KVMemory;
  /** Path to config file */
  configPath: string;
}

export interface InteractiveCommandResult {
  /** Whether user exited normally */
  success: boolean;
  /** Optional message */
  message?: string;
}

/**
 * Display welcome banner
 */
function showWelcomeBanner(): void {
  console.log(brainPink('\n━'.repeat(60)));
  console.log(brainPink('  🧠 Cortex Interactive Mode'));
  console.log(brainPink('━'.repeat(60)));
  console.log(dim('  Conversational configuration and exploration\n'));
}

/**
 * Display main menu
 */
async function showMainMenu(): Promise<string> {
  return select({
    message: 'What would you like to do?',
    choices: [
      {
        name: '⚙️  Configure Settings',
        value: 'configure',
        description: 'Guided configuration wizard',
      },
      {
        name: '🔍 Optimize Preview',
        value: 'preview',
        description: 'Preview optimization with confirmation',
      },
      {
        name: '📊 Stats Dashboard',
        value: 'stats',
        description: 'View metrics and performance data',
      },
      {
        name: '🧹 Memory Consolidation',
        value: 'consolidate',
        description: 'Clean up decayed entries and duplicates',
      },
      {
        name: '🚀 Quick Actions',
        value: 'quick',
        description: 'Common tasks and shortcuts',
      },
      {
        name: '❌ Exit',
        value: 'exit',
        description: 'Return to shell',
      },
    ],
  });
}

/**
 * Configuration wizard
 */
async function configureWizard(configPath: string): Promise<void> {
  console.log(neuralCyan('\n📝 Configuration Wizard\n'));

  // Load current config
  const configYAML = readFileSync(configPath, 'utf-8');
  const config = parseYAML(configYAML) as CortexConfig;

  const section = await select({
    message: 'Which settings would you like to configure?',
    choices: [
      { name: '🔪 Pruning (Relevance Filtering)', value: 'pruning' },
      { name: '⏳ Decay (Time-Based)', value: 'decay' },
      { name: '🎯 States (Entry Classification)', value: 'states' },
      { name: '⚡ Real-time Optimization', value: 'realtime' },
      { name: '🎨 UI Preferences', value: 'ui' },
      { name: '← Back to Main Menu', value: 'back' },
    ],
  });

  if (section === 'back') return;

  switch (section) {
    case 'pruning': {
      console.log(synapseViolet('\n🔪 Pruning Configuration'));
      console.log(dim('Keep only the most relevant context\n'));

      const threshold = await number({
        message: 'Pruning threshold (percentage of entries to keep):',
        default: config.pruning.threshold,
        min: 1,
        max: 100,
      });

      const aggressiveness = await number({
        message: 'Aggressiveness (0-100, affects TF-IDF weighting):',
        default: config.pruning.aggressiveness,
        min: 0,
        max: 100,
      });

      config.pruning.threshold = threshold ?? config.pruning.threshold;
      config.pruning.aggressiveness = aggressiveness ?? config.pruning.aggressiveness;

      console.log(neuralCyan('\n✓ Pruning settings updated'));
      break;
    }

    case 'decay': {
      console.log(synapseViolet('\n⏳ Decay Configuration'));
      console.log(dim('Apply time-based decay to older entries\n'));

      const defaultTTL = await number({
        message: 'Default TTL in hours:',
        default: config.decay.defaultTTL,
        min: 1,
      });

      const decayThreshold = await number({
        message: 'Decay threshold (0.0-1.0, entries below this are pruned):',
        default: config.decay.decayThreshold,
        min: 0,
        max: 1,
        step: 0.05,
      });

      config.decay.defaultTTL = defaultTTL ?? config.decay.defaultTTL;
      config.decay.decayThreshold = decayThreshold ?? config.decay.decayThreshold;

      console.log(neuralCyan('\n✓ Decay settings updated'));
      break;
    }

    case 'states': {
      console.log(synapseViolet('\n🎯 State Threshold Configuration'));
      console.log(dim('Classify entries as active/ready/silent based on score\n'));

      const activeThreshold = await number({
        message: 'Active state threshold (0.0-1.0):',
        default: config.states.activeThreshold,
        min: 0,
        max: 1,
        step: 0.05,
      });

      const readyThreshold = await number({
        message: 'Ready state threshold (0.0-1.0):',
        default: config.states.readyThreshold,
        min: 0,
        max: 1,
        step: 0.05,
      });

      config.states.activeThreshold = activeThreshold ?? config.states.activeThreshold;
      config.states.readyThreshold = readyThreshold ?? config.states.readyThreshold;

      console.log(neuralCyan('\n✓ State settings updated'));
      break;
    }

    case 'realtime': {
      console.log(synapseViolet('\n⚡ Real-time Optimization Configuration'));
      console.log(dim('Daemon settings for automatic optimization\n'));

      const tokenBudget = await number({
        message: 'Target token budget:',
        default: config.realtime.tokenBudget,
        min: 1000,
      });

      const autoOptimizeThreshold = await number({
        message: 'Auto-optimize threshold (triggers optimization):',
        default: config.realtime.autoOptimizeThreshold,
        min: 1000,
      });

      const windowSize = await number({
        message: 'Sliding window size (entries):',
        default: config.realtime.windowSize,
        min: 100,
      });

      const incremental = await confirm({
        message: 'Enable incremental optimization (faster delta processing)?',
        default: config.realtime.incremental,
      });

      config.realtime.tokenBudget = tokenBudget ?? config.realtime.tokenBudget;
      config.realtime.autoOptimizeThreshold =
        autoOptimizeThreshold ?? config.realtime.autoOptimizeThreshold;
      config.realtime.windowSize = windowSize ?? config.realtime.windowSize;
      config.realtime.incremental = incremental;

      console.log(neuralCyan('\n✓ Real-time settings updated'));
      break;
    }

    case 'ui': {
      console.log(synapseViolet('\n🎨 UI Preferences'));
      console.log(dim('Customize terminal output\n'));

      const colors = await confirm({
        message: 'Enable colored output?',
        default: config.ui.colors,
      });

      const verbose = await confirm({
        message: 'Enable verbose logging?',
        default: config.ui.verbose,
      });

      config.ui.colors = colors;
      config.ui.verbose = verbose;

      console.log(neuralCyan('\n✓ UI settings updated'));
      break;
    }
  }

  // Save config
  const updatedYAML = stringifyYAML(config);
  writeFileSync(configPath, updatedYAML, 'utf-8');
  console.log(neuralCyan(`\n💾 Configuration saved to ${configPath}\n`));
}

/**
 * Optimization preview with confirmation
 */
async function optimizePreview(memory: KVMemory): Promise<void> {
  console.log(neuralCyan('\n🔍 Optimization Preview\n'));

  const inputFile = await input({
    message: 'Input file path (or press Enter to skip):',
    default: '',
  });

  if (!inputFile) {
    console.log(dim('\nNo file specified. Returning to menu.\n'));
    return;
  }

  try {
    // Read file
    const content = readFileSync(resolve(process.cwd(), inputFile), 'utf-8');
    const tokensBefore = Math.ceil(content.length / 4); // Rough estimate

    console.log(synapseViolet('\n📄 File Preview:'));
    console.log(dim(`  Length: ${content.length} characters`));
    console.log(dim(`  Estimated tokens: ${tokensBefore.toLocaleString()}\n`));

    const shouldOptimize = await confirm({
      message: 'Proceed with optimization?',
      default: true,
    });

    if (!shouldOptimize) {
      console.log(dim('\nOptimization cancelled.\n'));
      return;
    }

    // Run optimization (simplified version)
    console.log(neuralCyan('\n⚡ Optimizing...\n'));

    // Lazy-load optimizer
    const { optimizeCommand } = await import('./optimize.js');

    const result = await optimizeCommand({
      inputFile,
      memory,
      dryRun: false,
      verbose: false,
    });

    console.log(neuralCyan(`\n✓ Optimization complete in ${result.durationMs}ms!`));
    console.log(synapseViolet(`  Tokens: ${result.tokensBefore} → ${result.tokensAfter}`));
    console.log(
      brainPink(
        `  Saved: ${result.tokensBefore - result.tokensAfter} tokens (${(result.reduction * 100).toFixed(1)}%)\n`,
      ),
    );

    const saveOutput = await confirm({
      message: 'Save optimized output to file?',
      default: false,
    });

    if (saveOutput) {
      const outputFile = await input({
        message: 'Output file path:',
        default: inputFile.replace(/(\.[^.]+)$/, '.optimized$1'),
      });

      writeFileSync(resolve(process.cwd(), outputFile), result.output, 'utf-8');
      console.log(neuralCyan(`\n💾 Saved to ${outputFile}\n`));
    }
  } catch (error) {
    console.error(errorRed('\n✗ Error:'), error instanceof Error ? error.message : String(error));
    console.log();
  }
}

/**
 * Stats dashboard with detailed metrics
 */
async function showStatsDashboard(memory: KVMemory): Promise<void> {
  console.log(neuralCyan('\n📊 Stats Dashboard\n'));

  const view = await select({
    message: 'Select view:',
    choices: [
      { name: '📈 Optimization History', value: 'history' },
      { name: '⚡ Real-time Metrics', value: 'realtime' },
      { name: '💾 Memory Statistics', value: 'memory' },
      { name: '← Back to Main Menu', value: 'back' },
    ],
  });

  if (view === 'back') return;

  switch (view) {
    case 'history': {
      const stats = await memory.getOptimizationStats();
      const totalRuns = stats.length;
      const totalTokensSaved = stats.reduce(
        (sum, s) => sum + (s.tokens_before - s.tokens_after),
        0,
      );
      const avgReduction =
        totalRuns > 0
          ? stats.reduce((sum, s) => {
              return (
                sum +
                (s.tokens_before > 0 ? (s.tokens_before - s.tokens_after) / s.tokens_before : 0)
              );
            }, 0) / totalRuns
          : 0;

      console.log(brainPink('\n━'.repeat(60)));
      console.log(neuralCyan('  📈 Optimization History'));
      console.log(brainPink('━'.repeat(60)));
      console.log(`  ${synapseViolet('Total runs:')}       ${totalRuns.toLocaleString()}`);
      console.log(`  ${synapseViolet('Tokens saved:')}    ${totalTokensSaved.toLocaleString()}`);
      console.log(`  ${synapseViolet('Avg reduction:')}   ${(avgReduction * 100).toFixed(1)}%`);

      if (totalRuns > 0) {
        console.log(`\n  ${dim('Recent optimizations:')}`);
        const recent = stats.slice(0, 5);
        for (const stat of recent) {
          const date = new Date(stat.timestamp).toLocaleString();
          const reduction =
            stat.tokens_before > 0
              ? ((stat.tokens_before - stat.tokens_after) / stat.tokens_before) * 100
              : 0;
          console.log(`    ${dim(date)} - ${neuralCyan(`${reduction.toFixed(1)}%`)} reduction`);
        }
      }

      console.log(brainPink(`${'━'.repeat(60)}\n`));
      break;
    }

    case 'realtime': {
      const metrics = getMetrics();
      const snapshot = metrics.getSnapshot();

      console.log(brainPink('\n━'.repeat(60)));
      console.log(neuralCyan('  ⚡ Real-time Metrics'));
      console.log(brainPink('━'.repeat(60)));
      console.log(
        `  ${synapseViolet('Total runs:')}      ${snapshot.optimization.totalRuns.toLocaleString()}`,
      );
      console.log(
        `  ${synapseViolet('Tokens saved:')}   ${snapshot.optimization.totalTokensSaved.toLocaleString()}`,
      );
      console.log(
        `  ${synapseViolet('Avg reduction:')}  ${(snapshot.optimization.averageReduction * 100).toFixed(1)}%`,
      );
      console.log(
        `  ${synapseViolet('P50 latency:')}   ${snapshot.optimization.p50Latency.toFixed(0)}ms`,
      );
      console.log(
        `  ${synapseViolet('P95 latency:')}   ${snapshot.optimization.p95Latency.toFixed(0)}ms`,
      );
      console.log(
        `  ${synapseViolet('P99 latency:')}   ${snapshot.optimization.p99Latency.toFixed(0)}ms`,
      );
      console.log(
        `\n  ${synapseViolet('Cache hit rate:')} ${(snapshot.cache.hitRate * 100).toFixed(1)}%`,
      );
      console.log(
        `  ${synapseViolet('Cache hits:')}     ${snapshot.cache.totalHits.toLocaleString()}`,
      );
      console.log(
        `  ${synapseViolet('Cache misses:')}   ${snapshot.cache.totalMisses.toLocaleString()}`,
      );
      console.log(brainPink(`${'━'.repeat(60)}\n`));
      break;
    }

    case 'memory': {
      const entries = await memory.query({});
      const totalEntries = entries.length;
      const totalSize = entries.reduce((sum, e) => sum + (e.content?.length || 0), 0);

      console.log(brainPink('\n━'.repeat(60)));
      console.log(neuralCyan('  💾 Memory Statistics'));
      console.log(brainPink('━'.repeat(60)));
      console.log(`  ${synapseViolet('Total entries:')}   ${totalEntries.toLocaleString()}`);
      console.log(`  ${synapseViolet('Total size:')}      ${(totalSize / 1024).toFixed(1)} KB`);
      console.log(
        `  ${synapseViolet('Avg entry size:')}  ${totalEntries > 0 ? (totalSize / totalEntries).toFixed(0) : 0} bytes`,
      );
      console.log(brainPink(`${'━'.repeat(60)}\n`));
      break;
    }
  }
}

/**
 * Memory consolidation with confirmation
 */
async function consolidateMemory(memory: KVMemory): Promise<void> {
  console.log(neuralCyan('\n🧹 Memory Consolidation\n'));

  console.log(dim('This will:'));
  console.log(dim('  • Remove decayed entries'));
  console.log(dim('  • Merge duplicate entries'));
  console.log(dim('  • VACUUM database to reclaim space\n'));

  const shouldConsolidate = await confirm({
    message: 'Proceed with consolidation?',
    default: true,
  });

  if (!shouldConsolidate) {
    console.log(dim('\nConsolidation cancelled.\n'));
    return;
  }

  // Lazy-load consolidate command
  const { consolidateCommand } = await import('./consolidate.js');

  console.log(neuralCyan('\n⚡ Consolidating...\n'));

  const result = await consolidateCommand({ memory });

  console.log(neuralCyan(`\n✓ Consolidation complete in ${result.durationMs}ms!`));
  console.log(synapseViolet(`  Entries: ${result.entriesBefore} → ${result.entriesAfter}`));
  console.log(
    brainPink(
      `  Removed: ${result.decayedRemoved} decayed, ${result.duplicatesRemoved} duplicates\n`,
    ),
  );
}

/**
 * Quick actions menu
 */
async function showQuickActions(memory: KVMemory, configPath: string): Promise<void> {
  const action = await select({
    message: 'Quick Actions:',
    choices: [
      { name: '🔄 Reset Statistics', value: 'reset-stats' },
      { name: '📋 Export Config (JSON)', value: 'export-config' },
      { name: '🧪 Run Test Optimization', value: 'test-optimize' },
      { name: '← Back to Main Menu', value: 'back' },
    ],
  });

  if (action === 'back') return;

  switch (action) {
    case 'reset-stats': {
      const confirmReset = await confirm({
        message: 'Are you sure you want to reset all statistics?',
        default: false,
      });

      if (confirmReset) {
        await memory.clearOptimizationStats();
        console.log(neuralCyan('\n✓ Statistics cleared\n'));
      } else {
        console.log(dim('\nReset cancelled.\n'));
      }
      break;
    }

    case 'export-config': {
      const configYAML = readFileSync(configPath, 'utf-8');
      const config = parseYAML(configYAML);
      const json = JSON.stringify(config, null, 2);

      console.log(synapseViolet('\n📋 Configuration (JSON):\n'));
      console.log(json);
      console.log();

      const shouldSave = await confirm({
        message: 'Save to file?',
        default: false,
      });

      if (shouldSave) {
        const outputPath = resolve(configPath.replace(/\.yaml$/, '.json'));
        writeFileSync(outputPath, json, 'utf-8');
        console.log(neuralCyan(`\n💾 Saved to ${outputPath}\n`));
      }
      break;
    }

    case 'test-optimize': {
      console.log(neuralCyan('\n🧪 Running test optimization...\n'));

      const testContent = `
# Test Context

This is a test context for optimization.
It includes some sample content to demonstrate the optimization process.

## Features
- Token counting
- Relevance filtering
- Decay application
- State classification
      `.trim();

      const { optimizeCommand } = await import('./optimize.js');

      const result = await optimizeCommand({
        input: testContent,
        memory,
        dryRun: true,
        verbose: false,
      });

      console.log(neuralCyan(`\n✓ Test optimization complete in ${result.durationMs}ms!`));
      console.log(synapseViolet(`  Tokens: ${result.tokensBefore} → ${result.tokensAfter}`));
      console.log(
        brainPink(
          `  Saved: ${result.tokensBefore - result.tokensAfter} tokens (${(result.reduction * 100).toFixed(1)}%)\n`,
        ),
      );
      break;
    }
  }
}

/**
 * Execute the interactive command
 */
export async function interactiveCommand(
  options: InteractiveCommandOptions,
): Promise<InteractiveCommandResult> {
  const { memory, configPath } = options;

  showWelcomeBanner();

  let running = true;
  while (running) {
    try {
      const choice = await showMainMenu();

      switch (choice) {
        case 'configure':
          await configureWizard(configPath);
          break;

        case 'preview':
          await optimizePreview(memory);
          break;

        case 'stats':
          await showStatsDashboard(memory);
          break;

        case 'consolidate':
          await consolidateMemory(memory);
          break;

        case 'quick':
          await showQuickActions(memory, configPath);
          break;

        case 'exit':
          running = false;
          console.log(brainPink('\n👋 Thanks for using Cortex!\n'));
          break;
      }
    } catch (error) {
      if ((error as { message?: string }).message === 'User force closed the prompt') {
        running = false;
        console.log(brainPink('\n👋 Thanks for using Cortex!\n'));
      } else {
        console.error(
          errorRed('\n✗ Error:'),
          error instanceof Error ? error.message : String(error),
        );
        console.log();
      }
    }
  }

  return {
    success: true,
    message: 'Interactive session completed',
  };
}
