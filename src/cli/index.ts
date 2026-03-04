#!/usr/bin/env node

/**
 * Cortex CLI entry point.
 * Implements all CLI commands using Commander.js.
 */

import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Command, Help } from 'commander';
import { load as loadYAML } from 'js-yaml';
import { playCommand, playComplete, playEnd, playStartup } from '../utils/audio.js';
import { setPreciseTokenCounting } from '../utils/tokenizer.js';
import { getBanner } from './ui/banner.js';

// Get cortex's own version from its package.json
function getVersion(): string {
  try {
    // Read from cortex's own package.json (relative to compiled module)
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = dirname(__filename);
    const pkg = JSON.parse(readFileSync(join(__dirname, '../../package.json'), 'utf-8'));
    return pkg.version;
  } catch {
    return '1.0.0';
  }
}

const VERSION = getVersion();

// Load precise token counting setting from config if available
try {
  const configPath = resolve(process.cwd(), '.cortex/config.yaml');
  const configContent = readFileSync(configPath, 'utf-8');
  // biome-ignore lint/suspicious/noExplicitAny: parseYAML returns unknown
  const config = loadYAML(configContent) as any;
  if (config?.realtime?.preciseTokenCounting) {
    setPreciseTokenCounting(true);
  }
} catch {
  // Config not found or not initialized — use default heuristic
}

// Lazy-loaded imports (loaded only when commands are executed):
// - createKVMemory (heavy: better-sqlite3)
// - command implementations (may import heavy modules)
// - progress spinners (heavy: ora)
// - colors (chalk is reasonably lightweight, but lazy-load for consistency)

/**
 * Global error handler for uncaught errors
 * Provides graceful degradation and helpful error messages
 */
async function handleError(error: Error | unknown, context?: string): Promise<void> {
  // Lazy-load colors
  const { errorRed, synapseViolet } = await import('./ui/colors.js');

  const errorMsg = error instanceof Error ? error.message : String(error);
  const stack = error instanceof Error ? error.stack : undefined;

  // Display user-friendly error message
  console.error(errorRed('\n✗ Error:'), errorMsg);

  if (context) {
    console.error(errorRed('Context:'), context);
  }

  // Database errors - provide recovery suggestions
  if (errorMsg.includes('SQLITE') || errorMsg.includes('database')) {
    console.error(synapseViolet('\n💡 Database issue detected:'));
    console.error('  Try running: rm -rf .cortex/ && cortex init');
    console.error('  This will reinitialize your Cortex database.\n');
  }

  // Permission errors
  if (errorMsg.includes('EACCES') || errorMsg.includes('permission')) {
    console.error(synapseViolet('\n💡 Permission issue detected:'));
    console.error('  Check file permissions in .cortex/ directory');
    console.error('  Try: chmod -R u+rw .cortex/\n');
  }

  // File not found errors
  if (errorMsg.includes('ENOENT') || errorMsg.includes('no such file')) {
    console.error(synapseViolet('\n💡 File not found:'));
    console.error('  Make sure you have run: cortex init');
    console.error('  Or check that the specified file exists.\n');
  }

  // Memory errors
  if (errorMsg.includes('out of memory') || errorMsg.includes('heap')) {
    console.error(synapseViolet('\n💡 Memory issue detected:'));
    console.error('  Try processing smaller chunks of context');
    console.error('  Or increase Node.js memory: NODE_OPTIONS=--max-old-space-size=4096\n');
  }

  // Show stack trace in verbose mode
  if (process.env['CORTEX_DEBUG'] === 'true' && stack) {
    console.error(errorRed('\nStack trace:'));
    console.error(stack);
  } else {
    console.error('  Run with CORTEX_DEBUG=true for stack trace\n');
  }

  process.exit(1);
}

/**
 * Global unhandled rejection handler
 */
process.on('unhandledRejection', (reason) => {
  void handleError(reason, 'Unhandled promise rejection');
});

/**
 * Global uncaught exception handler
 */
process.on('uncaughtException', (error) => {
  void handleError(error, 'Uncaught exception');
});

const program = new Command();

// Essential commands shown in default help
const ESSENTIAL_COMMANDS = new Set(['setup', 'status', 'optimize', 'stats', 'hooks']);

program
  .name('cortex')
  .description('Context optimization for AI coding agents')
  .version(VERSION, '-v, --version', 'Output the current version')
  .helpOption('-h, --help', 'Display help for command')
  .option('--all', 'Show all commands in help')
  .enablePositionalOptions();

// Save Commander's default help formatter before overriding
const defaultFormatHelp = Help.prototype.formatHelp;

// Custom help: show only essential commands by default
program.configureHelp({
  formatHelp(cmd, helper) {
    const showAll = process.argv.includes('--all');
    if (showAll || cmd.name() !== 'cortex') {
      // Use Commander's built-in formatter (avoid recursion)
      return defaultFormatHelp.call(helper, cmd, helper);
    }

    // Build custom help with command tiers
    const lines: string[] = [];
    lines.push('');
    lines.push(`Usage: ${cmd.name()} [command] [options]`);
    lines.push('');
    lines.push('Context optimization for AI coding agents');
    lines.push('');
    lines.push('Essential Commands:');

    const cmds = cmd.commands;
    const essential = cmds.filter((c) => ESSENTIAL_COMMANDS.has(c.name()));
    const advanced = cmds.filter((c) => !ESSENTIAL_COMMANDS.has(c.name()));

    const padWidth = Math.max(...essential.map((c) => c.name().length)) + 2;
    for (const c of essential) {
      lines.push(`  ${c.name().padEnd(padWidth)} ${c.description()}`);
    }

    lines.push('');
    lines.push(`Advanced Commands (${advanced.length} more — use --all to see all):`);
    lines.push(`  init, optimize, relay, consolidate, config, daemon,`);
    lines.push(`  interactive, graph, search, plan, exec, verify, docs, debt, dashboard`);
    lines.push('');
    lines.push('Options:');
    lines.push('  -v, --version  Output the current version');
    lines.push('  -h, --help     Display help for command');
    lines.push('  --all          Show all commands in help');
    lines.push('');
    lines.push('Getting Started:');
    lines.push('  $ cortex setup     # One-command setup (recommended)');
    lines.push('  $ cortex status    # Check project status');
    lines.push('');
    return lines.join('\n');
  },
});

playStartup();

program.hook('preAction', () => {
  playCommand();
});

program.hook('postAction', () => {
  playComplete();
});

process.on('exit', () => {
  playEnd();
});

process.once('SIGINT', () => {
  // Force exit to avoid inquirer re-prompting — 'exit' event will play end sound
  process.exit(0);
});

// Init command
program
  .command('init')
  .description('Initialize Cortex in the current project')
  .option('-f, --force', 'Force overwrite if .cortex/ already exists')
  .addHelpText(
    'after',
    `
Examples:
  $ cortex init                  # Initialize in current directory
  $ cortex init --force          # Overwrite existing .cortex/ directory

Files Created:
  .cortex/config.yaml            # Configuration with optimization parameters
  .cortex/memory.db              # SQLite database for context storage

Next Steps:
  After initialization, use 'cortex optimize' to start optimizing context.
`,
  )
  .action(async (options) => {
    // Lazy-load dependencies
    const { initCommand, displayInitSuccess } = await import('./commands/init.js');
    const { createInitSpinner } = await import('./ui/progress.js');
    const { neuralCyan, errorRed } = await import('./ui/colors.js');

    const spinner = createInitSpinner('🧠 Initializing Cortex...');
    try {
      spinner.start();
      spinner.text = '📁 Creating .cortex/ directory...';
      const result = await initCommand({ force: options.force });
      spinner.succeed(neuralCyan('Cortex initialized successfully!'));
      displayInitSuccess(result);
    } catch (error) {
      spinner.fail(errorRed('Initialization failed'));
      console.error('Error:', error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

// Setup command (one-command onboarding)
program
  .command('setup')
  .description('One-command setup: init + hooks + daemon + docs')
  .option('-f, --force', 'Force overwrite if .cortex/ already exists')
  .option('--skip-hooks', 'Skip hook installation')
  .option('--skip-daemon', 'Skip daemon start')
  .option('--skip-docs', 'Skip CLAUDE.md generation')
  .addHelpText(
    'after',
    `
Examples:
  $ cortex setup                   # Full automatic setup
  $ cortex setup --force           # Overwrite existing .cortex/
  $ cortex setup --skip-daemon     # Setup without starting daemon

What It Does:
  1. Detects Claude Code environment
  2. Creates .cortex/ with auto-configured settings
  3. Installs hooks (globally for Claude Code)
  4. Starts the optimization daemon
  5. Generates CLAUDE.md project documentation

This is the recommended way to get started with Cortex.
`,
  )
  .action(async (options) => {
    const { setupCommand } = await import('./commands/setup.js');
    const { neuralCyan, brainPink, dim, errorRed, synapseViolet } = await import('./ui/colors.js');
    const { createInitSpinner } = await import('./ui/progress.js');
    const { getBanner } = await import('./ui/banner.js');

    console.log(getBanner(VERSION));
    const spinner = createInitSpinner('Setting up Cortex...');
    spinner.start();

    try {
      spinner.text = 'Detecting environment...';
      const result = await setupCommand({
        force: options.force,
        skipHooks: options.skipHooks,
        skipDaemon: options.skipDaemon,
        skipDocs: options.skipDocs,
      });

      spinner.succeed(neuralCyan(`Setup complete in ${result.durationMs}ms!`));

      // Display results
      console.log(`\n${brainPink('━'.repeat(60))}`);
      console.log(brainPink('  Cortex Setup Summary'));
      console.log(brainPink('━'.repeat(60)));

      for (const step of result.steps) {
        const icon = step.status === 'success' ? '✓' : step.status === 'skipped' ? '○' : '✗';
        const color =
          step.status === 'success' ? neuralCyan : step.status === 'failed' ? errorRed : dim;
        console.log(`  ${color(`${icon} ${step.message}`)}`);
      }

      console.log(`\n  ${neuralCyan('Config:')}   ${dim(result.configPath)}`);
      console.log(`  ${neuralCyan('Database:')} ${dim(result.dbPath)}`);

      const failed = result.steps.filter((s) => s.status === 'failed');
      if (failed.length > 0) {
        console.log(
          synapseViolet(`\n  ${failed.length} step(s) had issues — Cortex will still work.`),
        );
      }

      console.log(`\n  ${brainPink('→')} Cortex is now active. Start a Claude Code session!`);
      console.log(`${brainPink('━'.repeat(60))}\n`);
    } catch (error) {
      spinner.fail(errorRed('Setup failed'));
      console.error(errorRed('Error:'), error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

// Optimize command
program
  .command('optimize')
  .description('Optimize context memory')
  .option('-i, --input <file>', 'Input file path')
  .option('-o, --output <file>', 'Output file path')
  .option('--dry-run', 'Run without saving to memory')
  .option('--verbose', 'Show detailed per-entry scores')
  .addHelpText(
    'after',
    `
Examples:
  $ cortex optimize -i context.txt -o optimized.txt    # Optimize file
  $ cat context.txt | cortex optimize                  # Optimize from stdin
  $ cortex optimize -i context.txt --dry-run           # Preview without saving
  $ cortex optimize -i context.txt --verbose           # Show entry scores

How It Works:
  1. Relevance Filtering: Keeps only 2-5% most relevant context
  2. Time-Based Decay: Fades old entries unless reinforced
  3. Entry Classification: Classifies as silent/ready/active
  4. Critical Event Detection: Locks errors and stack traces
  5. Periodic Consolidation: Merges duplicates and cleans up

Typical Results:
  • 60-90% token reduction
  • Preserved task-critical information
  • Enhanced AI agent focus
`,
  )
  .action(async (options) => {
    // Lazy-load dependencies
    const { createKVMemory } = await import('../core/kv-memory.js');
    const { optimizeCommand } = await import('./commands/optimize.js');
    const { createOptimizeSpinner, showTokenSavings } = await import('./ui/progress.js');
    const { neuralCyan, synapseViolet, errorRed } = await import('./ui/colors.js');

    const spinner = createOptimizeSpinner('🧠 Initializing optimization...');
    try {
      spinner.start();

      // Read from stdin if no input file specified
      let input: string | undefined;
      if (!options.input && !process.stdin.isTTY) {
        spinner.text = '📖 Reading context from stdin...';
        const chunks: Buffer[] = [];
        for await (const chunk of process.stdin) {
          chunks.push(chunk);
        }
        input = Buffer.concat(chunks).toString('utf-8');
      } else if (options.input) {
        spinner.text = `📖 Reading context from ${options.input}...`;
      }

      // Load memory
      spinner.text = '💾 Loading memory database...';
      const dbPath = resolve(process.cwd(), '.cortex/memory.db');
      const memory = await createKVMemory(dbPath);

      try {
        // Run optimization
        spinner.text = '⚡ Optimizing context...';
        const result = await optimizeCommand({
          input,
          inputFile: options.input,
          outputFile: options.output,
          memory,
          dryRun: options.dryRun || false,
          verbose: options.verbose || false,
        });

        spinner.succeed(neuralCyan(`Optimization complete in ${result.durationMs}ms!`));

        // Display visual impact
        showTokenSavings(result.tokensBefore, result.tokensAfter, result.reduction);

        // Show entry stats
        console.log(synapseViolet('  Entry Distribution:'));
        console.log(`    • Processed: ${result.entriesProcessed}`);
        console.log(`    • Kept: ${result.entriesKept}`);
        console.log(`    • Active: ${result.stateDistribution.active}`);
        console.log(`    • Ready: ${result.stateDistribution.ready}`);
        console.log(`    • Silent: ${result.stateDistribution.silent}\n`);

        // Show verbose details if requested
        if (options.verbose && result.details) {
          console.log(neuralCyan('  📋 Entry Details:'));
          for (const detail of result.details) {
            console.log(
              `    ${detail.id.substring(0, 8)}: score=${detail.score.toFixed(2)}, state=${detail.state}, tokens=${detail.tokens}`,
            );
          }
          console.log();
        }

        // Write to stdout if no output file
        if (!options.output) {
          console.log(result.output);
        }
      } finally {
        await memory.close();
      }
    } catch (error) {
      spinner.fail(errorRed('Optimization failed'));
      console.error(errorRed('Error:'), error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

// Stats command
program
  .command('stats')
  .description('View optimization statistics')
  .option('--graph', 'Display ASCII bar chart of optimization history')
  .option('--reset', 'Clear all optimization statistics')
  .option('--json', 'Output statistics in JSON format')
  .addHelpText(
    'after',
    `
Examples:
  $ cortex stats                 # View summary statistics
  $ cortex stats --graph         # Show ASCII chart of optimization history
  $ cortex stats --json          # Output as JSON for automation
  $ cortex stats --reset         # Clear all statistics (with confirmation)

Tracked Metrics:
  • Total optimizations performed
  • Total tokens saved across all runs
  • Average reduction percentage
  • Per-run token before/after counts
  • Optimization duration
`,
  )
  .action(async (options) => {
    // Lazy-load dependencies
    const { createKVMemory } = await import('../core/kv-memory.js');
    const { statsCommand } = await import('./commands/stats.js');
    const { createStatsSpinner } = await import('./ui/progress.js');
    const { neuralCyan, synapseViolet, errorRed } = await import('./ui/colors.js');

    const spinner = options.graph ? createStatsSpinner('📊 Generating statistics...') : null;
    try {
      if (spinner) spinner.start();

      // Load memory
      if (spinner) spinner.text = '💾 Loading optimization history...';
      const dbPath = resolve(process.cwd(), '.cortex/memory.db');
      const memory = await createKVMemory(dbPath);

      // Handle reset with confirmation
      let confirmReset = false;
      if (options.reset) {
        if (spinner) spinner.stop();
        console.log(synapseViolet('Warning: This will clear all optimization statistics.'));
        confirmReset = true; // Auto-confirm for now
      }

      try {
        // Get stats
        if (spinner) spinner.text = '📈 Calculating statistics...';
        const result = await statsCommand({
          memory,
          graph: options.graph || false,
          reset: options.reset || false,
          confirmReset,
          json: options.json || false,
        });

        if (spinner) spinner.succeed(neuralCyan('Statistics ready!'));

        // Display output
        if (options.json) {
          console.log(result.json);
        } else if (options.reset && result.resetConfirmed) {
          console.log(neuralCyan('\n✓ Statistics cleared\n'));
        } else {
          // Display stats summary
          console.log(neuralCyan('\n📊 Optimization Statistics\n'));
          console.log(`  Total optimizations: ${result.totalCommands}`);
          console.log(`  Total tokens saved: ${result.totalTokensSaved.toLocaleString()}`);
          console.log(`  Average reduction: ${(result.averageReduction * 100).toFixed(1)}%`);

          if (options.graph && result.graph) {
            console.log(result.graph);
          }

          console.log();
        }
      } finally {
        await memory.close();
      }
    } catch (error) {
      if (spinner) spinner.fail(errorRed('Statistics failed'));
      console.error(errorRed('Error:'), error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

// Relay command
program
  .command('relay <command> [args...]')
  .description('Proxy a CLI command through optimization')
  .passThroughOptions()
  .option('--silent', 'Suppress token savings summary')
  .addHelpText(
    'after',
    `
Examples:
  $ cortex relay git log         # Run 'git log' and optimize output
  $ cortex relay npm test        # Run 'npm test' and optimize output
  $ cortex relay gh pr view 123  # Optimize GitHub CLI output
  $ cortex relay ls -la --silent # Suppress optimization summary

Use Cases:
  • Wrap verbose CLI commands (git log, gh pr view)
  • Optimize test runner output
  • Compress build logs
  • Filter CI/CD output for AI agent consumption

The relay command passes the exit code from the wrapped command.
`,
  )
  .action(async (command, args, options) => {
    // Lazy-load dependencies
    const { createKVMemory } = await import('../core/kv-memory.js');
    const { relayCommand } = await import('./commands/relay.js');
    const { neuralCyan, errorRed } = await import('./ui/colors.js');

    try {
      // Load memory
      const dbPath = resolve(process.cwd(), '.cortex/memory.db');
      const memory = await createKVMemory(dbPath);

      let exitCode = 1;
      try {
        // Execute relay
        const result = await relayCommand({
          command,
          args: args || [],
          memory,
          silent: options.silent || false,
        });

        // Display optimized output
        console.log(result.optimizedOutput);

        // Display summary if not silent
        if (result.summary) {
          console.error(neuralCyan(`\n${result.summary}\n`));
        }

        exitCode = result.exitCode;
      } finally {
        await memory.close();
      }

      // Exit with same code as proxied command
      process.exit(exitCode);
    } catch (error) {
      console.error(errorRed('Error:'), error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

// Consolidate command
program
  .command('consolidate')
  .description('Consolidate memory: remove decayed entries and merge duplicates')
  .addHelpText(
    'after',
    `
Examples:
  $ cortex consolidate           # Run memory consolidation

What It Does:
  1. Remove Decayed Entries: Deletes entries that have fully decayed
  2. Merge Duplicates: Combines identical content entries
  3. VACUUM Database: Reclaims disk space from deletions
  4. Update Statistics: Tracks consolidation metrics

When to Run:
  • After long-running sessions
  • Before important optimizations
  • When database size grows large
  • As part of nightly maintenance

Typical Results:
  • 20-40% database size reduction
  • Faster query performance
  • Cleaner memory organization
`,
  )
  .action(async () => {
    // Lazy-load dependencies
    const { createKVMemory } = await import('../core/kv-memory.js');
    const { consolidateCommand } = await import('./commands/consolidate.js');
    const { createConsolidateSpinner, showConsolidationSummary } = await import('./ui/progress.js');
    const { neuralCyan, synapseViolet, errorRed } = await import('./ui/colors.js');

    const spinner = createConsolidateSpinner('🧹 Initializing memory consolidation...');
    try {
      spinner.start();

      // Load memory
      spinner.text = '💾 Loading memory database...';
      const dbPath = resolve(process.cwd(), '.cortex/memory.db');
      const memory = await createKVMemory(dbPath);

      try {
        // Run consolidation
        spinner.text = '🔍 Identifying decayed entries...';
        const result = await consolidateCommand({ memory });

        spinner.succeed(neuralCyan(`Consolidation complete in ${result.durationMs}ms!`));

        // Display visual impact
        showConsolidationSummary(
          result.entriesBefore,
          result.entriesAfter,
          result.decayedRemoved,
          result.duplicatesRemoved,
          result.durationMs,
        );

        // Database vacuum status
        if (result.vacuumCompleted) {
          console.log(synapseViolet('  ✓ Database VACUUM completed\n'));
        } else {
          console.log(errorRed('  ✗ Database VACUUM failed\n'));
        }
      } finally {
        await memory.close();
      }
    } catch (error) {
      spinner.fail(errorRed('Consolidation failed'));
      console.error(errorRed('Error:'), error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

// Config command
program
  .command('config [subcommand] [key] [value]')
  .description('View or modify configuration')
  .option('--json', 'Output result as JSON')
  .addHelpText(
    'after',
    `
Examples:
  $ cortex config                        # Open config in $EDITOR
  $ cortex config get pruning.threshold  # Get specific value
  $ cortex config set pruning.threshold 3 # Set value
  $ cortex config --json                 # View full config as JSON

Configuration Keys:
  pruning.threshold                     # Relevance threshold (2-5%)
  decay.halfLife                        # Decay half-life (hours)
  decay.minScore                        # Minimum decay score (0.0-1.0)
  states.activeThreshold                # Active state threshold
  states.readyThreshold                 # Ready state threshold
  embedding.model                       # BTSP embedding model
  embedding.dimensions                  # Embedding vector size

The config file is located at .cortex/config.yaml
`,
  )
  .action(async (subcommand, key, value, options) => {
    // Lazy-load dependencies
    const { configCommand } = await import('./commands/config.js');
    const { neuralCyan, errorRed } = await import('./ui/colors.js');

    try {
      const configPath = resolve(process.cwd(), '.cortex/config.yaml');

      // Execute config command
      const result = await configCommand({
        configPath,
        subcommand: subcommand as 'get' | 'set' | undefined,
        key,
        value,
        json: options.json || false,
      });

      if (!result.success) {
        console.error(errorRed('Error:'), result.error);
        process.exit(1);
      }

      // Handle editor mode
      if (result.editorPath && !options.json) {
        const editorEnv = process.env['EDITOR'] || 'vim';
        // Support multi-word EDITOR values (e.g. "code --wait")
        const editorParts = editorEnv.split(/\s+/);
        const editorCmd = editorParts[0] || 'vim';
        const editorArgs = [...editorParts.slice(1), result.editorPath];
        console.log(neuralCyan(`\n📝 Opening config in ${editorCmd}...\n`));

        // Spawn editor
        const child = spawn(editorCmd, editorArgs, {
          stdio: 'inherit',
        });

        child.on('close', (code) => {
          if (code === 0) {
            console.log(neuralCyan('\n✓ Config edited\n'));
          }
          process.exit(code ?? 0);
        });

        return;
      }

      // Display result
      if (result.json) {
        console.log(result.json);
      } else if (result.message) {
        console.log(result.message);
      }
    } catch (error) {
      console.error(errorRed('Error:'), error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

// Daemon command
program
  .command('daemon <subcommand>')
  .description('Manage real-time optimization daemon')
  .addHelpText(
    'after',
    `
Subcommands:
  start                                 # Start daemon
  stop                                  # Stop daemon
  status                                # Check daemon status

Examples:
  $ cortex daemon start                  # Start watching Claude Code sessions
  $ cortex daemon stop                   # Stop daemon
  $ cortex daemon status                 # Check if daemon is running

The daemon watches ~/.claude/projects/**/*.jsonl and automatically
optimizes contexts when they exceed the configured threshold.
`,
  )
  .action(async (subcommand) => {
    // Lazy-load dependencies
    const { load: parseYAML } = await import('js-yaml');
    const { createDaemonCommand } = await import('../daemon/daemon-process.js');
    const { neuralCyan, errorRed } = await import('./ui/colors.js');

    try {
      // Load config
      const configPath = resolve(process.cwd(), '.cortex/config.yaml');
      const configYAML = readFileSync(configPath, 'utf-8');
      // biome-ignore lint/suspicious/noExplicitAny: parseYAML returns unknown, need to cast
      const config = parseYAML(configYAML) as any;

      const daemon = createDaemonCommand();

      switch (subcommand) {
        case 'start': {
          const result = await daemon.start(config);
          if (result.success) {
            console.log(neuralCyan(`\n✓ ${result.message}\n`));
          } else {
            console.error(errorRed(`\n✗ ${result.message}\n`));
            process.exit(1);
          }
          break;
        }

        case 'stop': {
          const result = await daemon.stop(config);
          if (result.success) {
            console.log(neuralCyan(`\n✓ ${result.message}\n`));
          } else {
            console.error(errorRed(`\n✗ ${result.message}\n`));
            process.exit(1);
          }
          break;
        }

        case 'status': {
          const result = await daemon.status(config);
          if (result.running) {
            console.log(neuralCyan(`\n✓ ${result.message}`));
            if (result.sessionsWatched !== undefined) {
              console.log(`  Sessions watched: ${result.sessionsWatched}`);
            }
            if (result.tokensSaved !== undefined) {
              console.log(`  Tokens saved: ${result.tokensSaved.toLocaleString()}`);
            }
            console.log();
          } else {
            console.log(errorRed(`\n✗ ${result.message}\n`));
          }
          break;
        }

        default:
          console.error(errorRed(`\nUnknown subcommand: ${subcommand}\n`));
          console.error('Valid subcommands: start, stop, status\n');
          process.exit(1);
      }
    } catch (error) {
      console.error(errorRed('Error:'), error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

// Hooks command
program
  .command('hooks <subcommand>')
  .description('Manage Claude Code hook integration')
  .option('--global', 'Install hooks globally (for all projects)')
  .addHelpText(
    'after',
    `
Subcommands:
  install                               # Install hooks
  uninstall                             # Uninstall hooks
  status                                # Check hook status

Examples:
  $ cortex hooks install                 # Install hooks for current project
  $ cortex hooks install --global        # Install hooks globally
  $ cortex hooks uninstall               # Uninstall hooks
  $ cortex hooks status                  # Check if hooks are active

Hooks automatically optimize context before each Claude Code prompt
and compress verbose tool results after execution.
`,
  )
  .action(async (subcommand, options) => {
    // Lazy-load dependencies
    const { hooksCommand } = await import('./commands/hooks.js');
    const { neuralCyan, errorRed } = await import('./ui/colors.js');

    try {
      const result = await hooksCommand({
        subcommand: subcommand as 'install' | 'uninstall' | 'status',
        global: options.global || false,
      });

      if (result.success) {
        console.log(neuralCyan(`\n✓ ${result.message}`));

        if (result.hookPaths) {
          console.log('\nHook paths:');
          console.log(`  pre-prompt: ${result.hookPaths.prePrompt}`);
          console.log(`  post-tool-result: ${result.hookPaths.postToolResult}`);
          console.log(`  stop-docs-refresh: ${result.hookPaths.stopDocsRefresh}`);
        }

        console.log();
      } else {
        console.error(errorRed(`\n✗ ${result.message}`));
        if (result.error) {
          console.error(`  ${result.error}`);
        }
        console.log();
        process.exit(1);
      }
    } catch (error) {
      console.error(errorRed('Error:'), error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

// Interactive command
program
  .command('interactive')
  .alias('i')
  .description('Launch interactive mode for configuration and exploration')
  .addHelpText(
    'after',
    `
Examples:
  $ cortex interactive                   # Launch interactive mode
  $ cortex i                             # Short alias

Features:
  • 📝 Configuration Wizard - Guided prompts for all settings
  • 🔍 Optimization Preview - Test optimization with file preview
  • 📊 Stats Dashboard - Beautiful metrics display
  • 🧹 Memory Consolidation - Interactive cleanup
  • 🚀 Quick Actions - Common tasks and shortcuts

The interactive mode provides a conversational interface for exploring
and configuring Cortex without memorizing CLI flags.
`,
  )
  .action(async () => {
    // Lazy-load dependencies
    const { createKVMemory } = await import('../core/kv-memory.js');
    const { interactiveCommand } = await import('./commands/interactive.js');
    const { errorRed } = await import('./ui/colors.js');

    try {
      // Load memory
      const dbPath = resolve(process.cwd(), '.cortex/memory.db');
      const memory = await createKVMemory(dbPath);

      try {
        // Config path
        const configPath = resolve(process.cwd(), '.cortex/config.yaml');

        // Run interactive mode
        await interactiveCommand({
          memory,
          configPath,
        });
      } finally {
        await memory.close();
      }
    } catch (error) {
      console.error(errorRed('Error:'), error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

// Analyze command
program
  .command('analyze [path]')
  .description('Multi-dimensional codebase analysis with scoring')
  .option('--focus <categories>', 'Analyze specific categories (comma-separated)')
  .option('--json', 'Output structured JSON')
  .option('-o, --output <file>', 'Write full Markdown report to file')
  .option('--verbose', 'Show all findings')
  .option('--changed [ref]', 'Only files changed since ref (default: HEAD~1)')
  .option('--file <path>', 'Analyze a single file')
  .option('--history', 'Show score history')
  .option('--save-baseline', 'Save current results as baseline')
  .option('--diff', 'Compare against saved baseline')
  .action(async (path, options) => {
    const { analyzeCommand } = await import('./commands/analyze.js');
    const { neuralCyan, synapseViolet, errorRed, dim, bold } = await import('./ui/colors.js');
    const { writeFileSync } = await import('node:fs');

    try {
      const result = await analyzeCommand({
        path,
        focus: options.focus,
        json: options.json,
        output: options.output,
        verbose: options.verbose,
        changed: options.changed,
        file: options.file,
        history: options.history,
        saveBaseline: options.saveBaseline,
        diff: options.diff,
      });

      if (options.json) {
        console.log(result.json);
      } else {
        const { report } = result;

        // Mode header
        let modeLabel = '';
        if (result.mode === 'changed') {
          modeLabel = ` (changed files since ${result.modeDetail ?? 'HEAD~1'}, ${report.metrics.totalFiles} files)`;
        } else if (result.mode === 'file') {
          modeLabel = ` — ${result.modeDetail}`;
        }

        console.log(neuralCyan(`\n  Cortex Analysis — ${report.project.name}${modeLabel}\n`));

        // Score + trend
        let trendStr = '';
        if (result.trend) {
          const color =
            result.trend.delta > 0 ? neuralCyan : result.trend.delta < 0 ? errorRed : dim;
          trendStr = ` ${color(result.trend.label)}`;
        }
        console.log(
          bold(`  Score: ${report.score.totalScore}/100  Grade: ${report.score.grade}`) +
            trendStr +
            '\n',
        );

        for (const cat of report.categoryResults) {
          const catData = report.score.categories[cat.category];
          if (catData?.isNA) {
            console.log(dim(`  ${cat.name.padEnd(22)} N/A`));
          } else {
            console.log(
              `  ${cat.name.padEnd(22)} ${synapseViolet(`${Math.round(cat.score * 100) / 100}/${cat.maxPoints}`)}`,
            );
          }
        }

        // Top findings
        const allFindings = report.categoryResults.flatMap((r) => r.findings);
        const critical = allFindings.filter((f) => f.severity === 'critical');
        const major = allFindings.filter((f) => f.severity === 'major');

        if (critical.length > 0 || major.length > 0) {
          console.log(errorRed('\n  Top Issues:'));
          for (const f of [...critical, ...major].slice(0, 5)) {
            const sev = f.severity === 'critical' ? errorRed('[CRIT]') : synapseViolet('[MAJR]');
            console.log(`  ${sev} ${f.ruleId}: ${f.title}`);
            if (f.filePath) console.log(dim(`       ${f.filePath}`));
          }
        }

        console.log(
          dim(
            `\n  ${report.metrics.totalFiles} files | ${report.metrics.totalTokens.toLocaleString()} tokens | ${allFindings.length} findings\n`,
          ),
        );

        // Baseline diff output
        if (result.baselineDiff) {
          const bd = result.baselineDiff;
          const scoreSign = bd.scoreChange >= 0 ? '+' : '';
          console.log(bold('  Baseline Diff:'));
          console.log(neuralCyan(`    New findings: ${bd.newFindings}`));
          console.log(neuralCyan(`    Fixed:        ${bd.fixedFindings}`));
          console.log(dim(`    Unchanged:    ${bd.unchanged}`));
          console.log(bold(`    Score change: ${scoreSign}${bd.scoreChange}\n`));
        }

        // History output
        if (result.historyEntries && result.historyEntries.length > 0) {
          console.log(bold('  Score History:'));
          for (const entry of result.historyEntries) {
            const date = new Date(entry.timestamp).toISOString().slice(0, 16).replace('T', ' ');
            console.log(dim(`    ${date}  ${entry.score}/100  ${entry.grade}`));
          }
          console.log('');
        }

        if (options.saveBaseline) {
          console.log(neuralCyan('  Baseline saved to .cortex/analyze-baseline.json\n'));
        }

        if (options.output) {
          writeFileSync(options.output, result.markdown, 'utf-8');
          console.log(neuralCyan(`  Report written to ${options.output}\n`));
        }
      }
    } catch (error) {
      console.error(errorRed('Error:'), error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

// Graph command
program
  .command('graph')
  .description('Analyze dependency graph of the project')
  .option('--entry <file>', 'Start from a specific entry point')
  .option('--depth <n>', 'Limit traversal depth', (v: string) => Number.parseInt(v, 10))
  .option('--focus <pattern>', 'Focus on modules matching pattern')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    const { graphCommand } = await import('./commands/graph.js');
    const { neuralCyan, synapseViolet, errorRed } = await import('./ui/colors.js');

    try {
      const result = await graphCommand({
        entry: options.entry,
        depth: options.depth,
        focus: options.focus,
        json: options.json,
      });

      if (options.json) {
        console.log(result.json);
      } else {
        console.log(neuralCyan('\n📊 Dependency Graph Analysis\n'));
        console.log(`  Files analyzed: ${result.nodeCount}`);
        console.log(`  Entry points: ${result.analysis.entryPoints.length}`);
        console.log(`  Orphaned files: ${result.analysis.orphans.length}`);
        console.log(`  Total tokens: ${result.analysis.totalTokens.toLocaleString()}`);

        if (result.analysis.hotPaths.length > 0) {
          console.log(synapseViolet('\n  Hot paths (most imported):'));
          for (const path of result.analysis.hotPaths.slice(0, 5)) {
            console.log(`    ${path}`);
          }
        }

        if (result.analysis.entryPoints.length > 0) {
          console.log(synapseViolet('\n  Entry points:'));
          for (const path of result.analysis.entryPoints.slice(0, 5)) {
            console.log(`    ${path}`);
          }
        }

        console.log();
      }
    } catch (error) {
      console.error(errorRed('Error:'), error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

// Search command
program
  .command('search [query]')
  .description('Search codebase using FTS5 + ripgrep')
  .option('--glob <pattern>', 'Filter by file glob pattern')
  .option('--max <n>', 'Max results (default: 10)', (v: string) => Number.parseInt(v, 10))
  .option('--json', 'Output as JSON')
  .action(async (query, options) => {
    const { searchCommand } = await import('./commands/search.js');
    const { neuralCyan, synapseViolet, errorRed } = await import('./ui/colors.js');

    try {
      // Detect subcommands
      let subcommand: 'init' | 'refresh' | undefined;
      if (query === 'init') subcommand = 'init';
      if (query === 'refresh') subcommand = 'refresh';

      const result = await searchCommand({
        query: subcommand ? undefined : query,
        subcommand,
        glob: options.glob,
        maxResults: options.max,
        json: options.json,
      });

      if (options.json && result.json) {
        console.log(result.json);
      } else if (result.message) {
        console.log(neuralCyan(`\n✓ ${result.message}\n`));
      }

      if (result.results && !options.json) {
        console.log(neuralCyan(`\n🔍 ${result.results.length} results\n`));
        for (const r of result.results) {
          console.log(synapseViolet(`  ${r.filePath}:${r.lineNumber}`));
          console.log(`    ${r.content.trim()}`);
          console.log();
        }
      }
    } catch (error) {
      console.error(errorRed('Error:'), error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

// Plan command
program
  .command('plan <task>')
  .description('Create an execution plan for a task')
  .option('--files <files...>', 'Files needed for the task')
  .option('--searches <queries...>', 'Search queries to run')
  .option('--max-reads <n>', 'Max file reads (default: 5)', (v: string) => Number.parseInt(v, 10))
  .option('--json', 'Output as JSON')
  .action(async (task, options) => {
    const { planCommand } = await import('./commands/plan.js');
    const { neuralCyan, synapseViolet, errorRed } = await import('./ui/colors.js');

    try {
      if (task === 'list') {
        const { planListCommand } = await import('./commands/plan.js');
        const result = await planListCommand({ json: options.json });

        if (options.json) {
          console.log(result.json);
        } else {
          console.log(neuralCyan('\n📋 Plans\n'));
          for (const p of result.plans) {
            console.log(`  ${p.id} [${p.status}] ${p.task}`);
          }
          if (result.plans.length === 0) console.log('  No plans found');
          console.log();
        }
        return;
      }

      const result = await planCommand({
        task,
        files: options.files,
        searches: options.searches,
        maxReads: options.maxReads,
        json: options.json,
      });

      if (options.json) {
        console.log(result.json);
      } else {
        console.log(neuralCyan(`\n✓ ${result.message}`));
        console.log(synapseViolet('\n  Steps:'));
        for (const step of result.plan.steps) {
          console.log(`    ${step.order}. [${step.action}] ${step.target} — ${step.description}`);
        }
        console.log();
      }
    } catch (error) {
      console.error(errorRed('Error:'), error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

// Exec command
program
  .command('exec <planId>')
  .description('Execute a plan with constraints')
  .option('--json', 'Output as JSON')
  .action(async (planId, options) => {
    const { execCommand } = await import('./commands/exec.js');
    const { neuralCyan, errorRed } = await import('./ui/colors.js');

    try {
      const result = await execCommand({ planId, json: options.json });

      if (options.json) {
        console.log(result.json);
      } else {
        console.log(neuralCyan(`\n✓ ${result.message}\n`));
      }
    } catch (error) {
      console.error(errorRed('Error:'), error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

// Verify command
program
  .command('verify <planId>')
  .description('Verify plan completion')
  .option('--json', 'Output as JSON')
  .action(async (planId, options) => {
    const { verifyCommand } = await import('./commands/verify.js');
    const { neuralCyan, synapseViolet, errorRed } = await import('./ui/colors.js');

    try {
      const result = await verifyCommand({ planId, json: options.json });

      if (options.json) {
        console.log(result.json);
      } else {
        console.log(neuralCyan(`\n${result.message}`));
        console.log(synapseViolet('\n  Steps:'));
        for (const d of result.verification.details) {
          const icon = d.status === 'completed' ? '✓' : d.status === 'failed' ? '✗' : '○';
          console.log(`    ${icon} ${d.step}. [${d.action}] ${d.target} — ${d.status}`);
        }
        console.log();
      }
    } catch (error) {
      console.error(errorRed('Error:'), error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

// Docs command
program
  .command('docs')
  .description('Auto-generate CLAUDE.md for the project')
  .option('-o, --output <file>', 'Output file path (default: CLAUDE.md)')
  .option('--no-graph', 'Skip dependency graph analysis')
  .option('--json', 'Output content as JSON')
  .action(async (options) => {
    const { docsCommand } = await import('./commands/docs.js');
    const { neuralCyan, errorRed } = await import('./ui/colors.js');

    try {
      const result = await docsCommand({
        output: options.output,
        includeGraph: options.graph !== false,
        json: options.json,
      });

      if (options.json) {
        console.log(JSON.stringify({ content: result.content }, null, 2));
      } else {
        console.log(neuralCyan(`\n✓ ${result.message}\n`));
      }
    } catch (error) {
      console.error(errorRed('Error:'), error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

// Debt command
program
  .command('debt <subcommand> [description]')
  .description('Track technical debt')
  .option('--severity <level>', 'Severity: P0, P1, P2 (default: P1)')
  .option('--due <date>', 'Repayment date (YYYY-MM-DD)')
  .option('--files <files...>', 'Affected files')
  .option('--tokens <n>', 'Token cost estimate', (v: string) => Number.parseInt(v, 10))
  .option('--id <id>', 'Debt ID (for resolve/start)')
  .option('--overdue', 'Show only overdue debts')
  .option('--json', 'Output as JSON')
  .action(async (subcommand, description, options) => {
    const { debtCommand } = await import('./commands/debt.js');
    const { neuralCyan, synapseViolet, errorRed } = await import('./ui/colors.js');

    try {
      const result = await debtCommand({
        subcommand: subcommand as 'add' | 'list' | 'resolve' | 'stats' | 'start',
        description,
        severity: options.severity,
        due: options.due,
        files: options.files,
        tokenCost: options.tokens,
        id: options.id || description,
        overdue: options.overdue,
        json: options.json,
      });

      if (options.json && result.json) {
        console.log(result.json);
      } else {
        console.log(neuralCyan(`\n✓ ${result.message}`));

        if (result.debts) {
          for (const d of result.debts) {
            const due = new Date(d.repayment_date).toLocaleDateString();
            const overdue =
              d.repayment_date < Date.now() && d.status !== 'resolved' ? ' [OVERDUE]' : '';
            console.log(
              synapseViolet(
                `  ${d.id} [${d.severity}] ${d.status}${overdue} — ${d.description} (due: ${due})`,
              ),
            );
          }
        }

        if (result.stats) {
          console.log(
            `  Open: ${result.stats.open} | In Progress: ${result.stats.in_progress} | Resolved: ${result.stats.resolved}`,
          );
          console.log(
            `  Overdue: ${result.stats.overdue} | Repayment rate: ${(result.stats.repaymentRate * 100).toFixed(0)}%`,
          );
        }

        console.log();
      }
    } catch (error) {
      console.error(errorRed('Error:'), error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

// Dashboard command
program
  .command('dashboard')
  .alias('dash')
  .description('Launch interactive TUI dashboard')
  .option('--refresh <ms>', 'Refresh interval in milliseconds', (v: string) =>
    Number.parseInt(v, 10),
  )
  .action(async (options) => {
    const { renderDashboard } = await import('./dashboard/app.js');
    const dbPath = resolve(process.cwd(), '.cortex/memory.db');
    const projectRoot = process.cwd();
    renderDashboard({
      dbPath,
      projectRoot,
      refreshInterval: options.refresh ?? 2000,
    });
  });

// Security audit command
program
  .command('secure [path]')
  .description('Enterprise security audit — 10 OWASP 2025-aligned defense layers')
  .option('--fix', 'Apply safe auto-fixes')
  .option('--ci', 'CI mode — exit non-zero on failures')
  .option('--min-grade <grade>', 'Minimum passing grade (CI mode)')
  .option('--fail-on <severity>', 'Fail on severity: critical, high, medium, low')
  .option('--layer <layers>', 'Run specific layers (comma-separated: 1,5,7)')
  .option('--compare <file>', 'Compare with previous JSON report')
  .option('--output <format>', 'Output format: json, markdown (default: console)')
  .option('--output-file <file>', 'Write report to file')
  .option('--quick', 'Quick scan — critical layers only (1,3,4,5)')
  .option('--compliance <framework>', 'Compliance framework: owasp-top10, asvs-l2, nist-zta')
  .option('--verbose', 'Show detailed check output')
  .addHelpText(
    'after',
    `
Examples:
  $ cortex secure                           # Scan current directory
  $ cortex secure ./my-project              # Scan specific path
  $ cortex secure --quick                   # Critical layers only
  $ cortex secure --layer=1,5               # Access control + injection only
  $ cortex secure --output json --output-file report.json
  $ cortex secure --ci --min-grade=A --fail-on=critical
  $ cortex secure --fix                     # Apply safe auto-fixes
  $ cortex secure --compare previous.json   # Compare with baseline
`,
  )
  .action(async (path, options) => {
    const { secureCommand, displaySecureReport } = await import('./commands/secure.js');
    const { neuralCyan, synapseViolet, errorRed, brainPink, dim, bold } = await import(
      './ui/colors.js'
    );
    const { createOptimizeSpinner } = await import('./ui/progress.js');

    const spinner = createOptimizeSpinner('Running security audit...');
    try {
      playCommand();
      spinner.start();

      const result = await secureCommand({ path, ...options });

      spinner.stop();

      // JSON output mode — just print JSON
      if (options.output === 'json') {
        console.log(result.json);
      } else if (options.output === 'markdown') {
        console.log(result.markdown);
      } else {
        displaySecureReport(result, { neuralCyan, synapseViolet, errorRed, brainPink, dim, bold });
      }

      if (options.outputFile) {
        console.log(dim(`Report written to ${options.outputFile}`));
      }

      playComplete();

      if (result.exitCode !== 0) {
        process.exit(result.exitCode);
      }
    } catch (error) {
      spinner.fail(errorRed('Security audit failed'));
      console.error(errorRed('Error:'), error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

// Compliance audit command
program
  .command('comply [path]')
  .description('Legal & regulatory compliance audit — GDPR, CCPA, HIPAA, SOC2')
  .option('--ci', 'CI mode — exit non-zero on failures')
  .option('--min-grade <grade>', 'Minimum passing grade (CI mode)')
  .option('--fail-on <severity>', 'Fail on severity: critical, high, medium, low')
  .option('--framework <list>', 'Frameworks: gdpr,ccpa,hipaa,soc2,all (default: all)')
  .option('--layer <layers>', 'Run specific layers (comma-separated: 1,3,6)')
  .option('--output <format>', 'Output format: json, markdown (default: console)')
  .option('--output-file <file>', 'Write report to file')
  .option('--quick', 'Quick scan — layers 1,2,3 only')
  .option('--verbose', 'Show detailed check output')
  .addHelpText(
    'after',
    `
Examples:
  $ cortex comply                           # Scan current directory (all frameworks)
  $ cortex comply ./my-project              # Scan specific path
  $ cortex comply --framework gdpr          # GDPR only
  $ cortex comply --framework gdpr,ccpa     # GDPR + CCPA
  $ cortex comply --quick                   # Layers 1,2,3 only
  $ cortex comply --layer=1,3              # Personal data + data rights only
  $ cortex comply --output json --output-file report.json
  $ cortex comply --ci --min-grade=A --fail-on=critical
`,
  )
  .action(async (path, options) => {
    const { complyCommand, displayComplyReport } = await import('./commands/comply.js');
    const { neuralCyan, synapseViolet, errorRed, brainPink, dim, bold } = await import(
      './ui/colors.js'
    );
    const { createOptimizeSpinner } = await import('./ui/progress.js');

    const spinner = createOptimizeSpinner('Running compliance audit...');
    try {
      playCommand();
      spinner.start();

      const result = await complyCommand({ path, ...options });

      spinner.stop();

      // JSON output mode — just print JSON
      if (options.output === 'json') {
        console.log(result.json);
      } else if (options.output === 'markdown') {
        console.log(result.markdown);
      } else {
        displayComplyReport(result, { neuralCyan, synapseViolet, errorRed, brainPink, dim, bold });
      }

      if (options.outputFile) {
        console.log(dim(`Report written to ${options.outputFile}`));
      }

      playComplete();

      if (result.exitCode !== 0) {
        process.exit(result.exitCode);
      }
    } catch (error) {
      spinner.fail(errorRed('Compliance audit failed'));
      console.error(errorRed('Error:'), error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

// Status command (quick overview)
program
  .command('status')
  .description('Quick project status overview')
  .action(async () => {
    const { neuralCyan, synapseViolet } = await import('./ui/colors.js');

    console.log(neuralCyan(`\n🧠 Cortex v${VERSION} Status\n`));

    // Check .cortex init
    const { existsSync: exists } = await import('node:fs');
    const cortexDir = resolve(process.cwd(), '.cortex');
    const initialized = exists(cortexDir);
    console.log(`  Initialized: ${initialized ? '✓' : '✗ (run cortex init)'}`);

    if (initialized) {
      // Check database
      const dbPath = resolve(cortexDir, 'memory.db');
      console.log(`  Database: ${exists(dbPath) ? '✓' : '✗'}`);

      // Check search index
      const searchDb = resolve(cortexDir, 'search.db');
      console.log(`  Search index: ${exists(searchDb) ? '✓' : '✗ (run cortex search init)'}`);

      // Check plans
      const plansDir = resolve(cortexDir, 'plans');
      if (exists(plansDir)) {
        const { readdirSync: readDir } = await import('node:fs');
        const plans = readDir(plansDir).filter((f: string) => f.endsWith('.json'));
        console.log(`  Plans: ${plans.length}`);
      }

      // Check daemon
      const pidFile = resolve(cortexDir, 'daemon.pid');
      console.log(`  Daemon: ${exists(pidFile) ? '✓ running' : '✗ stopped'}`);
    }

    console.log(
      synapseViolet('\n  Commands: graph | search | plan | exec | verify | docs | debt\n'),
    );
  });

// Show banner on version
program.on('option:version', () => {
  console.log(getBanner(VERSION));
  process.exit(0);
});

// Default command: run `status` when no args provided
const args = process.argv.slice(2).filter((a) => !a.startsWith('-'));
if (
  args.length === 0 &&
  !process.argv.includes('-h') &&
  !process.argv.includes('--help') &&
  !process.argv.includes('-v') &&
  !process.argv.includes('--version') &&
  !process.argv.includes('--all')
) {
  // Insert 'status' as the default command
  process.argv.splice(2, 0, 'status');
}

// Parse arguments
program.parse();
