/**
 * Command executor hook — wires parser + command modules + formatters.
 *
 * Parses raw input, lazy-imports command modules, calls them, formats results
 * into OutputLine[] for the output panel.
 */

import { useCallback, useState } from 'react';
import type { KVMemory } from '../../../core/kv-memory.js';
import { parseCommand } from '../command-parser.js';
import type { OutputLine } from '../formatters.js';
import {
  formatConsolidate,
  formatDebt,
  formatDocs,
  formatError,
  formatExec,
  formatGraph,
  formatHelp,
  formatOptimize,
  formatPlan,
  formatPlanList,
  formatSearch,
  formatStats,
  formatVerify,
} from '../formatters.js';

const MAX_OUTPUT_LINES = 200;

interface UseCommandExecutorOptions {
  getMemory: () => KVMemory | null;
  forceRefresh: () => void;
  dbPath: string;
  projectRoot: string;
}

interface UseCommandExecutorResult {
  execute: (rawInput: string) => void;
  outputLines: OutputLine[];
  isRunning: boolean;
  runningCommand: string | undefined;
  clearOutput: () => void;
}

export function useCommandExecutor({
  getMemory,
  forceRefresh,
  dbPath,
  projectRoot,
}: UseCommandExecutorOptions): UseCommandExecutorResult {
  const [outputLines, setOutputLines] = useState<OutputLine[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  const [runningCommand, setRunningCommand] = useState<string | undefined>();

  const appendLines = useCallback((lines: OutputLine[]) => {
    setOutputLines((prev) => {
      const next = [...prev, ...lines];
      return next.length > MAX_OUTPUT_LINES ? next.slice(-MAX_OUTPUT_LINES) : next;
    });
  }, []);

  const clearOutput = useCallback(() => {
    setOutputLines([]);
  }, []);

  const execute = useCallback(
    (rawInput: string) => {
      const parsed = parseCommand(rawInput);
      if (!parsed) return;

      // Built-in commands
      if (parsed.name === 'clear') {
        clearOutput();
        return;
      }

      if (parsed.name === 'help') {
        appendLines(formatHelp());
        return;
      }

      setIsRunning(true);
      setRunningCommand(parsed.name);

      void (async () => {
        try {
          const lines = await executeCommand(parsed.name, parsed.positionals, parsed.flags, {
            getMemory,
            dbPath,
            projectRoot,
          });
          appendLines(lines);
          forceRefresh();
        } catch (err) {
          appendLines(formatError(err instanceof Error ? err : new Error(String(err))));
        } finally {
          setIsRunning(false);
          setRunningCommand(undefined);
        }
      })();
    },
    [getMemory, forceRefresh, dbPath, projectRoot, appendLines, clearOutput],
  );

  return { execute, outputLines, isRunning, runningCommand, clearOutput };
}

async function executeCommand(
  name: string,
  positionals: string[],
  flags: Record<string, string | true>,
  ctx: { getMemory: () => KVMemory | null; dbPath: string; projectRoot: string },
): Promise<OutputLine[]> {
  switch (name) {
    case 'optimize': {
      const memory = ctx.getMemory();
      if (!memory) throw new Error('Memory not initialized');
      const { optimizeCommand } = await import('../../commands/optimize.js');
      const result = await optimizeCommand({
        memory,
        input: typeof flags['input'] === 'string' ? flags['input'] : undefined,
        inputFile: typeof flags['input-file'] === 'string' ? flags['input-file'] : undefined,
        outputFile: typeof flags['output-file'] === 'string' ? flags['output-file'] : undefined,
        dryRun: flags['dry-run'] === true,
        verbose: flags['verbose'] === true || flags['v'] === true,
      });
      return formatOptimize(result);
    }

    case 'stats': {
      const memory = ctx.getMemory();
      if (!memory) throw new Error('Memory not initialized');
      const { statsCommand } = await import('../../commands/stats.js');
      const result = await statsCommand({
        memory,
        graph: flags['graph'] === true || flags['g'] === true,
        reset: flags['reset'] === true,
        confirmReset: flags['confirm-reset'] === true,
      });
      return formatStats(result);
    }

    case 'consolidate': {
      const memory = ctx.getMemory();
      if (!memory) throw new Error('Memory not initialized');
      const { consolidateCommand } = await import('../../commands/consolidate.js');
      const result = await consolidateCommand({ memory });
      return formatConsolidate(result);
    }

    case 'search': {
      const { searchCommand } = await import('../../commands/search.js');
      // Handle subcommands: "search init", "search refresh"
      const subcommand =
        positionals[0] === 'init' || positionals[0] === 'refresh' ? positionals[0] : undefined;
      const query = subcommand ? undefined : positionals.join(' ') || undefined;
      const result = await searchCommand({
        query,
        subcommand,
        glob: typeof flags['glob'] === 'string' ? flags['glob'] : undefined,
        maxResults:
          typeof flags['max-results'] === 'string'
            ? Number.parseInt(flags['max-results'], 10)
            : undefined,
      });
      return formatSearch(result);
    }

    case 'graph': {
      const { graphCommand } = await import('../../commands/graph.js');
      const result = await graphCommand({
        entry: typeof flags['entry'] === 'string' ? flags['entry'] : undefined,
        depth: typeof flags['depth'] === 'string' ? Number.parseInt(flags['depth'], 10) : undefined,
        focus: typeof flags['focus'] === 'string' ? flags['focus'] : undefined,
      });
      return formatGraph(result);
    }

    case 'plan': {
      // "plan list" subcommand
      if (positionals[0] === 'list') {
        const { planListCommand } = await import('../../commands/plan.js');
        const result = await planListCommand({});
        return formatPlanList(result);
      }
      const { planCommand } = await import('../../commands/plan.js');
      const task = positionals.join(' ');
      if (!task) throw new Error('Task description required: plan <task>');
      const files = typeof flags['files'] === 'string' ? flags['files'].split(',') : undefined;
      const searches =
        typeof flags['searches'] === 'string' ? flags['searches'].split(',') : undefined;
      const result = await planCommand({ task, files, searches });
      return formatPlan(result);
    }

    case 'exec': {
      const planId = positionals[0];
      if (!planId) throw new Error('Plan ID required: exec <planId>');
      const { execCommand } = await import('../../commands/exec.js');
      const result = await execCommand({ planId });
      return formatExec(result);
    }

    case 'verify': {
      const planId = positionals[0];
      if (!planId) throw new Error('Plan ID required: verify <planId>');
      const { verifyCommand } = await import('../../commands/verify.js');
      const result = await verifyCommand({ planId });
      return formatVerify(result);
    }

    case 'docs': {
      const { docsCommand } = await import('../../commands/docs.js');
      const result = await docsCommand({
        output: typeof flags['output'] === 'string' ? flags['output'] : undefined,
        includeGraph: flags['no-graph'] !== true,
      });
      return formatDocs(result);
    }

    case 'debt': {
      const subcommand = positionals[0] as
        | 'add'
        | 'list'
        | 'resolve'
        | 'stats'
        | 'start'
        | undefined;
      if (!subcommand || !['add', 'list', 'resolve', 'stats', 'start'].includes(subcommand)) {
        throw new Error('Subcommand required: debt add|list|resolve|start|stats');
      }
      const { debtCommand } = await import('../../commands/debt.js');
      const result = await debtCommand({
        subcommand,
        description: subcommand === 'add' ? positionals.slice(1).join(' ') || undefined : undefined,
        severity: typeof flags['severity'] === 'string' ? flags['severity'] : undefined,
        due: typeof flags['due'] === 'string' ? flags['due'] : undefined,
        tokenCost:
          typeof flags['token-cost'] === 'string'
            ? Number.parseInt(flags['token-cost'], 10)
            : undefined,
        id: subcommand === 'resolve' || subcommand === 'start' ? positionals[1] : undefined,
        overdue: flags['overdue'] === true,
      });
      return formatDebt(result);
    }

    default:
      throw new Error(`Unknown command: ${name}. Type help for available commands.`);
  }
}
