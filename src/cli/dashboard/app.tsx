/**
 * Cortex Dashboard — Persistent TUI with integrated command execution.
 *
 * 4 auto-refreshing monitoring panels + command input/output area.
 * Vim-inspired `:` toggle between monitor mode and command mode.
 *
 * Keys (monitor mode): q=quit, Tab=cycle focus, arrows=scroll, :=command mode
 * Keys (command mode): Escape=monitor mode, Enter=execute, arrows=scroll output
 */

import { Box, render, Text, useApp, useInput } from 'ink';
import type React from 'react';
import { useEffect, useState } from 'react';
import { CommandInput } from './components/command-input.js';
import { OutputPanel } from './components/output-panel.js';
import { useCommandExecutor } from './hooks/use-command-executor.js';
import { useDashboardData } from './hooks/use-data.js';
import { DebtTrackerPanel } from './panels/debt-tracker.js';
import { GraphViewPanel } from './panels/graph-view.js';
import { MemoryStatusPanel } from './panels/memory-status.js';
import { OptimizationPanel } from './panels/optimization.js';
import { theme } from './theme.js';

type PanelId = 'optimization' | 'graph' | 'memory' | 'debt' | 'output';
const PANELS: PanelId[] = ['optimization', 'graph', 'memory', 'debt', 'output'];

type Mode = 'monitor' | 'command';

interface DashboardProps {
  dbPath: string;
  projectRoot: string;
  refreshInterval: number;
}

function Dashboard({ dbPath, projectRoot, refreshInterval }: DashboardProps): React.ReactElement {
  const { exit } = useApp();
  const data = useDashboardData(dbPath, projectRoot, refreshInterval);

  const [mode, setMode] = useState<Mode>('monitor');
  const [focusIndex, setFocusIndex] = useState(0);
  const [graphScroll, setGraphScroll] = useState(0);
  const [debtScroll, setDebtScroll] = useState(0);
  const [outputScroll, setOutputScroll] = useState(0);

  const focusedPanel = PANELS[focusIndex] ?? 'optimization';

  const executor = useCommandExecutor({
    getMemory: data.getMemory,
    forceRefresh: data.forceRefresh,
    dbPath,
    projectRoot,
  });

  useInput(
    (input, key) => {
      if (mode === 'command') {
        // In command mode, only handle Escape to go back
        if (key.escape) {
          setMode('monitor');
        }
        return;
      }

      // Monitor mode keybinds
      if (input === 'q') {
        exit();
        return;
      }

      if (input === ':') {
        setMode('command');
        return;
      }

      if (key.tab) {
        setFocusIndex((prev) => (prev + 1) % PANELS.length);
        return;
      }

      // Arrow keys for scrolling the focused panel
      if (key.upArrow) {
        if (focusedPanel === 'graph') setGraphScroll((prev) => Math.max(0, prev - 1));
        if (focusedPanel === 'debt') setDebtScroll((prev) => Math.max(0, prev - 1));
        if (focusedPanel === 'output') setOutputScroll((prev) => Math.max(0, prev - 1));
      }
      if (key.downArrow) {
        if (focusedPanel === 'graph') setGraphScroll((prev) => prev + 1);
        if (focusedPanel === 'debt') setDebtScroll((prev) => prev + 1);
        if (focusedPanel === 'output') setOutputScroll((prev) => prev + 1);
      }
    },
    { isActive: mode === 'monitor' || mode === 'command' },
  );

  // Auto-scroll output to follow latest lines
  const outputMaxVisible = 8;
  useEffect(() => {
    setOutputScroll(Math.max(0, executor.outputLines.length - outputMaxVisible));
  }, [executor.outputLines.length]);

  if (data.loading) {
    return (
      <Box flexDirection="column" padding={1}>
        <Text color={theme.neuralCyan}>Cortex Dashboard</Text>
        <Text color={theme.dimGray}>Loading data...</Text>
      </Box>
    );
  }

  if (data.error) {
    return (
      <Box flexDirection="column" padding={1}>
        <Text color={theme.neuralCyan}>Cortex Dashboard</Text>
        <Text color={theme.errorRed}>Error: {data.error}</Text>
        <Text color={theme.dimGray}>Press q to quit</Text>
      </Box>
    );
  }

  const timeStr = data.lastRefresh.toLocaleTimeString();
  const modeHint =
    mode === 'command' ? 'Esc:monitor Enter:run' : 'q:quit Tab:focus \u2191\u2193:scroll ::cmd';

  return (
    <Box flexDirection="column">
      {/* Header */}
      <Box justifyContent="space-between" paddingX={1}>
        <Text bold color={theme.neuralCyan}>
          Cortex Dashboard
        </Text>
        <Text color={theme.dimGray}>
          {modeHint} | {timeStr}
        </Text>
      </Box>

      {/* Top row */}
      <Box>
        <OptimizationPanel
          stats={data.optimizationStats}
          focused={focusedPanel === 'optimization'}
        />
        <GraphViewPanel
          analysis={data.graphAnalysis}
          nodes={data.graphNodes}
          focused={focusedPanel === 'graph'}
          scrollOffset={graphScroll}
        />
      </Box>

      {/* Bottom row */}
      <Box>
        <MemoryStatusPanel
          totalEntries={data.totalEntries}
          dbSizeBytes={data.dbSizeBytes}
          stateDistribution={data.stateDistribution}
          daemon={data.daemon}
          focused={focusedPanel === 'memory'}
        />
        <DebtTrackerPanel
          debts={data.debts}
          debtStats={data.debtStats}
          focused={focusedPanel === 'debt'}
          scrollOffset={debtScroll}
        />
      </Box>

      {/* Output panel */}
      <OutputPanel
        lines={executor.outputLines}
        scrollOffset={outputScroll}
        focused={focusedPanel === 'output'}
      />

      {/* Command input */}
      <CommandInput
        onSubmit={executor.execute}
        isRunning={executor.isRunning}
        runningCommand={executor.runningCommand}
        active={mode === 'command'}
      />
    </Box>
  );
}

export interface RenderDashboardOptions {
  dbPath: string;
  projectRoot: string;
  refreshInterval?: number;
}

export function renderDashboard(options: RenderDashboardOptions): void {
  render(
    <Dashboard
      dbPath={options.dbPath}
      projectRoot={options.projectRoot}
      refreshInterval={options.refreshInterval ?? 2000}
    />,
  );
}
