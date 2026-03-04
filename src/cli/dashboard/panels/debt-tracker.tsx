/**
 * Tech Debt Panel — Bottom-right
 *
 * Scrollable list of debt items with severity coloring.
 * Footer shows open/in-progress/resolved/overdue counts.
 */

import { Box, Text } from 'ink';
import type React from 'react';
import type { DebtStats, TechDebt } from '../../../core/debt-tracker.js';
import { theme } from '../theme.js';

interface Props {
  debts: TechDebt[];
  debtStats: DebtStats | null;
  focused: boolean;
  scrollOffset: number;
}

function severityColor(severity: string): string {
  switch (severity) {
    case 'P0':
      return theme.errorRed;
    case 'P1':
      return theme.synapseViolet;
    default:
      return theme.dimGray;
  }
}

function formatDate(ts: number): string {
  const d = new Date(ts);
  return `${d.getMonth() + 1}/${d.getDate()}`;
}

export function DebtTrackerPanel({
  debts,
  debtStats,
  focused,
  scrollOffset,
}: Props): React.ReactElement {
  const borderColor = focused ? theme.neuralCyan : theme.dimGray;
  const now = Date.now();

  // Filter to unresolved debts for the list
  const openDebts = debts.filter((d) => d.status !== 'resolved');
  const visibleDebts = openDebts.slice(scrollOffset, scrollOffset + 8);

  return (
    <Box
      flexDirection="column"
      borderStyle="round"
      borderColor={borderColor}
      paddingX={1}
      width="50%"
      flexGrow={1}
    >
      <Text bold color={theme.errorRed}>
        Tech Debt
      </Text>
      <Box flexDirection="column">
        {visibleDebts.length === 0 && <Text color={theme.dimGray}>No open debts</Text>}
        {visibleDebts.map((d) => {
          const isOverdue = d.repayment_date < now && d.status !== 'resolved';
          const color = severityColor(d.severity);
          const desc =
            d.description.length > 30 ? `${d.description.substring(0, 27)}...` : d.description;
          return (
            <Text key={d.id}>
              <Text color={color}>[{d.severity}]</Text> {desc}{' '}
              <Text color={theme.dimGray}>(due: {formatDate(d.repayment_date)})</Text>
              {isOverdue && <Text color={theme.errorRed}> OVERDUE</Text>}
            </Text>
          );
        })}
        {openDebts.length > 8 && (
          <Text color={theme.dimGray}>
            [{scrollOffset + 1}-{Math.min(scrollOffset + 8, openDebts.length)}/{openDebts.length}]
            {focused ? ' \u2191\u2193 scroll' : ''}
          </Text>
        )}
      </Box>
      {debtStats && (
        <Box marginTop={1}>
          <Text color={theme.dimGray}>
            Open:{debtStats.open} InProg:{debtStats.in_progress} Resolved:{debtStats.resolved}{' '}
            Overdue:{debtStats.overdue}
          </Text>
        </Box>
      )}
    </Box>
  );
}
