/**
 * Memory / Daemon Status Panel — Bottom-left
 *
 * Shows DB entry count, file size, state distribution,
 * and daemon running/stopped status.
 */

import { Box, Text } from 'ink';
import type React from 'react';
import type { DaemonStatusResult } from '../../../daemon/daemon-process.js';
import { theme } from '../theme.js';

interface Props {
  totalEntries: number;
  dbSizeBytes: number;
  stateDistribution: { active: number; ready: number; silent: number };
  daemon: DaemonStatusResult | null;
  focused: boolean;
}

function formatSize(bytes: number): string {
  if (bytes >= 1_048_576) return `${(bytes / 1_048_576).toFixed(1)} MB`;
  if (bytes >= 1_024) return `${(bytes / 1_024).toFixed(1)} KB`;
  return `${bytes} B`;
}

function formatTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

export function MemoryStatusPanel({
  totalEntries,
  dbSizeBytes,
  stateDistribution,
  daemon,
  focused,
}: Props): React.ReactElement {
  const borderColor = focused ? theme.neuralCyan : theme.dimGray;

  const daemonRunning = daemon?.running ?? false;
  const daemonPid = daemon?.pid;
  const sessions = daemon?.sessionsWatched;
  const tokensSaved = daemon?.tokensSaved;

  return (
    <Box
      flexDirection="column"
      borderStyle="round"
      borderColor={borderColor}
      paddingX={1}
      width="50%"
      flexGrow={1}
    >
      <Text bold color={theme.brainPink}>
        Memory / Daemon
      </Text>
      <Text>
        Entries: <Text color={theme.white}>{totalEntries}</Text> | Size:{' '}
        <Text color={theme.white}>{formatSize(dbSizeBytes)}</Text>
      </Text>
      <Text>
        Active: <Text color={theme.neuralCyan}>{stateDistribution.active}</Text> Ready:{' '}
        <Text color={theme.synapseViolet}>{stateDistribution.ready}</Text> Silent:{' '}
        <Text color={theme.dimGray}>{stateDistribution.silent}</Text>
      </Text>
      <Box marginTop={1}>
        {daemonRunning ? (
          <Text>
            Daemon: <Text color={theme.neuralCyan}>{'\u25CF'} Running</Text>
            {daemonPid != null ? ` (PID ${daemonPid})` : ''}
          </Text>
        ) : (
          <Text>
            Daemon: <Text color={theme.errorRed}>{'\u25CF'} Stopped</Text>
          </Text>
        )}
      </Box>
      {daemonRunning && (
        <Text>
          Sessions: <Text color={theme.white}>{sessions ?? 0}</Text> | Saved:{' '}
          <Text color={theme.white}>{formatTokens(tokensSaved ?? 0)}</Text>
        </Text>
      )}
    </Box>
  );
}
