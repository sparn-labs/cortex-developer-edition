/**
 * Optimization Stats Panel — Top-left
 *
 * Shows total optimizations, tokens saved, average reduction,
 * and last 5 runs as compact rows.
 */

import { Box, Text } from 'ink';
import type React from 'react';
import type { OptimizationStats } from '../../../core/kv-memory.js';
import { theme } from '../theme.js';

interface Props {
  stats: OptimizationStats[];
  focused: boolean;
}

function formatTime(ts: number): string {
  const d = new Date(ts);
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}

function formatTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

function makeBar(pct: number, width: number): string {
  const filled = Math.round((pct / 100) * width);
  return '\u2588'.repeat(filled) + '\u2591'.repeat(width - filled);
}

export function OptimizationPanel({ stats, focused }: Props): React.ReactElement {
  const totalOpts = stats.length;
  const totalSaved = stats.reduce((s, r) => s + (r.tokens_before - r.tokens_after), 0);

  let avgReduction = 0;
  if (totalOpts > 0) {
    const totalBefore = stats.reduce((s, r) => s + r.tokens_before, 0);
    avgReduction =
      totalBefore > 0 ? ((totalBefore - (totalBefore - totalSaved)) / totalBefore) * 100 : 0;
  }

  const recent = stats.slice(-5).reverse();
  const borderColor = focused ? theme.neuralCyan : theme.dimGray;

  return (
    <Box
      flexDirection="column"
      borderStyle="round"
      borderColor={borderColor}
      paddingX={1}
      width="50%"
      flexGrow={1}
    >
      <Text bold color={theme.neuralCyan}>
        Optimization Stats
      </Text>
      <Text>
        Total: <Text color={theme.white}>{totalOpts}</Text> optimizations
      </Text>
      <Text>
        Saved: <Text color={theme.white}>{formatTokens(totalSaved)}</Text> tokens
      </Text>
      <Text>
        Avg: <Text color={theme.white}>{avgReduction.toFixed(1)}%</Text>{' '}
        <Text color={theme.neuralCyan}>{makeBar(avgReduction, 10)}</Text>
      </Text>
      {recent.length > 0 && (
        <Box flexDirection="column" marginTop={1}>
          <Text color={theme.dimGray}>Recent:</Text>
          {recent.map((r) => {
            const pct =
              r.tokens_before > 0
                ? (((r.tokens_before - r.tokens_after) / r.tokens_before) * 100).toFixed(0)
                : '0';
            return (
              <Text key={r.id}>
                {'  '}
                {formatTime(r.timestamp)} | {formatTokens(r.tokens_before)}
                {'\u2192'}
                {formatTokens(r.tokens_after)} | {pct}%
              </Text>
            );
          })}
        </Box>
      )}
    </Box>
  );
}
