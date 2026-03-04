/**
 * Output Panel — Shows command execution results.
 *
 * Bordered box below the 4 monitoring panels. Scrollable when focused.
 * Empty state shows usage hint.
 */

import { Box, Text } from 'ink';
import type React from 'react';
import type { OutputLine } from '../formatters.js';
import { theme } from '../theme.js';

interface Props {
  lines: OutputLine[];
  scrollOffset: number;
  focused: boolean;
  maxVisibleLines?: number;
}

export function OutputPanel({
  lines,
  scrollOffset,
  focused,
  maxVisibleLines = 8,
}: Props): React.ReactElement {
  const borderColor = focused ? theme.neuralCyan : theme.dimGray;

  if (lines.length === 0) {
    return (
      <Box
        flexDirection="column"
        borderStyle="round"
        borderColor={borderColor}
        paddingX={1}
        width="100%"
      >
        <Text bold color={theme.dimGray}>
          Output
        </Text>
        <Text color={theme.dimGray}>Type : then a command. Try help for available commands.</Text>
      </Box>
    );
  }

  const visible = lines.slice(scrollOffset, scrollOffset + maxVisibleLines);
  const hasMore = lines.length > maxVisibleLines;

  return (
    <Box
      flexDirection="column"
      borderStyle="round"
      borderColor={borderColor}
      paddingX={1}
      width="100%"
    >
      <Text bold color={theme.dimGray}>
        Output
      </Text>
      <Box flexDirection="column">
        {visible.map((line, i) => (
          <Text key={`${scrollOffset + i}`} color={line.color}>
            {line.text}
          </Text>
        ))}
      </Box>
      {hasMore && (
        <Text color={theme.dimGray}>
          [{scrollOffset + 1}-{Math.min(scrollOffset + maxVisibleLines, lines.length)}/
          {lines.length}]{focused ? ' \u2191\u2193 scroll' : ''}
        </Text>
      )}
    </Box>
  );
}
