/**
 * Dependency Graph Panel — Top-right
 *
 * ASCII tree of top 8 hot paths using box-drawing chars.
 * Scrollable when focused.
 */

import { Box, Text } from 'ink';
import type React from 'react';
import type { DependencyNode, GraphAnalysis } from '../../../core/dependency-graph.js';
import { theme } from '../theme.js';

interface Props {
  analysis: GraphAnalysis | null;
  nodes: Map<string, DependencyNode>;
  focused: boolean;
  scrollOffset: number;
}

function formatTokens(n: number): string {
  if (n >= 1_000) return `${(n / 1_000).toFixed(0)}K`;
  return String(n);
}

function basename(filePath: string): string {
  const parts = filePath.replace(/\\/g, '/').split('/');
  return parts[parts.length - 1] || filePath;
}

interface TreeLine {
  text: string;
  color: string;
}

function buildTreeLines(nodes: Map<string, DependencyNode>): TreeLine[] {
  const lines: TreeLine[] = [];

  // Sort by callers count (descending) to show hottest paths first
  const sorted = [...nodes.values()]
    .filter((n) => n.callers.length > 0)
    .sort((a, b) => b.callers.length - a.callers.length)
    .slice(0, 8);

  for (const node of sorted) {
    const name = basename(node.filePath);
    const tok = formatTokens(node.tokenEstimate);
    lines.push({
      text: `${name} (${node.callers.length} callers, ${tok}tok)`,
      color: theme.neuralCyan,
    });

    const callerNames = node.callers.slice(0, 3).map(basename);
    const remaining = node.callers.length - callerNames.length;

    for (let i = 0; i < callerNames.length; i++) {
      const isLast = i === callerNames.length - 1 && remaining === 0;
      const prefix = isLast ? ' \u2514\u2500\u2500 ' : ' \u251C\u2500\u2500 ';
      lines.push({
        text: `${prefix}${callerNames[i]}`,
        color: theme.dimGray,
      });
    }

    if (remaining > 0) {
      lines.push({
        text: ` \u2514\u2500\u2500 ... ${remaining} more`,
        color: theme.dimGray,
      });
    }
  }

  return lines;
}

export function GraphViewPanel({
  analysis,
  nodes,
  focused,
  scrollOffset,
}: Props): React.ReactElement {
  const borderColor = focused ? theme.neuralCyan : theme.dimGray;

  if (!analysis) {
    return (
      <Box
        flexDirection="column"
        borderStyle="round"
        borderColor={borderColor}
        paddingX={1}
        width="50%"
        flexGrow={1}
      >
        <Text bold color={theme.synapseViolet}>
          Dependency Graph
        </Text>
        <Text color={theme.dimGray}>Loading graph...</Text>
      </Box>
    );
  }

  const lines = buildTreeLines(nodes);
  const visibleLines = lines.slice(scrollOffset, scrollOffset + 12);

  return (
    <Box
      flexDirection="column"
      borderStyle="round"
      borderColor={borderColor}
      paddingX={1}
      width="50%"
      flexGrow={1}
    >
      <Text bold color={theme.synapseViolet}>
        Dependency Graph
      </Text>
      <Text color={theme.dimGray}>
        {analysis.entryPoints.length} entries | {analysis.orphans.length} orphans |{' '}
        {formatTokens(analysis.totalTokens)}tok
      </Text>
      <Box flexDirection="column" marginTop={1}>
        {visibleLines.map((line) => (
          <Text key={line.text} color={line.color}>
            {line.text}
          </Text>
        ))}
        {lines.length > 12 && (
          <Text color={theme.dimGray}>
            [{scrollOffset + 1}-{Math.min(scrollOffset + 12, lines.length)}/{lines.length}]
            {focused ? ' \u2191\u2193 scroll' : ''}
          </Text>
        )}
      </Box>
    </Box>
  );
}
